# ISAM-WSTrust-TokenExchange (Apigee Shared Flow)

An Apigee shared flow that exchanges an inbound bearer token for an
ISAM-issued SAML assertion via WS-Trust, with:

- ISAM host/config lookup from an environment KVM (no hard-coded hosts)
- A dynamically built WS-Trust `RequestSecurityToken` (RST) SOAP request, mixing
  static config attributes with attributes pulled off the inbound request
  (bearer token, client IP, client certificate, user agent)
- Failover from the primary to the secondary ISAM host specifically on a
  transport failure or HTTP 500
- Extraction of the `saml:Assertion` (and its subject/NameID) from whichever
  host responded
- XML-DSig signature validation of the assertion against its own embedded
  certificate, with optional signing-cert pinning
- Conditional zip + base64 compression of the assertion, gated by a
  `compressSaml` flag

**Built entirely from native Apigee policies (`KeyValueMapOperations`,
`ExtractVariables`, `AssignMessage`, `ServiceCallout`, `RaiseFault`) — no
JavaScript anywhere in the flow.** Two steps (XML signature verification, zip
compression) use a small Java callout because Apigee has no native policy for
either; see "Why Java is still here" below for exactly why, and what a
JS-only alternative would have cost.

## Layout

```
sharedflowbundle/
  ISAM-WSTrust-TokenExchange.xml   # root bundle descriptor
  policies/                        # one XML file per policy, see below
  sharedflows/default.xml          # the flow, step order + conditions
  resources/java/                  # isam-saml-callouts.jar goes here (built, not checked in)
java-callouts/isam-saml-callouts/  # Maven module for the two Java callouts
examples/
  FlowCallout-Sample.xml           # how to call this from an API proxy
scripts/
  provision-kvm.sh                 # creates/updates the KVM entries
```

## Flow

1. **KVM-Get-ISAMConfig** — one `KeyValueMapOperations` policy, one `<Get>`
   per config field, reading directly from the environment-scoped KVM
   `ISAM.WSTrust.Config` into `isam.config.*` variables. No JSON, no parsing.
2. **RF-ISAM-Config-Missing** — raised if any required `isam.config.*`
   variable came back null (a `Condition` on the step, no code).
3. **EV-Extract-BearerToken** — native `ExtractVariables` with a `Header`
   `Pattern` (`Bearer {token}`) on `Authorization`, setting
   `wstrust.bearer.token`.
4. **RF-Missing-Bearer-Token** — raised if that came back null.
5. **AM-Set-Default-CompressSaml** — only runs if the calling proxy didn't
   already set a `compressSaml` flow variable; copies the KVM default
   (`isam.config.compressSaml`) in, or `false` if even that's unset.
6. **AM-Build-WSTrust-Request** — a native `AssignMessage` that builds the
   full WS-Trust SOAP envelope as literal nested XML, using Apigee's built-in
   message-template functions (`escapeXML`, `createUuid`, `encodeBase64`) for
   the parts that need them, into a new message variable `wstrustRequestMsg`.
7. **SC-Call-ISAM-Primary** — POSTs `{wstrustRequestMsg.content}` to the
   primary ISAM host (`continueOnError="true"` so failure doesn't abort the
   flow outright).
8. **SC-Call-ISAM-Secondary** — runs only if the primary call failed outright
   (transport error) or returned HTTP 500, POSTing the same payload to the
   secondary host. Any other primary error (4xx, other 5xx) is *not* retried
   against the secondary — see "Failover semantics" below.
9. **RF-ISAM-Unavailable** — raised only if both hosts failed/500'd.
10. **EV-Parse-Primary-Response** / **EV-Parse-Secondary-Response** — whichever
    host returned HTTP 200 gets its RSTR parsed via XPath into:
    - `isam.rstr.assertion.xml` — the full `<saml:Assertion>` XML fragment
    - `isam.rstr.subject.id` — the assertion's `Subject/NameID` (or `NameIdentifier`)
    - `isam.rstr.notBefore` / `isam.rstr.notOnOrAfter` — from `saml:Conditions`
    - `isam.rstr.fault` — SOAP Fault reason text, if ISAM returned a fault instead

    These XPaths use `local-name()` throughout instead of hard namespace
    bindings, so they keep working regardless of exact prefixes or whether the
    RSTR is wrapped in a `RequestSecurityTokenResponseCollection`.
11. **RF-WSTrust-Fault** — raised if no assertion was extracted (SOAP Fault, or
    an unexpected response shape from either host).
12. **JC-Validate-SAML-Signature** (Java callout) — verifies the assertion's
    `ds:Signature` against the X.509 cert embedded in its own `ds:KeyInfo`.
13. **RF-SAML-Signature-Invalid** — raised if the signature doesn't validate
    (or, when pinning is configured, if the signing cert isn't a trusted one).
14. **JC-Compress-SAML-Assertion** (Java callout) — zips (if `compressSaml`)
    and base64-encodes the assertion into `saml.assertion.output`.
15. **AM-Set-SAML-Response-Header** — sets `X-SAML-Assertion`,
    `X-SAML-Assertion-Compressed`, and `X-SAML-Subject-Id` request headers, and
    mirrors the subject/lifetime into `isam.exchanged.*` flow variables for
    the calling proxy to read directly instead, if preferred.

### Failover semantics

The task only calls for failing over "if the first call fails with an error
500", so that's exactly what's implemented: primary → secondary only on a
transport-level failure or an explicit HTTP 500 from the primary. A primary
response of, say, 400 or 503 is *not* retried against the secondary (a 400
would presumably repeat identically there anyway); it instead falls through
to `RF-WSTrust-Fault` once no assertion was extracted from anywhere. If you'd
rather retry on any non-200, broaden the conditions in
`sharedflowbundle/sharedflows/default.xml` (the two `SC-Call-ISAM-Secondary`
and `RF-ISAM-Unavailable` steps) accordingly.

## Why Java is still here

Two steps could not be moved to native policies or JavaScript, because
Apigee's JavaScript sandbox has no crypto or compression primitives (no
`crypto`, no `zlib`/`Deflater`, no XML-canonicalization library) and there is
no native Apigee policy for either operation:

- **`JC-Validate-SAML-Signature`** — verifying an XML-DSig `ds:Signature`
  needs XML canonicalization (C14N) plus RSA/X.509 verification. This is
  algorithmically substantial and security-sensitive; a hand-rolled
  JavaScript version would be both a large amount of code and a real risk of
  getting subtly wrong in a way that *looks* like it validates. The Java
  version uses only JDK-standard `javax.xml.crypto.dsig` (JSR-105), no
  third-party crypto library.
- **`JC-Compress-SAML-Assertion`** — DEFLATE/zip has no native Apigee policy
  either. It *could* be reimplemented in pure JavaScript (the algorithm
  doesn't require native code), but that means porting/hand-writing a
  compliant DEFLATE encoder — hundreds of lines, with its own correctness
  risk, to replace three lines of `java.util.zip`. Java was kept here for
  the same reason: it's the smaller, more reliable option once *some*
  custom code is unavoidable.

If you'd rather drop one or both of these than carry a Java callout, that's a
real option, not just a footnote: signature validation could be deferred to
whatever consumes `X-SAML-Assertion` downstream, and compression can simply
be disabled everywhere (`compressSaml` always false, which needs no code at
all — the "else" branch of `JC-Compress-SAML-Assertion` is just
`encodeBase64()`, which is itself a native message-template function). Say
the word and I'll cut over.

## KVM config

Individual keys in KVM `ISAM.WSTrust.Config` (environment-scoped) — no JSON,
each field is its own entry:

| Key | Required | Example |
|---|---|---|
| `isam.sts.host1` | yes | `isam1.internal.example.com` |
| `isam.sts.host2` | yes | `isam2.internal.example.com` |
| `isam.sts.port` | yes | `443` |
| `isam.sts.scheme` | yes | `https` |
| `isam.sts.path` | yes | `/TrustServer/SecurityTokenService` |
| `isam.sts.appliesTo` | yes | `urn:isam:relying-party:my-service` |
| `isam.sts.tokenType` | yes | `urn:ietf:params:oauth:token-type:jwt` |
| `isam.sts.keyType` | yes | `http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer` |
| `isam.sts.requestType` | yes | `http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue` |
| `isam.sts.connectTimeoutMs` | no (default 5000) | `5000` |
| `isam.sts.ioTimeoutMs` | no (default 10000) | `10000` |
| `isam.sts.compressSaml` | no (default false) | `false` |
| `isam.sts.trustedSigningCertThumbprints` | no | comma-separated SHA-256 thumbprints |

Use `scripts/provision-kvm.sh` to create/update these entries (edit the
`KEYS` array at the top of the script first):

```bash
ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
  ./scripts/provision-kvm.sh
```

## Dynamic (per-request) attributes on the outbound WS-Trust request

| WS-Trust element                                | Source                                                             |
|--------------------------------------------------|----------------------------------------------------------------------|
| `wsse:BinarySecurityToken` (header + OnBehalfOf) | `Authorization: Bearer <token>` request header, base64-encoded via `encodeBase64()` |
| `AdditionalContext/ContextItem[@Name='ip']`      | `client.ip` (Apigee-native)                                          |
| `AdditionalContext/ContextItem[@Name='forwardedFor']` | `X-Forwarded-For` request header, passed through verbatim (not split — see below) |
| `AdditionalContext/ContextItem[@Name='userAgent']` | `User-Agent` request header                                        |
| `AdditionalContext/ContextItem[@Name='clientCertificate']` | `X-Client-Cert` request header (hard-coded name — see below)  |
| `wsa:MessageID`                                   | `createUuid()` (Apigee-native)                                       |

Any of these that are absent on the inbound request render as an empty
`<wsc:Value/>` rather than omitting the `ContextItem` entirely — a
deliberate simplification (conditionally omitting an XML element isn't
something a single native `Payload` template can express; doing so would
need branching logic, i.e. code).

### Client IP: `ip` vs `forwardedFor`

The original design tried to compute "the first hop of X-Forwarded-For" as a
fallback for `client.ip`. That string-splitting is exactly the kind of thing
that needs code, so instead both are now sent separately and verbatim:
`ip` is Apigee's own view of the peer, `forwardedFor` is the raw
`X-Forwarded-For` header (however many hops it has). Let ISAM's own mapping
rule decide which one it trusts, rather than deciding client-side.

### Client certificate header

The header name is now **hard-coded to `X-Client-Cert`** in
`AM-Build-WSTrust-Request.xml`, rather than configurable via KVM as in the
JS version. This is a direct consequence of removing JavaScript: looking up
a header by a name stored in *another* variable (`request.header.{headerNameVar}`)
needs indirect variable resolution, which Apigee's native templating doesn't
support — only JavaScript's `context.getVariable('request.header.' + name)`
can do that. If your header name needs to vary, edit that one line in
`AM-Build-WSTrust-Request.xml` directly.

The value is also expected **pre-normalized to bare base64** (no
`-----BEGIN CERTIFICATE-----` armor, no URL-encoding, no embedded newlines)
by whatever terminates mTLS in front of Apigee — e.g. NGINX's
`$ssl_client_escaped_cert` would need reformatting before it reaches Apigee.
The JS version stripped PEM armor and newlines itself; doing that natively
would mean chaining `replaceAll()` calls, which is more fragile than just
fixing the upstream format once. Confirm the actual format with whoever
terminates mTLS.

## Signature validation & trust

`JC-Validate-SAML-Signature` verifies the assertion's `ds:Signature`
cryptographically matches the X.509 certificate embedded in that same
signature's `ds:KeyInfo` — i.e. "the assertion wasn't altered after whoever
holds that certificate's private key signed it."

**That alone does not prove ISAM signed it.** Nothing stops an attacker who
can inject a response into this flow from generating their own keypair,
embedding their own self-signed certificate, and signing a forged assertion
with it — the signature would validate perfectly, against the wrong signer.

To close that gap, set `isam.sts.trustedSigningCertThumbprints` in the KVM to
the SHA-256 thumbprint(s) of ISAM's actual signing certificate(s) (both hosts,
plus room for a rotation overlap). When set, `JC-Validate-SAML-Signature`
additionally rejects any assertion whose signing cert isn't in that list —
this is the pinning that anchors trust in something you control rather than
in the token itself. Get the current thumbprint with:

```bash
openssl x509 -in isam-signing-cert.pem -noout -fingerprint -sha256
```

Leave the field empty only if you have another way to establish trust in the
signer (e.g. mutual TLS to ISAM plus implicit trust in the channel) and
understand the tradeoff.

## Compression (`compressSaml`)

`JC-Compress-SAML-Assertion` zips the assertion (a real zip archive, one
`assertion.xml` entry) and base64-encodes it when `compressSaml` resolves
true; otherwise it just base64-encodes the raw XML. Either way the result is
in `saml.assertion.output` and gets set as the `X-SAML-Assertion` header by
`AM-Set-SAML-Response-Header`, with `X-SAML-Assertion-Compressed` telling the
receiver which case it is.

The flag resolves in this order: a `compressSaml` flow variable set by the
*calling* proxy before invoking this shared flow (see
`examples/FlowCallout-Sample.xml`) wins; otherwise it falls back to
`isam.sts.compressSaml` in the KVM (via `AM-Set-Default-CompressSaml`).

## TLS trust for the outbound call to ISAM

The `ServiceCallout` policies reference `ref://isam-truststore-ref`. If ISAM's
TLS certificate is signed by an internal/private CA, create a Keystore
containing that CA chain in the target environment and create a Reference
named `isam-truststore-ref` pointing at it:

```
apigeecli keystores create -n isam-truststore --env <env> --org <org> --token <token>
apigeecli keystores certs create -k isam-truststore --certfile isam-ca-chain.pem ...
apigeecli references create -n isam-truststore-ref --restype TrustStore --refers isam-truststore --env <env> --org <org> --token <token>
```

If ISAM's cert chains to a public/well-known CA already trusted by Apigee,
you can drop the `<SSLInfo>` block from both `SC-Call-ISAM-*` policies.
(This is separate from, and does not substitute for, the SAML signature
pinning above — TLS trust protects the transport; signature pinning protects
the token itself, which may travel further than this one hop.)

## Java callouts

`JC-Validate-SAML-Signature` and `JC-Compress-SAML-Assertion` are backed by a
small Maven module at `java-callouts/isam-saml-callouts/`. Build it and drop
the jar into the bundle before deploying:

```bash
cd java-callouts/isam-saml-callouts
mvn -B package   # copies isam-saml-callouts.jar into sharedflowbundle/resources/java/
```

See `java-callouts/isam-saml-callouts/README.md` for the class/property
reference, and "Why Java is still here" above for why these two specifically
couldn't move to native policies.

## Calling this shared flow from a proxy

See `examples/FlowCallout-Sample.xml`. Attach a `FlowCallout` step (referencing
`SharedFlowBundle: ISAM-WSTrust-TokenExchange`) in your proxy's PreFlow. Any
fault raised inside the shared flow (missing config, missing bearer token,
both ISAM hosts down, SOAP fault, invalid signature) propagates up as a
raised fault for your proxy's own fault handling to catch.

## Deploying

This directory follows the standard Apigee shared flow bundle layout, so it
deploys the same way any shared flow does — via `apigeecli`, Maven
(`apigee-config-maven-plugin` / `apigee-deploy-maven-plugin`), or by zipping
`sharedflowbundle/` and importing it through the Apigee UI/Management API.
Build the Java callout jar *first* (see above) so it's present under
`sharedflowbundle/resources/java/` before packaging. Example with `apigeecli`:

```bash
apigeecli sharedflows create -n ISAM-WSTrust-TokenExchange \
  -f sharedflowbundle --org <org> --token <token>
apigeecli sharedflows deploy -n ISAM-WSTrust-TokenExchange \
  --env <env> --org <org> --ovr --token <token>
```

## Notes / things to confirm with the ISAM side

- The RST/RSTR shape here (SOAP 1.2, WS-Trust 1.3 `Issue`, `AdditionalContext`
  with `ContextItem`s for IP/cert/UA) matches ISAM's common Federation/STS
  chain pattern where a JavaScript STS module maps `AdditionalContext` into
  custom claims — confirm the exact `ContextItem` names your ISAM mapping rule
  expects.
- `TokenType`, `KeyType`, `RequestType`, and `AppliesTo` are all pulled from
  KVM as static values — adjust them per relying party if you end up needing
  more than one profile.
- Bearer token is embedded, base64-encoded, both in the WS-Security header
  (`wsse:Security`) and in `wst:OnBehalfOf`; drop whichever one your ISAM STS
  chain doesn't expect to keep the request minimal, and confirm ISAM expects
  base64 there at all rather than the raw JWT text.
- The SAML extraction XPaths assume the assertion is reachable at
  `.../RequestedSecurityToken/saml:Assertion` (any namespace prefix, any
  wrapper around `RequestedSecurityToken`). If your ISAM STS wraps it
  differently, adjust the XPaths in `EV-Parse-Primary-Response.xml` /
  `EV-Parse-Secondary-Response.xml`.
