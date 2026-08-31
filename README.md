# ISAM Token Exchange (Apigee Shared Flows)

Two Apigee shared flows that exchange an inbound bearer token for an
ISAM-issued SAML assertion, differing only in wire format:

- **`sharedflowbundle/`** — `ISAM-WSTrust-TokenExchange`: WS-Trust SOAP
  request/response.
- **`sharedflowbundle-json/`** — `ISAM-JSON-TokenExchange`: JSON
  request/response, same attributes, same logic.

Both:

- Look up ISAM host config from an environment KVM (no hard-coded hosts)
- Build a request mixing static config attributes with attributes pulled off
  the inbound request (bearer token, client IP, client certificate, user agent)
- Fail over from the primary to the secondary ISAM host specifically on a
  transport failure or HTTP 500
- Extract the `saml:Assertion` (and its subject/NameID) from whichever host
  responded
- Validate the assertion's XML-DSig signature against its own embedded
  certificate, with optional signing-cert pinning
- Conditionally zip + base64 compress the assertion, gated by a
  `compressSaml` flag

**Built entirely from native Apigee policies (`KeyValueMapOperations`,
`ExtractVariables`, `AssignMessage`, `ServiceCallout`, `RaiseFault`) — no
JavaScript anywhere in either flow.** Two steps (XML signature verification,
zip compression) use a small Java callout, shared unchanged by both bundles,
because Apigee has no native policy for either; see "Why Java is still here"
below for exactly why, and what a JS-only alternative would have cost.

## Layout

```
sharedflowbundle/            # ISAM-WSTrust-TokenExchange (SOAP)
  ISAM-WSTrust-TokenExchange.xml
  policies/
  sharedflows/default.xml
  resources/java/            # isam-saml-callouts.jar goes here (built, not checked in)
sharedflowbundle-json/       # ISAM-JSON-TokenExchange (JSON)
  ISAM-JSON-TokenExchange.xml
  policies/
  sharedflows/default.xml
  resources/java/            # same jar, copied here too
java-callouts/isam-saml-callouts/  # the one Maven module backing both bundles
examples/
  FlowCallout-Sample.xml        # calling the WS-Trust bundle from a proxy
  FlowCallout-JSON-Sample.xml   # calling the JSON bundle from a proxy
scripts/
  provision-kvm.sh              # KVM entries for the WS-Trust bundle
  provision-kvm-json.sh         # KVM entries for the JSON bundle
```

## ISAM-WSTrust-TokenExchange (`sharedflowbundle/`)

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
   (transport error) or returned HTTP 500 — see "Failover semantics" below.
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
11. **RF-WSTrust-Fault** — raised if no assertion was extracted.
12. **JC-Validate-SAML-Signature** (Java callout) — see "Why Java is still here".
13. **RF-SAML-Signature-Invalid** — raised if the signature doesn't validate.
14. **JC-Compress-SAML-Assertion** (Java callout) — see "Why Java is still here".
15. **AM-Set-SAML-Response-Header** — sets `X-SAML-Assertion`,
    `X-SAML-Assertion-Compressed`, and `X-SAML-Subject-Id` request headers, and
    mirrors the subject/lifetime into `isam.exchanged.*` flow variables.

### Dynamic (per-request) attributes on the WS-Trust request

| WS-Trust element                                | Source                                                             |
|--------------------------------------------------|----------------------------------------------------------------------|
| `wsse:BinarySecurityToken` (header + OnBehalfOf) | `Authorization: Bearer <token>` request header, base64-encoded via `encodeBase64()` |
| `AdditionalContext/ContextItem[@Name='ip']`      | `client.ip` (Apigee-native)                                          |
| `AdditionalContext/ContextItem[@Name='forwardedFor']` | `X-Forwarded-For` request header, passed through verbatim (not split — see below) |
| `AdditionalContext/ContextItem[@Name='userAgent']` | `User-Agent` request header                                        |
| `AdditionalContext/ContextItem[@Name='clientCertificate']` | `X-Client-Cert` request header (hard-coded name — see below)  |
| `wsa:MessageID`                                   | `createUuid()` (Apigee-native)                                       |

### KVM config (`ISAM.WSTrust.Config`)

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

Provision with `scripts/provision-kvm.sh` (edit its `KEYS` array first).

## ISAM-JSON-TokenExchange (`sharedflowbundle-json/`)

Same flow shape as the WS-Trust bundle, transport swapped from SOAP/XML to
JSON throughout. Every step name mirrors its WS-Trust counterpart 1:1:

1. **KVM-Get-ISAMJSONConfig** — reads `ISAM.JSON.Config` into `isamjson.config.*`.
   A *separate* KVM from the WS-Trust bundle's, since the JSON token endpoint
   may live on a different host/port/path than the SOAP one, even on the same
   ISAM appliance.
2. **RF-ISAM-Config-Missing** — same idea, JSON-bundle wording.
3. **EV-Extract-BearerToken** — identical `Header`/`Pattern` extraction,
   setting `isamjson.bearer.token`.
4. **RF-Missing-Bearer-Token**.
5. **AM-Set-Default-CompressSaml** — identical mechanism, reading
   `isamjson.config.compressSaml`.
6. **AM-Build-JSON-Request** — builds the JSON request body as a literal JSON
   object in an `AssignMessage` `Payload`, using `escapeJSON()` (JSON's
   analogue of `escapeXML()`) and `createUuid()`, into `isamJsonRequestMsg`:

   ```json
   {
     "requestId": "<uuid>",
     "requestType": "<from KVM>",
     "tokenType": "<from KVM>",
     "keyType": "<from KVM>",
     "appliesTo": "<from KVM>",
     "bearerToken": "<raw bearer token, not base64>",
     "clientContext": {
       "ip": "<client.ip>",
       "forwardedFor": "<X-Forwarded-For header, verbatim>",
       "userAgent": "<User-Agent header>",
       "clientCertificate": "<X-Client-Cert header>"
     }
   }
   ```

   Unlike the WS-Trust envelope, the bearer token is sent as plain text, not
   base64 — that encoding was a WS-Security `BinarySecurityToken` convention,
   not something a JSON API would typically expect. `escapeJSON()` is applied
   to every dynamic string regardless, since (unlike XML) an unescaped quote
   or backslash in a header value would break the JSON structure itself.
7. **SC-Call-ISAM-JSON-Primary** — POSTs `{isamJsonRequestMsg.content}` with
   `Content-Type`/`Accept: application/json` to the primary host.
8. **SC-Call-ISAM-JSON-Secondary** — same failover-on-500 condition as the
   WS-Trust bundle.
9. **RF-ISAM-Unavailable**.
10. **EV-Parse-JSON-Primary-Response** / **EV-Parse-JSON-Secondary-Response** —
    `ExtractVariables` with `JSONPayload`/`JSONPath` (native, no XPath
    complexity needed) into:
    - `isamjson.response.assertion.xml` — the SAML assertion XML, expected as
      a string value in the JSON response's `saml` field
    - `isamjson.response.subject.id` — from `subjectId`
    - `isamjson.response.notBefore` / `.notOnOrAfter`
    - `isamjson.response.fault` — from `error`, if ISAM returned one instead

    **These field names (`saml`, `subjectId`, `notBefore`, `notOnOrAfter`,
    `error`) are assumed** — there was no actual ISAM JSON contract to go on,
    only "one of the response attributes is the saml". Confirm the real
    response shape with the ISAM side and adjust the `JSONPath`s in
    `EV-Parse-JSON-Primary-Response.xml` / `EV-Parse-JSON-Secondary-Response.xml`
    accordingly — everything downstream (signature validation, compression,
    header names) is unaffected by a field-name change, since only these two
    `JSONPath`s would need editing.
11. **RF-JSON-Fault** — raised if no assertion was extracted.
12. **JC-Validate-SAML-Signature** (Java callout, same jar as the WS-Trust
    bundle, `Properties` pointed at `isamjson.*` variable names) — see "Why
    Java is still here". Signature validation itself doesn't care whether the
    assertion arrived inside a SOAP envelope or a JSON string field — it's
    the same XML fragment either way.
13. **RF-SAML-Signature-Invalid**.
14. **JC-Compress-SAML-Assertion** (Java callout, same jar).
15. **AM-Set-SAML-Response-Header** — identical output contract to the
    WS-Trust bundle: `X-SAML-Assertion`, `X-SAML-Assertion-Compressed`,
    `X-SAML-Subject-Id` headers, plus `isam.exchanged.*` variables.

### KVM config (`ISAM.JSON.Config`)

Same field set as `ISAM.WSTrust.Config`, different key prefix (`isam.json.*`
instead of `isam.sts.*`) and a REST-shaped default path/requestType:

| Key | Required | Example |
|---|---|---|
| `isam.json.host1` / `.host2` | yes | `isam1.internal.example.com` |
| `isam.json.port` | yes | `443` |
| `isam.json.scheme` | yes | `https` |
| `isam.json.path` | yes | `/json/token-exchange` |
| `isam.json.appliesTo` | yes | `urn:isam:relying-party:my-service` |
| `isam.json.tokenType` | yes | `urn:ietf:params:oauth:token-type:jwt` |
| `isam.json.keyType` | yes | `http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer` |
| `isam.json.requestType` | yes | `issue` |
| `isam.json.connectTimeoutMs` / `.ioTimeoutMs` | no | `5000` / `10000` |
| `isam.json.compressSaml` | no (default false) | `false` |
| `isam.json.trustedSigningCertThumbprints` | no | comma-separated SHA-256 thumbprints |

Provision with `scripts/provision-kvm-json.sh` (edit its `KEYS` array first).

## Failover semantics (both bundles)

The task only calls for failing over "if the first call fails with an error
500", so that's exactly what's implemented: primary → secondary only on a
transport-level failure or an explicit HTTP 500 from the primary. A primary
response of, say, 400 or 503 is *not* retried against the secondary; it
instead falls through to the fault step once no assertion was extracted from
anywhere. If you'd rather retry on any non-200, broaden the conditions in the
relevant `sharedflows/default.xml` (the `SC-Call-*-Secondary` and
`RF-ISAM-Unavailable` steps).

## Why Java is still here

Two steps, identical in both bundles, could not be moved to native policies
or JavaScript, because Apigee's JavaScript sandbox has no crypto or
compression primitives (no `crypto`, no `zlib`/`Deflater`, no
XML-canonicalization library) and there is no native Apigee policy for
either operation:

- **`JC-Validate-SAML-Signature`** — verifying an XML-DSig `ds:Signature`
  needs XML canonicalization (C14N) plus RSA/X.509 verification. This is
  algorithmically substantial and security-sensitive; a hand-rolled
  JavaScript version would be both a large amount of code and a real risk of
  getting subtly wrong in a way that *looks* like it validates. The Java
  version uses only JDK-standard `javax.xml.crypto.dsig` (JSR-105), no
  third-party crypto library. This is unaffected by whether the assertion
  arrived via SOAP or JSON — it's the same XML fragment either way.
- **`JC-Compress-SAML-Assertion`** — DEFLATE/zip has no native Apigee policy
  either. It *could* be reimplemented in pure JavaScript (the algorithm
  doesn't require native code), but that means porting/hand-writing a
  compliant DEFLATE encoder — hundreds of lines, with its own correctness
  risk, to replace three lines of `java.util.zip`. Java was kept here for
  the same reason: it's the smaller, more reliable option once *some*
  custom code is unavoidable.

Both are already built and tested (against a real self-signed-cert-signed
assertion for the validator: valid/tampered/pinned/unpinned/unsigned cases;
a real zip/base64 round trip for the compressor).

## Dynamic-attribute simplifications (both bundles)

Two trade-offs fall out of going JS-free, common to both bundles:

- **Client IP**: no "first hop of X-Forwarded-For" parsing. That
  string-splitting needs code, so instead both `client.ip` (Apigee's own
  view) and the raw `X-Forwarded-For` header (however many hops) are sent
  separately and verbatim — let ISAM's own mapping rule decide which one it
  trusts, rather than deciding client-side.
- **Client certificate header**: the header name is **hard-coded to
  `X-Client-Cert`** in `AM-Build-WSTrust-Request.xml` / `AM-Build-JSON-Request.xml`,
  rather than KVM-configurable. Looking up a header by a name stored in
  *another* variable needs indirect variable resolution, which Apigee's
  native templating doesn't support — only JavaScript could do that. If your
  header name needs to vary, edit that one line directly. The value is also
  expected **pre-normalized to bare base64** (no PEM armor, no URL-encoding,
  no embedded newlines) by whatever terminates mTLS in front of Apigee.

## Signature validation & trust

`JC-Validate-SAML-Signature` verifies the assertion's `ds:Signature`
cryptographically matches the X.509 certificate embedded in that same
signature's `ds:KeyInfo` — i.e. "the assertion wasn't altered after whoever
holds that certificate's private key signed it."

**That alone does not prove ISAM signed it.** Nothing stops an attacker who
can inject a response into this flow from generating their own keypair,
embedding their own self-signed certificate, and signing a forged assertion
with it — the signature would validate perfectly, against the wrong signer.

To close that gap, set `trustedSigningCertThumbprints` in the relevant KVM
(`isam.sts.trustedSigningCertThumbprints` or `isam.json.trustedSigningCertThumbprints`)
to the SHA-256 thumbprint(s) of ISAM's actual signing certificate(s) (both
hosts, plus room for a rotation overlap). When set, `JC-Validate-SAML-Signature`
additionally rejects any assertion whose signing cert isn't in that list —
this is the pinning that anchors trust in something you control rather than
in the token itself. Get the current thumbprint with:

```bash
openssl x509 -in isam-signing-cert.pem -noout -fingerprint -sha256
```

Leave the field empty only if you have another way to establish trust in the
signer and understand the tradeoff.

## Compression (`compressSaml`)

`JC-Compress-SAML-Assertion` zips the assertion (a real zip archive, one
`assertion.xml` entry) and base64-encodes it when `compressSaml` resolves
true; otherwise it just base64-encodes the raw XML. Either way the result is
in `saml.assertion.output` and gets set as the `X-SAML-Assertion` header,
with `X-SAML-Assertion-Compressed` telling the receiver which case it is.

The flag resolves in this order: a `compressSaml` flow variable set by the
*calling* proxy before invoking the shared flow (see the `examples/` files)
wins; otherwise it falls back to the KVM default (`AM-Set-Default-CompressSaml`).

## TLS trust for the outbound call to ISAM

Both bundles' `ServiceCallout` policies reference `ref://isam-truststore-ref`.
If ISAM's TLS certificate is signed by an internal/private CA, create a
Keystore containing that CA chain in the target environment and create a
Reference named `isam-truststore-ref` pointing at it:

```
apigeecli keystores create -n isam-truststore --env <env> --org <org> --token <token>
apigeecli keystores certs create -k isam-truststore --certfile isam-ca-chain.pem ...
apigeecli references create -n isam-truststore-ref --restype TrustStore --refers isam-truststore --env <env> --org <org> --token <token>
```

If ISAM's cert chains to a public/well-known CA already trusted by Apigee,
drop the `<SSLInfo>` block from the `SC-Call-*` policies instead. (This is
separate from, and does not substitute for, the SAML signature pinning above
— TLS trust protects the transport; signature pinning protects the token
itself, which may travel further than this one hop.)

## Java callouts

Both bundles' `JC-Validate-SAML-Signature` and `JC-Compress-SAML-Assertion`
are backed by the single Maven module at `java-callouts/isam-saml-callouts/`.
Build it once and it drops the jar into both bundles:

```bash
cd java-callouts/isam-saml-callouts
mvn -B package   # copies isam-saml-callouts.jar into both bundles' resources/java/
```

See `java-callouts/isam-saml-callouts/README.md` for the class/property
reference (including the WS-Trust-vs-JSON property value differences).

## Calling a shared flow from a proxy

See `examples/FlowCallout-Sample.xml` (WS-Trust) or
`examples/FlowCallout-JSON-Sample.xml` (JSON). Attach a `FlowCallout` step
(referencing the relevant `SharedFlowBundle`) in your proxy's PreFlow. Any
fault raised inside the shared flow propagates up as a raised fault for your
proxy's own fault handling to catch.

## Deploying

Each bundle follows the standard Apigee shared flow bundle layout, so it
deploys the same way any shared flow does — via `apigeecli`, Maven
(`apigee-config-maven-plugin` / `apigee-deploy-maven-plugin`), or by zipping
the bundle directory and importing it through the Apigee UI/Management API.
Build the Java callout jar *first* (see above) so it's present under both
bundles' `resources/java/` before packaging. Example with `apigeecli`:

```bash
apigeecli sharedflows create -n ISAM-WSTrust-TokenExchange \
  -f sharedflowbundle --org <org> --token <token>
apigeecli sharedflows deploy -n ISAM-WSTrust-TokenExchange \
  --env <env> --org <org> --ovr --token <token>

apigeecli sharedflows create -n ISAM-JSON-TokenExchange \
  -f sharedflowbundle-json --org <org> --token <token>
apigeecli sharedflows deploy -n ISAM-JSON-TokenExchange \
  --env <env> --org <org> --ovr --token <token>
```

## Notes / things to confirm with the ISAM side

- **WS-Trust bundle**: the RST/RSTR shape (SOAP 1.2, WS-Trust 1.3 `Issue`,
  `AdditionalContext` with `ContextItem`s for IP/cert/UA) matches ISAM's
  common Federation/STS chain pattern where a JavaScript STS module maps
  `AdditionalContext` into custom claims — confirm the exact `ContextItem`
  names your ISAM mapping rule expects. The SAML extraction XPaths assume
  the assertion is reachable at `.../RequestedSecurityToken/saml:Assertion`
  (any namespace prefix, any wrapper around `RequestedSecurityToken`).
- **JSON bundle**: the request shape (`requestType`/`tokenType`/`keyType`/
  `appliesTo`/`bearerToken`/`clientContext.*`) and especially the **response**
  field names (`saml`/`subjectId`/`notBefore`/`notOnOrAfter`/`error`) are
  this repo's assumptions, not a confirmed ISAM contract — there was no
  actual JSON schema to build against. Get the real one and adjust
  `AM-Build-JSON-Request.xml` (request shape) and the two
  `EV-Parse-JSON-*-Response.xml` files (response `JSONPath`s) accordingly.
- **Both**: `TokenType`, `KeyType`, `RequestType`, and `AppliesTo` are pulled
  from KVM as static values — adjust per relying party if you need more than
  one profile. Confirm whether ISAM expects the bearer token base64-encoded
  (WS-Trust bundle does this) or raw (JSON bundle does this) — that's an
  assumption following each format's own convention, not something ISAM told
  us either way.
