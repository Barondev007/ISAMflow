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

## Layout

```
sharedflowbundle/
  ISAM-WSTrust-TokenExchange.xml   # root bundle descriptor
  policies/                        # one XML file per policy, see below
  sharedflows/default.xml          # the flow, step order + conditions
  resources/jsc/build-wstrust-request.js
  resources/java/                  # isam-saml-callouts.jar goes here (built, not checked in)
java-callouts/isam-saml-callouts/  # Maven module for the two Java callouts
examples/
  FlowCallout-Sample.xml           # how to call this from an API proxy
scripts/
  provision-kvm.sh                 # creates/updates the KVM entry
```

## Flow

1. **KVM-Get-ISAMConfig** — `KeyValueMapOperations` reads a single JSON blob
   (key `isam.sts.config`) from the environment-scoped KVM `ISAM.WSTrust.Config`
   into `isam.config.raw`.
2. **JS-Build-WSTrust-Request** — parses/validates that JSON, pulls the
   `Authorization: Bearer …` header, `client.ip`, `User-Agent`, and (optionally)
   a forwarded client certificate header off the request, resolves the
   `compressSaml` flag (caller override else KVM default), and builds the
   WS-Trust SOAP envelope (`wstrust.request.payload`) plus the two target URLs.
3. **RF-ISAM-Config-Missing** / **RF-Missing-Bearer-Token** — short-circuit with
   a clear error if the KVM entry is missing/invalid or there's no bearer token.
4. **SC-Call-ISAM-Primary** — POSTs the SOAP request to the primary ISAM host
   (`continueOnError="true"` so failure doesn't abort the flow outright).
5. **SC-Call-ISAM-Secondary** — runs only if the primary call failed outright
   (transport error) or returned HTTP 500, POSTing the same payload to the
   secondary host. Any other primary error (4xx, other 5xx) is *not* retried
   against the secondary — see "Failover semantics" below.
6. **RF-ISAM-Unavailable** — raised only if both hosts failed/500'd.
7. **EV-Parse-Primary-Response** / **EV-Parse-Secondary-Response** — whichever
   host returned HTTP 200 gets its RSTR parsed via XPath into:
   - `isam.rstr.assertion.xml` — the full `<saml:Assertion>` XML fragment
   - `isam.rstr.subject.id` — the assertion's `Subject/NameID` (or `NameIdentifier`)
   - `isam.rstr.notBefore` / `isam.rstr.notOnOrAfter` — from `saml:Conditions`
   - `isam.rstr.fault` — SOAP Fault reason text, if ISAM returned a fault instead
   
   These XPaths use `local-name()` throughout instead of hard namespace
   bindings, so they keep working regardless of exact prefixes or whether the
   RSTR is wrapped in a `RequestSecurityTokenResponseCollection`.
8. **RF-WSTrust-Fault** — raised if no assertion was extracted (SOAP Fault, or
   an unexpected response shape from either host).
9. **JC-Validate-SAML-Signature** (Java callout) — verifies the assertion's
   `ds:Signature` against the X.509 cert embedded in its own `ds:KeyInfo`.
10. **RF-SAML-Signature-Invalid** — raised if the signature doesn't validate
    (or, when pinning is configured, if the signing cert isn't a trusted one).
11. **JC-Compress-SAML-Assertion** (Java callout) — zips (if `compressSaml`)
    and base64-encodes the assertion into `saml.assertion.output`.
12. **AM-Set-SAML-Response-Header** — sets `X-SAML-Assertion`,
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

## KVM config shape

Single key `isam.sts.config` in KVM `ISAM.WSTrust.Config` (environment-scoped),
value is a JSON string:

```json
{
  "host1": "isam1.internal.example.com",
  "host2": "isam2.internal.example.com",
  "port": "443",
  "scheme": "https",
  "path": "/TrustServer/SecurityTokenService",
  "connectTimeoutMs": "5000",
  "ioTimeoutMs": "10000",
  "appliesTo": "urn:isam:relying-party:my-service",
  "tokenType": "urn:ietf:params:oauth:token-type:jwt",
  "keyType": "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer",
  "requestType": "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
  "clientCertHeader": "X-Client-Cert",
  "compressSaml": false,
  "trustedSigningCertThumbprints": ""
}
```

`host1`, `host2`, `port`, `scheme`, `path`, `appliesTo`, `tokenType`,
`keyType`, and `requestType` are required; the rest have defaults.
`trustedSigningCertThumbprints` is a comma-separated list of SHA-256
certificate thumbprints (hex, colons optional) — see "Signature validation &
trust" below.

Use `scripts/provision-kvm.sh` to create/update this entry:

```bash
ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
  ./scripts/provision-kvm.sh
```

Edit the JSON block in the script (or point `CONFIG_JSON_FILE` at a file)
before running it against a real environment.

## Dynamic (per-request) attributes on the outbound WS-Trust request

| WS-Trust element                                | Source                                                             |
|--------------------------------------------------|----------------------------------------------------------------------|
| `wsse:BinarySecurityToken` (header + OnBehalfOf) | `Authorization: Bearer <token>` request header                     |
| `AdditionalContext/ContextItem[@Name='ip']`      | `client.ip`, falling back to first hop of `X-Forwarded-For`         |
| `AdditionalContext/ContextItem[@Name='userAgent']` | `User-Agent` request header (omitted if absent)                   |
| `AdditionalContext/ContextItem[@Name='clientCertificate']` | Header named by `clientCertHeader` in the KVM config (omitted if absent) |
| `wsa:MessageID`                                   | Generated UUID per request                                          |

The client certificate is expected as a URL-encoded PEM in a header, which is
the common convention when TLS/mTLS is terminated by a load balancer or NGINX
in front of Apigee (e.g. NGINX's `$ssl_client_escaped_cert`, or an ALB's
`X-Amzn-Mtls-Clientcert`). Confirm the actual header name/format with whoever
terminates mTLS and set `clientCertHeader` accordingly. If Apigee itself
terminates mutual TLS on the ProxyEndpoint, adjust `JS-Build-WSTrust-Request`
to read the appropriate `ssl_info.*` flow variables instead.

## Signature validation & trust

`JC-Validate-SAML-Signature` verifies the assertion's `ds:Signature`
cryptographically matches the X.509 certificate embedded in that same
signature's `ds:KeyInfo` — i.e. "the assertion wasn't altered after whoever
holds that certificate's private key signed it."

**That alone does not prove ISAM signed it.** Nothing stops an attacker who
can inject a response into this flow from generating their own keypair,
embedding their own self-signed certificate, and signing a forged assertion
with it — the signature would validate perfectly, against the wrong signer.

To close that gap, set `trustedSigningCertThumbprints` in the KVM config to
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
`compressSaml` in the KVM config.

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
reference. Apigee has no native XML-DSig or zip policy, which is why these
two steps are Java rather than JavaScript or AssignMessage — Apigee's
JavaScript sandbox doesn't expose the crypto/zip primitives needed for either.

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
- Bearer token is embedded both in the WS-Security header (`wsse:Security`)
  and in `wst:OnBehalfOf`; drop whichever one your ISAM STS chain doesn't
  expect to keep the request minimal.
- The SAML extraction XPaths assume the assertion is reachable at
  `.../RequestedSecurityToken/saml:Assertion` (any namespace prefix, any
  wrapper around `RequestedSecurityToken`). If your ISAM STS wraps it
  differently, adjust the XPaths in `EV-Parse-Primary-Response.xml` /
  `EV-Parse-Secondary-Response.xml`.
