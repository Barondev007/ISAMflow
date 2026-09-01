# ISAM Token Exchange (Apigee Shared Flows)

Six Apigee shared flows, one per SAML/JWT "type" ISAM issues, built on four
shared **common** building blocks so the actual ISAM call, signature
validation, and compression logic exist exactly once instead of being
duplicated six times.

## Why this shape

> "I have different types of SAML — for each the request can be different
> but the call itself to the ISAM endpoint is the same."

That's the whole design in one sentence. Apigee shared flows can call other
shared flows via `FlowCallout`, so the parts that are genuinely identical
across every type (POST-with-failover to ISAM, XML-DSig signature
verification, zip compression, SAML header-setting) live in four **common**
bundles under `common/`, called via `FlowCallout` from six thin
**type-specific** bundles under `types/` that only contain what's actually
different per type: KVM config, request shape, response shape.

```
                     ┌─────────────────────────────────────┐
  API proxy  ──────▶ │  type-specific shared flow (1 of 6)  │
                     │  - own KVM config (own ISAM hosts)   │
                     │  - build request (XML or JSON)       │
                     │  - parse response (own shape)        │
                     └───────────────┬───────────────────────┘
                                      │ FlowCallout
                      ┌───────────────┼───────────────┬──────────────────┐
                      ▼               ▼               ▼                  ▼
             ISAM-Common-      ISAM-Common-    ISAM-Common-      ISAM-Common-
             CallISAM          ValidateSignature CompressAssertion SetSamlHeaders
             (POST + failover) (Java, JSR-105)  (Java, zip)       (headers)
```

Type 6 (JWT-is-the-token) only calls `ISAM-Common-CallISAM` — there's no
SAML assertion in that type, so signature validation, compression, and
SAML headers don't apply; it sets its own token header directly.

## The six types

| # | Bundle | Request | Bearer token | Response | Calls |
|---|---|---|---|---|---|
| 1 | `ISAM-SAML-Light` | WS-Trust (SOAP/XML) | **none** — client cert is the only identity | SAML assertion | CallISAM, ValidateSignature, CompressAssertion, SetSamlHeaders |
| 2 | `ISAM-SAML-User` | WS-Trust (SOAP/XML) | yes | SAML assertion | same four |
| 3 | `ISAM-SAML-TP` | WS-Trust (SOAP/XML) | yes | SAML assertion | same four |
| 4 | `ISAM-SAML-Technical` | WS-Trust (SOAP/XML) | yes | SAML assertion | same four |
| 5 | `ISAM-JWT-SAML` | JSON | yes | SAML assertion in a JSON field | same four |
| 6 | `ISAM-JWT-Token` | JSON | yes | **JWT itself is the token** (no SAML) | CallISAM only |

Types 2, 3, and 4 are structurally identical WS-Trust requests; they're
still three separate bundles (not one bundle with branching) because each
has its own ISAM host pair, path, and audience (`appliesTo`) — per your
answer, hosts can differ per type, not just the path.

## Layout

```
common/
  ISAM-Common-CallISAM/sharedflowbundle/            # POST + failover-on-500
  ISAM-Common-ValidateSignature/sharedflowbundle/   # XML-DSig, Java callout
  ISAM-Common-CompressAssertion/sharedflowbundle/   # zip+base64, Java callout
  ISAM-Common-SetSamlHeaders/sharedflowbundle/       # X-SAML-* headers
types/
  type1-light-saml/sharedflowbundle/      # ISAM-SAML-Light
  type2-user-saml/sharedflowbundle/       # ISAM-SAML-User
  type3-tp-saml/sharedflowbundle/         # ISAM-SAML-TP
  type4-technical-saml/sharedflowbundle/  # ISAM-SAML-Technical
  type5-jwt-saml/sharedflowbundle/        # ISAM-JWT-SAML
  type6-jwt-token/sharedflowbundle/       # ISAM-JWT-Token
  type*/provision-kvm.sh                  # one provisioning script per type
java-callouts/isam-saml-callouts/         # the one Maven module backing
                                           # ISAM-Common-ValidateSignature
                                           # and ISAM-Common-CompressAssertion
examples/
  FlowCallout-Sample.xml                  # how to call any of the six types
dev-testing/
  Mock-ISAM/                              # dev-only stand-in for ISAM
  ISAM-Test-Caller/                       # dev-only proxy exercising all six types
```

Every bundle is independently deployable — including the four common ones,
since `FlowCallout` in Apigee resolves a shared flow by name at runtime, the
same way an API proxy resolves the shared flow it calls.

## The contract: how type flows talk to common flows

Apigee shared flows don't have formal parameters — a `FlowCallout` just
continues in the same transaction, so "input" and "output" are flow
variables by convention. Each common bundle documents its own contract in
its root descriptor's `<Description>`; the short version:

**`ISAM-Common-CallISAM`** — input: `isamcall.request.body`,
`isamcall.request.contentType`, `isamcall.target.url.primary/.secondary`,
`isamcall.connectTimeoutMs`/`.ioTimeoutMs`. Output:
`isamcall.response.body`, `isamcall.response.statusCode`. Raises its own
`RF-ISAM-Unavailable` (502) if both hosts failed or 500'd.

**`ISAM-Common-ValidateSignature`** — input: `saml.assertion.xml`,
`saml.trustedThumbprints` (optional). Output: `saml.signature.*`,
`saml.subject.id`, `saml.assertion.notBefore`/`.notOnOrAfter`. Raises its
own `RF-SAML-Signature-Invalid` (502) if the signature doesn't validate.

**`ISAM-Common-CompressAssertion`** — input: `saml.assertion.xml`,
`compressSaml`. Output: `saml.assertion.output`, `saml.assertion.compressed`.

**`ISAM-Common-SetSamlHeaders`** — input: whatever the two flows above just
set. Sets `X-SAML-Assertion`, `X-SAML-Assertion-Compressed`,
`X-SAML-Subject-Id` request headers plus `isam.exchanged.*` variables.

A type flow's job is: read its own KVM into `isam.config.*`, build its own
request, call `ISAM-Common-CallISAM`, parse its own response into
`saml.assertion.xml` (a single canonical name every common flow after that
point reads), then call the remaining three common flows in order. See
`types/type2-user-saml/sharedflowbundle/sharedflows/default.xml` for the
canonical example of that sequence — every SAML-bearing type follows it
exactly.

### Why a plain string, not a Message object, for `isamcall.response.body`

`ISAM-Common-CallISAM` hands back the ISAM response as a **plain string**
variable, not a Message-type object — deliberately, so it stays agnostic to
what the caller does with it. Each type's own `EV-Parse-*` step then points
`ExtractVariables`'s `<Source>` straight at that string variable (the same
technique Apigee's own docs use for `<Source>request.content</Source>` —
`.content` is itself just a string) and applies its own `XMLPayload` or
`JSONPayload` extraction. This is what makes the common/type split possible
without the common flow needing to know anything about WS-Trust vs JSON.

## Failover semantics

Only `ISAM-Common-CallISAM` implements failover, and it does exactly what
was asked: primary → secondary only on a transport-level failure or an
explicit HTTP 500 from the primary, never on other 4xx/5xx (a 400 would
presumably repeat identically on the secondary). A non-200 that isn't 500
returns normally from the common flow (with `isamcall.response.statusCode`
set accordingly) and it's each type's own response-parsing step that turns
"couldn't find what I expected in this body" into that type's own fault.

## Why Java is still here

Two operations, used by every SAML-bearing type via
`ISAM-Common-ValidateSignature` / `ISAM-Common-CompressAssertion`, have no
native Apigee policy and no safe JavaScript equivalent:

- **XML-DSig signature verification** needs XML canonicalization (C14N) plus
  RSA/X.509 verification — algorithmically substantial and
  security-sensitive enough that a hand-rolled JavaScript version would be a
  lot of code with real risk of getting subtly wrong in a way that *looks*
  like it validates. The Java version uses only JDK-standard
  `javax.xml.crypto.dsig` (JSR-105), no third-party crypto library.
- **zip/DEFLATE compression** has no native Apigee policy either, and while
  it *could* be reimplemented in pure JavaScript, that means porting or
  hand-writing a compliant DEFLATE encoder — hundreds of lines, with its own
  correctness risk, to replace three lines of `java.util.zip`.

Factoring both into their own common bundles means exactly two Java classes
exist for all six types combined, not up to twelve. Both were built and
tested (a real self-signed-cert-signed assertion for the validator:
valid/tampered/pinned/unpinned/unsigned cases and correct subject/lifetime
extraction; a real zip/base64 round trip for the compressor) — see
`java-callouts/isam-saml-callouts/README.md`.

Type 6 skips both entirely, per your answer: there's no SAML assertion to
validate or compress, only a JWT to pass through as-is.

## Dynamic-attribute simplifications (all WS-Trust and JSON types)

Two trade-offs, common to every type, fall out of building everything from
native Apigee policies (no JavaScript anywhere in this project):

- **Client IP**: no "first hop of X-Forwarded-For" parsing — that
  string-splitting needs code. Instead `client.ip` (Apigee's own view) and
  the raw `X-Forwarded-For` header are sent separately and verbatim; let
  ISAM's own mapping rule decide which it trusts.
- **Client certificate header**: hard-coded to `X-Client-Cert` in each
  type's `AM-Build-*-Request.xml`, rather than KVM-configurable — looking up
  a header by a name stored in *another* variable needs indirect variable
  resolution, which native Apigee templating can't do (only JavaScript
  could). If your header name varies, edit that one line per type. The
  value is also expected pre-normalized to bare base64 (no PEM armor, no
  URL-encoding) by whatever terminates mTLS in front of Apigee.

## Signature validation & trust

`ISAM-Common-ValidateSignature` verifies the assertion's `ds:Signature`
cryptographically matches the X.509 certificate embedded in that same
signature's `ds:KeyInfo` — i.e. "the assertion wasn't altered after whoever
holds that certificate's private key signed it." **That alone does not
prove ISAM signed it**: nothing stops an attacker who can inject a response
into this flow from generating their own keypair, embedding their own
self-signed certificate, and signing a forged assertion with it.

To close that gap, set `trustedSigningCertThumbprints` in each type's own
KVM to the SHA-256 thumbprint(s) of ISAM's actual signing certificate(s).
When set, `ISAM-Common-ValidateSignature` additionally rejects any assertion
whose signing cert isn't in that list:

```bash
openssl x509 -in isam-signing-cert.pem -noout -fingerprint -sha256
```

Leave it empty only if you have another way to establish trust in the
signer and understand the tradeoff.

## TLS trust for the outbound call to ISAM

`ISAM-Common-CallISAM`'s `ServiceCallout` policies reference
`ref://isam-truststore-ref`. If any ISAM host's TLS certificate is signed by
an internal/private CA, create a Keystore with that CA chain and a
Reference named `isam-truststore-ref` in the target environment:

```bash
apigeecli keystores create -n isam-truststore --env <env> --org <org> --token <token>
apigeecli keystores certs create -k isam-truststore --certfile isam-ca-chain.pem ...
apigeecli references create -n isam-truststore-ref --restype TrustStore --refers isam-truststore --env <env> --org <org> --token <token>
```

This is a single shared reference since it lives in `ISAM-Common-CallISAM`,
used by all six types regardless of which type-specific ISAM hosts they
call — if different types' ISAM hosts use different CAs, that truststore
needs to contain all of their chains.

## KVM config per type

Every type's KVM map has the same shape (fields listed once here; the key
*prefix* differs per type — see each `provision-kvm.sh`):

| Field | Required | Types 1-4 (WS-Trust) | Types 5-6 (JSON) |
|---|---|---|---|
| `host1` / `host2` | yes | ✓ | ✓ |
| `port` / `scheme` / `path` | yes | ✓ | ✓ |
| `appliesTo` / `tokenType` / `keyType` / `requestType` | yes | ✓ | ✓ |
| `connectTimeoutMs` / `ioTimeoutMs` | no | ✓ | ✓ |
| `compressSaml` | no | ✓ | type 5 only |
| `trustedSigningCertThumbprints` | no | ✓ | type 5 only |

| Type | KVM map | Key prefix | Script |
|---|---|---|---|
| 1 | `ISAM.SamlLight.Config` | `isam.saml.light.*` | `types/type1-light-saml/provision-kvm.sh` |
| 2 | `ISAM.SamlUser.Config` | `isam.saml.user.*` | `types/type2-user-saml/provision-kvm.sh` |
| 3 | `ISAM.SamlTP.Config` | `isam.saml.tp.*` | `types/type3-tp-saml/provision-kvm.sh` |
| 4 | `ISAM.SamlTechnical.Config` | `isam.saml.technical.*` | `types/type4-technical-saml/provision-kvm.sh` |
| 5 | `ISAM.JwtSaml.Config` | `isam.jwtsaml.*` | `types/type5-jwt-saml/provision-kvm.sh` |
| 6 | `ISAM.JwtToken.Config` | `isam.jwttoken.*` | `types/type6-jwt-token/provision-kvm.sh` |

Run any script with `ORG=... ENV=... TOKEN=$(gcloud auth print-access-token) ./provision-kvm.sh` (edit its `KEYS` array first).

## Java callouts

`ISAM-Common-ValidateSignature` and `ISAM-Common-CompressAssertion` are
backed by the single Maven module at `java-callouts/isam-saml-callouts/`.
Build it once and it drops the jar into both common bundles:

```bash
cd java-callouts/isam-saml-callouts
mvn -B package
```

See that module's own README for the class/property reference.

## Calling a type from a proxy

See `examples/FlowCallout-Sample.xml`. Attach a `FlowCallout` step
(referencing the one type bundle your proxy needs) in your proxy's PreFlow.
Any fault raised anywhere in the chain (missing config/bearer
token/client-cert, both ISAM hosts down, bad response, invalid signature)
propagates up as a raised fault for your proxy's own fault handling to
catch.

## Testing without a real ISAM

`dev-testing/` has two throwaway proxies for exactly this: `Mock-ISAM`
(returns canned, genuinely-signed SAML assertions/a mock JWT, plus routes to
simulate failover and an invalid signature) and `ISAM-Test-Caller` (calls
each of the six types and reports the result as JSON, so `curl` is enough
to test with). See `dev-testing/README.md` for the quickstart. Deploy both
only into a throwaway dev/test environment.

## Deploying

Each bundle (four common, six type-specific) follows the standard Apigee
shared flow bundle layout and deploys independently — via `apigeecli`,
Maven, or by zipping the bundle directory and importing through the Apigee
UI/Management API. Build the Java callout jar *first* so it's present under
both common bundles' `resources/java/` before packaging them. Deploy the
four common bundles before any type bundle that calls them (a `FlowCallout`
to an undeployed shared flow fails at runtime, not at import time). Example:

```bash
# common bundles first
for b in ISAM-Common-CallISAM ISAM-Common-ValidateSignature ISAM-Common-CompressAssertion ISAM-Common-SetSamlHeaders; do
  apigeecli sharedflows create -n "$b" -f "common/$b/sharedflowbundle" --org <org> --token <token>
  apigeecli sharedflows deploy -n "$b" --env <env> --org <org> --ovr --token <token>
done

# then whichever type(s) you need, e.g.:
apigeecli sharedflows create -n ISAM-SAML-User -f types/type2-user-saml/sharedflowbundle --org <org> --token <token>
apigeecli sharedflows deploy -n ISAM-SAML-User --env <env> --org <org> --ovr --token <token>
```

## Notes / things to confirm with the ISAM side

- **Types 1-4 (WS-Trust)**: the RST/RSTR shape (SOAP 1.2, WS-Trust 1.3
  `Issue`, `AdditionalContext` with `ContextItem`s for IP/cert/UA) matches
  ISAM's common Federation/STS chain pattern. The SAML assertion location
  (`RequestedSecurityTokenResponse/RequestedSecurityToken`, holding the
  assertion either as a real nested element or as XML-escaped text) is
  confirmed against a real ISAM response for the type this was originally
  built against — types 3 and 4 assume the same shape but haven't
  individually been confirmed; if either differs, only that type's
  `EV-Parse-ISAM-Response.xml` needs adjusting.
- **Type 1 specifically**: assumed to still return a full SAML RSTR despite
  carrying no bearer token; if ISAM's light-SAML endpoint responds
  differently (e.g. a bare assertion with no SOAP envelope at all), adjust
  `types/type1-light-saml/sharedflowbundle/policies/EV-Parse-ISAM-Response.xml`.
- **Type 5 (JWT-SAML)**: request shape
  (`requestType`/`tokenType`/`keyType`/`appliesTo`/`bearerToken`/`clientContext.*`)
  and response field names (`saml`/`subjectId`/`notBefore`/`notOnOrAfter`/`error`)
  are this repo's assumptions, not a confirmed ISAM contract.
- **Type 6 (JWT-Token)**: request shape assumed identical to type 5's;
  response field names (`token`/`tokenType`/`expiresIn`/`error`) are assumed
  too. `X-Access-Token` / `X-Access-Token-Type` are this repo's own header
  naming choice for surfacing the JWT — rename in
  `types/type6-jwt-token/sharedflowbundle/policies/AM-Set-JWT-Response-Header.xml`
  if your downstream expects something specific (e.g. `Authorization: Bearer`).
- **All types**: `TokenType`/`KeyType`/`RequestType`/`AppliesTo` are pulled
  from each type's own KVM as static values — confirm the actual values
  each ISAM endpoint expects; the provisioning scripts ship with placeholder
  defaults.
