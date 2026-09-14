# Example KVM entries for orders-api

`KeyValueMapOperations`'s `mapIdentifier` (the KVM/table name) must be
a static literal in Apigee — it does not support `{variable}`
substitution at runtime. So `SF-Signature-Router` uses **one fixed,
environment-scoped KVM named `signature`**, shared by every proxy that
calls it, and puts the per-proxy part on the **entry key** instead
(`{apiproxy.name}.<sub-step>...`), which does support a runtime
variable via `<Parameter ref="...">`.

For the `orders-api` example proxy that's three entries in the same KVM:

| Sub-step | Entry key | Value |
|---|---|---|
| JWT | `orders-api.jwt.header` | JOSE header JSON template |
| JWT | `orders-api.jwt.output` | plain string: the header name the finished JWS goes in |
| Cavage | `orders-api.cavage.headers` | JSON array of header names to sign |

`SF-SAML-Extractor` doesn't use a KVM at all — it just decodes the
assertion, then (since XPath can't be KVM-driven either — no
`{variable}` substitution inside `<XPath>`, not even the `Parameter
ref` indirection KVM keys get) runs a native `ExtractVariables` policy
selected by the calling proxy's `saml.extract.profile` flag, e.g.
`SF-SAML-Extractor/policies/EV-Extract-SAML-orders-api.xml`. See
`../orders-api-proxy/apiproxy/policies/AM-Set-SAML-Extract-Profile.xml`
for how a proxy opts into a profile.

## JWT

- `orders-api.signature.jwt-header.json` — the JOSE header template,
  for readability. Static fields (`typ`, `alg`, `kid`, `iss`) are
  literal; `${signature.jwt.iat}` / `.exp` / `.jti` are auto-populated
  by the shared flow; `${orders.txnId}` is set by the proxy's
  `AM-Set-Signature-Type` policy from the `x-txn-id` request header;
  `${saml.email}` (the `sub` claim) is set by
  `EV-Extract-SAML-Claims`, which runs earlier in the proxy's flow;
  `crit` names `x-txn-id` as an extension header a verifier must
  understand.
- `orders-api.jwt-header.entry.json` — the same template minified into
  a single string under key `orders-api.jwt.header`, ready to POST as
  the KVM entry (an entry value is always a string, so the JSON object
  has to be serialized before it's stored).
- `orders-api.jwt-output.entry.json` — key `orders-api.jwt.output`,
  value `"X-JWS-Signature"`. Just a header name, not JSON — read
  directly by `KVM-Get-JWT-Output-Header`, no parsing needed. Kept as
  its own entry rather than a field inside `orders-api.jwt.header`
  because `JS-Build-JWT-Signing-String` copies every top-level key of
  that entry straight into the JWT's actual JOSE header; an extra field
  there would leak into the token.

## Cavage

- `orders-api.cavage-headers.json` — the ordered header list, for
  readability: `(request-target)`, `(created)` and `(expires)` are
  computed by the shared flow; `host` and `x-request-id` are read
  as-is from the request; `digest` is reused if the request already
  carries a `Digest` header, otherwise computed (SHA-256 of the body)
  and attached.
- `orders-api.cavage-headers.entry.json` — the same array minified
  into a single string under key `orders-api.cavage.headers`, ready to
  POST as the KVM entry.

## Create the KVM (once per environment) and entries (per proxy)

```bash
ORG=your-org
ENV=your-env
TOKEN=$(gcloud auth print-access-token)

# 1) Create the shared KVM (once per environment, not per proxy)
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "signature"}'

# 2) Create this proxy's entries
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.jwt-header.entry.json

curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.jwt-output.entry.json

curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.cavage-headers.entry.json
```

To change an entry later, update it (`PUT` the same URL with
`/entries/<key>`) — no proxy or shared flow redeploy needed. Adding a
new proxy just adds new entries (`{proxyName}.jwt.header`,
`{proxyName}.jwt.output`, `{proxyName}.cavage.headers`) to this same
KVM.

## Or with apigeecli

```bash
apigeecli kvms create -n signature -o "$ORG" -e "$ENV" --token "$TOKEN"

apigeecli kvms entries create -m signature -k orders-api.jwt.header \
  -v "$(jq -c . orders-api.signature.jwt-header.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"

apigeecli kvms entries create -m signature -k orders-api.jwt.output \
  -v "X-JWS-Signature" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"

apigeecli kvms entries create -m signature -k orders-api.cavage.headers \
  -v "$(jq -c . orders-api.cavage-headers.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"
```
