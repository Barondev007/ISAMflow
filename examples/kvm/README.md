# Example KVM entries for orders-api

`KeyValueMapOperations`'s `mapIdentifier` (the KVM/table name) must be
a static literal in Apigee — it does not support `{variable}`
substitution at runtime. So each shared flow that needs per-proxy
config uses **one fixed, environment-scoped KVM**, shared by every
proxy that calls it, and puts the per-proxy part on the **entry key**
instead (`{apiproxy.name}.<sub-step>...`), which does support a
runtime variable via `<Parameter ref="...">`.

For the `orders-api` example proxy that's three entries across two KVMs:

| Shared flow | KVM | Entry key | Value |
|---|---|---|---|
| SF-Signature-Router (JWT) | `signature` | `orders-api.jwt.header` | JOSE header JSON template |
| SF-Signature-Router (Cavage) | `signature` | `orders-api.cavage.headers` | JSON array of header names to sign |
| SF-SAML-Extractor | `saml` | `orders-api.saml.elements` | JSON array of extraction rules |

## SF-Signature-Router: JWT

- `orders-api.signature.jwt-header.json` — the JOSE header template,
  for readability. Static fields (`typ`, `alg`, `kid`, `iss`) are
  literal; `${signature.jwt.iat}` / `.exp` / `.jti` are auto-populated
  by the shared flow; `${orders.txnId}` is set by the proxy's
  `AM-Set-Signature-Type` policy from the `x-txn-id` request header;
  `${saml.email}` (the `sub` claim) is set by `SF-SAML-Extractor`,
  which runs earlier in the proxy's flow (see below); `crit` names
  `x-txn-id` as an extension header a verifier must understand.
- `orders-api.jwt-header.entry.json` — the same template minified into
  a single string under key `orders-api.jwt.header`, ready to POST as
  the KVM entry (an entry value is always a string, so the JSON object
  has to be serialized before it's stored).

## SF-Signature-Router: Cavage

- `orders-api.cavage-headers.json` — the ordered header list, for
  readability: `(request-target)`, `(created)` and `(expires)` are
  computed by the shared flow; `host` and `x-request-id` are read
  as-is from the request; `digest` is reused if the request already
  carries a `Digest` header, otherwise computed (SHA-256 of the body)
  and attached.
- `orders-api.cavage-headers.entry.json` — the same array minified
  into a single string under key `orders-api.cavage.headers`, ready to
  POST as the KVM entry.

## SF-SAML-Extractor

- `orders-api.saml-elements.json` — the extraction rules, for
  readability: `saml.subject` from the assertion's `NameID` element;
  `saml.email` from the `<Attribute Name="email">` claim; and
  `saml.sessionIndex` from the `SessionIndex` XML attribute on
  `AuthnStatement`. The shared flow reads the assertion from the
  `X-SAML-Assertion` request header by default (raw XML or
  base64-encoded, auto-detected) — override the header name by
  setting `saml.header.name` before calling it.
- `orders-api.saml-elements.entry.json` — the same array minified
  into a single string under key `orders-api.saml.elements`, ready to
  POST as the KVM entry.

## Create the KVMs (once per environment) and entries (per proxy)

```bash
ORG=your-org
ENV=your-env
TOKEN=$(gcloud auth print-access-token)

# 1) Create the shared KVMs (once per environment, not per proxy)
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "signature"}'

curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "saml"}'

# 2) Create this proxy's entries
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.jwt-header.entry.json

curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.cavage-headers.entry.json

curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/saml/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.saml-elements.entry.json
```

To change an entry later, update it (`PUT` the same URL with
`/entries/<key>`) — no proxy or shared flow redeploy needed. Adding a
new proxy just adds new entries (`{proxyName}.jwt.header`,
`{proxyName}.cavage.headers`, `{proxyName}.saml.elements`) to these
same two KVMs.

## Or with apigeecli

```bash
apigeecli kvms create -n signature -o "$ORG" -e "$ENV" --token "$TOKEN"
apigeecli kvms create -n saml -o "$ORG" -e "$ENV" --token "$TOKEN"

apigeecli kvms entries create -m signature -k orders-api.jwt.header \
  -v "$(jq -c . orders-api.signature.jwt-header.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"

apigeecli kvms entries create -m signature -k orders-api.cavage.headers \
  -v "$(jq -c . orders-api.cavage-headers.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"

apigeecli kvms entries create -m saml -k orders-api.saml.elements \
  -v "$(jq -c . orders-api.saml-elements.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"
```
