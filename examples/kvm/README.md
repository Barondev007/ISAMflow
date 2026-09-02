# Example KVM entry: orders-api.jwt.header

`KeyValueMapOperations`'s `mapIdentifier` (the KVM/table name) must be
a static literal in Apigee — it does not support `{variable}`
substitution at runtime. So `SF-Signature-Router` uses **one fixed,
environment-scoped KVM named `signature`**, shared by every proxy that
calls it, and puts the per-proxy part on the **entry key** instead
(`{apiproxy.name}.jwt.header`), which does support a runtime variable
via `<Parameter ref="...">`.

For the `orders-api` example proxy that means: KVM `signature`, entry
key `orders-api.jwt.header`.

- `orders-api.signature.jwt-header.json` — the JOSE header template,
  for readability. Static fields (`typ`, `alg`, `kid`, `iss`) are
  literal; `${signature.jwt.iat}` / `.exp` / `.jti` are auto-populated
  by the shared flow; `${orders.txnId}` is set by the proxy's
  `AM-Set-Signature-Type` policy from the `x-txn-id` request header;
  `crit` names `x-txn-id` as an extension header a verifier must
  understand.
- `orders-api.jwt-header.entry.json` — the same template minified into
  a single string under key `orders-api.jwt.header`, ready to POST as
  the KVM entry (an entry value is always a string, so the JSON object
  has to be serialized before it's stored).

## Create the KVM (once per environment) and entry (per proxy)

```bash
ORG=your-org
ENV=your-env
TOKEN=$(gcloud auth print-access-token)

# 1) Create the shared KVM (once per environment, not per proxy)
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "signature"}'

# 2) Create this proxy's entry
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.jwt-header.entry.json
```

To change the header later, update the entry (`PUT` the same URL with
`/entries/orders-api.jwt.header`) — no proxy or shared flow redeploy
needed. Adding a new proxy just adds a new entry (`{proxyName}.jwt.header`)
to this same KVM.

## Or with apigeecli

```bash
apigeecli kvms create -n signature -o "$ORG" -e "$ENV" --token "$TOKEN"
apigeecli kvms entries create -m signature -k orders-api.jwt.header \
  -v "$(jq -c . orders-api.signature.jwt-header.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"
```
