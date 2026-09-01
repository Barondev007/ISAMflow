# Example KVM: orders-api.signature

Matches the `examples/orders-api-proxy` proxy, which has `apiproxy name = orders-api`,
so `SF-Signature-Router`'s `AM-JWT-Set-KVM-Name` step looks up KVM
`orders-api.signature`.

- `orders-api.signature.jwt-header.json` — the JOSE header template, for
  readability. Static fields (`typ`, `alg`, `kid`, `iss`) are literal;
  `${signature.jwt.iat}` / `.exp` / `.jti` are auto-populated by the
  shared flow; `${orders.txnId}` is set by the proxy's
  `AM-Set-Signature-Type` policy from the `x-txn-id` request header;
  `crit` names `x-txn-id` as an extension header a verifier must
  understand.
- `orders-api.signature.entry.json` — the same template minified into
  a single string, ready to POST as the KVM entry value (a KVM entry
  value is always a string, so the JSON object has to be serialized
  before it's stored).

## Create the KVM and entry (Apigee X / hybrid Management API)

```bash
ORG=your-org
ENV=your-env
TOKEN=$(gcloud auth print-access-token)

# 1) Create the KVM (once per proxy)
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "orders-api.signature"}'

# 2) Create the jwt.header entry
curl -s -X POST \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/keyvaluemaps/orders-api.signature/entries" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @orders-api.signature.entry.json
```

To change the header later, update the entry (`PUT` the same URL with
`/entries/jwt.header`) — no proxy or shared flow redeploy needed.

## Or with apigeecli

```bash
apigeecli kvms create -n orders-api.signature -o "$ORG" -e "$ENV" --token "$TOKEN"
apigeecli kvms entries create -m orders-api.signature -k jwt.header \
  -v "$(jq -c . orders-api.signature.jwt-header.json)" \
  -o "$ORG" -e "$ENV" --token "$TOKEN"
```
