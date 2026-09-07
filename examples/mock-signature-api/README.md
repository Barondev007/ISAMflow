# mock-signature-api

A mock of the external signature API that `SF-Signature-Router`'s
`NI-Signature-*-Sign` placeholders will eventually call — useful for
testing that side's request/response wiring before the real signing
service is available. No target backend: every response is built
directly in the proxy's PreFlow and returned via an empty `RouteRule`.

Every endpoint always returns the same fixed dummy success response —
no real HMAC or signature computation. Set the **`X-Mock-Fail`**
request header to `true` to get that endpoint's failure response
instead, for testing error handling on the caller's side.

## Endpoints

### `POST /scopes/{scope}/keys/{keyName}/hmacs:compute`

```bash
curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/hmac-key-1/hmacs:compute" \
  -H "Content-Type: application/json" -d '{"message": "hello world"}'
# {"hmac":"MOCK-HMAC-VALUE"}

curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/hmac-key-1/hmacs:compute" \
  -H "Content-Type: application/json" -H "X-Mock-Fail: true" -d '{"message": "hello world"}'
# 400 {"code":"mock_hmac_compute_failure","message":"Simulated hmacs:compute failure (X-Mock-Fail)."}
```

### `POST /scopes/{scope}/keys/{keyName}/hmacs:verify`

```bash
curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/hmac-key-1/hmacs:verify" \
  -H "Content-Type: application/json" -d '{"message": "hello world", "hmac": "anything"}'
# {"valid":"true"}
```

### `POST /scopes/{scope}/keys/{keyName}/signature:compute`

```bash
curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/rsa-key-1/signature:compute" \
  -H "Content-Type: application/json" -d '{"hash": "ZGlnZXN0Ynl0ZXM=", "algorithm": "SHA-256"}'
# {"mechanism":"ECDSAhSHA256","signature":{"m":"MOCK-M-VALUE","r":"MOCK-R-VALUE","s":"MOCK-S-VALUE"}}
```

`X-Mock-Fail: true` works the same way on all three endpoints, each
returning its own `{"code": "...", "message": "..."}` failure body at
`400`.

A path that doesn't match one of the three operations returns `404`
with the same error shape.
