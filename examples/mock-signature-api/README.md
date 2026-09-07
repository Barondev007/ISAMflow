# mock-signature-api

A mock of the external signature API that `SF-Signature-Router`'s
`NI-Signature-*-Sign` placeholders will eventually call — useful for
testing that side's request/response wiring before the real signing
service is available. No target backend: every response is built
directly in the proxy's PreFlow and returned via an empty `RouteRule`.

## Endpoints

### `POST /scopes/{scope}/keys/{keyName}/hmacs:compute`

Real HMAC-SHA256, verified against Node's `crypto.createHmac`. The key
is derived deterministically from `scope` + `keyName` (not real
KMS-backed key material — this is a mock), so the same pair always
produces the same key, and `hmacs:compute`/`hmacs:verify` for that pair
round-trip correctly with each other.

```bash
curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/hmac-key-1/hmacs:compute" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello world"}'
# {"hmac":"LjOEgT6Ws0s6YgGMckRMIyDlY3Lb3QA3S9GRKRTw0eU="}
```

### `POST /scopes/{scope}/keys/{keyName}/hmacs:verify`

```bash
curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/hmac-key-1/hmacs:verify" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello world", "hmac": "LjOEgT6Ws0s6YgGMckRMIyDlY3Lb3QA3S9GRKRTw0eU="}'
# {"valid":"true"}
```

Using a different `scope`/`keyName` than the one the HMAC was computed
with returns `{"valid":"false"}`, same as a wrong `hmac` value —
correct, since the derived key differs.

### `POST /scopes/{scope}/keys/{keyName}/signature:compute`

```bash
curl -s -X POST "https://$HOST/mock-signature-api/scopes/orders/keys/rsa-key-1/signature:compute" \
  -H "Content-Type: application/json" \
  -d '{"hash": "ZGlnZXN0Ynl0ZXM=", "algorithm": "SHA-256"}'
# {"mechanism":"ECDSAhSHA256","signature":{"m":"...","r":"...","s":"..."}}
```

**Not a real signature.** Generating one needs actual RSA/ECDSA
private-key math (bignum modular exponentiation or elliptic-curve
point operations), which is out of scope for a mock with no real key
material. `m`/`r`/`s` are deterministic (same input → same output, so
still useful for testing that the caller parses the response shape
correctly) but carry no cryptographic meaning — don't feed them to a
real signature verifier expecting them to validate.

## Errors

Missing/invalid request fields, or a path that doesn't match one of
the three operations, return the spec's `{"code": "...", "message":
"..."}` shape with a `400` (or `404` for an unmatched path).
