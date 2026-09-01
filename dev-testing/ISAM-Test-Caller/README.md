# ISAM-Test-Caller

A dev-only Apigee proxy that calls each of the six `ISAM-*` type-specific
shared flows and reports the result as JSON — so you can exercise every
type from `curl`/Postman without writing a real client, or attaching a
debug session to inspect flow variables by hand.

**Never deploy this outside a throwaway dev/test environment** — it has no
auth of its own and just forwards whatever `Authorization`/`X-Client-Cert`
header you send straight into the shared flow it calls.

## Routes

| Route | Calls | Needs |
|---|---|---|
| `POST /isam-test/light` | `ISAM-SAML-Light` | `X-Client-Cert` header (no bearer token) |
| `POST /isam-test/user` | `ISAM-SAML-User` | `Authorization: Bearer <token>` |
| `POST /isam-test/tp` | `ISAM-SAML-TP` | `Authorization: Bearer <token>` |
| `POST /isam-test/technical` | `ISAM-SAML-Technical` | `Authorization: Bearer <token>` |
| `POST /isam-test/jwt-saml` | `ISAM-JWT-SAML` | `Authorization: Bearer <token>` |
| `POST /isam-test/jwt-token` | `ISAM-JWT-Token` | `Authorization: Bearer <token>` |
| `GET /isam-test/` | — | this table, as JSON |

Optional on every SAML-bearing route: `?compressSaml=true` (or `false`) to
override that type's KVM default for the one call. Ignored on `/jwt-token`
(type 6 has no compression step).

Any bearer token / cert value works — Mock-ISAM doesn't validate them, it
just returns its canned response regardless of what you send. The header
just needs to be *present* for types that require one, since that check
happens before the call to ISAM.

## Example calls

```bash
BASE=https://YOUR-HOST/isam-test

# Type 1: light SAML, client cert only
curl -s -X POST "$BASE/light" -H 'X-Client-Cert: dGVzdC1jZXJ0LWJhc2U2NA==' | jq .

# Type 2: user SAML, with a bearer token, requesting compression
curl -s -X POST "$BASE/user?compressSaml=true" -H 'Authorization: Bearer dev-test-token' | jq .

# Type 6: JWT-is-the-token
curl -s -X POST "$BASE/jwt-token" -H 'Authorization: Bearer dev-test-token' | jq .
```

## Response shape

```json
{
  "ok": true,
  "saml": {
    "assertionBase64": "...",
    "assertionCompressed": "false",
    "subjectId": "jdoe@example.com",
    "notBefore": "2026-01-01T00:00:00Z",
    "notOnOrAfter": "2030-01-01T00:00:00Z"
  },
  "signature": {
    "valid": "true",
    "certSubject": "CN=Mock ISAM Dev Signer,O=Dev Testing",
    "certIssuer": "CN=Mock ISAM Dev Signer,O=Dev Testing",
    "certThumbprint": "9266C165C80B7128E208EA00827820DBC814E42375B4C087F0F8F2D947292566",
    "pinned": "false"
  },
  "jwt": {
    "accessToken": "",
    "accessTokenType": "",
    "expiresIn": ""
  },
  "isamStatusCode": "200"
}
```

One response shape covers all six types: the `saml`/`signature` fields
populate for types 1-5 and stay empty for type 6; the `jwt` fields populate
only for type 6. `saml.assertionBase64` is `saml.assertion.output` — a real
zip archive base64'd if `assertionCompressed` is true, otherwise a plain
base64 of the raw assertion XML; decode and unzip it to see the actual
assertion if you want to inspect it.

**If a shared flow raises a fault** (missing token/cert, ISAM down,
signature invalid, no assertion in the response, etc.) you get *that*
fault's own JSON body and HTTP status directly — this proxy doesn't wrap or
reformat it, since each fault already explains itself. E.g. hit `/user`
with no `Authorization` header to see `RF-Missing-Bearer-Token`'s 401
directly.

## Deploying

Deploy the four `common/ISAM-Common-*` bundles and whichever
`types/type*` bundles you want to test **first** (this proxy's
`FlowCallout`s fail at runtime, not at import time, if the shared flow they
reference isn't deployed yet):

```bash
apigeecli apis create bundle -f apiproxy --name ISAM-Test-Caller --org <org> --token <token>
apigeecli apis deploy --name ISAM-Test-Caller --env <env> --org <org> --ovr --token <token>
```

Then point the types you're testing at Mock-ISAM with
`../provision-kvm-dev.sh` before calling this proxy.
