# Mock-ISAM

A dev-only Apigee proxy that stands in for ISAM. Point any type's KVM
`host1`/`host2`/`path` at this proxy (see `../provision-kvm-dev.sh`) and it
returns canned, **genuinely signed** SAML assertions or a mock JWT — real
enough that `ISAM-Common-ValidateSignature`'s actual signature verification
runs and passes, not something you have to bypass to test with.

**Never deploy this outside a throwaway dev/test environment.** It has no
auth of its own and always returns the same canned identities.

## Routes

| Path | Type | Response |
|---|---|---|
| `POST /mock-isam/light` | 1 | WS-Trust, SAML assertion as **XML-escaped text** in `RequestedSecurityToken` |
| `POST /mock-isam/user` | 2 | WS-Trust, SAML assertion as a **real nested element** |
| `POST /mock-isam/tp` | 3 | WS-Trust, XML-escaped text |
| `POST /mock-isam/technical` | 4 | WS-Trust, real nested element |
| `POST /mock-isam/jwt-saml` | 5 | JSON, `{"saml": "<assertion XML as a string>", "subjectId": ..., "notBefore": ..., "notOnOrAfter": ...}` |
| `POST /mock-isam/jwt-token` | 6 | JSON, `{"token": "<jwt>", "tokenType": ..., "expiresIn": ...}` (not cryptographically real — type 6 never verifies it) |
| `POST /mock-isam/{anything}/fail` | any | Always HTTP 500 |
| `POST /mock-isam/{anything}/tampered` | any | A signed assertion whose `Subject` was altered *after* signing — signature verification correctly fails on it |
| `GET /mock-isam/` | — | This table, as JSON |

The escaped-text vs. nested-element split across types 1-4 is deliberate:
it exercises **both** branches of `AM-Coalesce-SAML-Assertion`'s
nodeset/text fallback (see that policy's comment in each type bundle),
since real ISAM apparently uses both shapes depending on circumstance.

### Testing failover

`ISAM-Common-CallISAM` only fails over to the secondary host on a transport
failure or HTTP 500 from the primary. To exercise that with `host1`/`host2`
both pointed at this same mock, use different **paths**: set a type's
`*.host1`'s path (or just re-provision that one field) to
`/mock-isam/<type>/fail` while leaving `*.host2`'s path normal — the call
should fail over and still succeed. Set both to `/fail` to instead trigger
`RF-ISAM-Unavailable` (HTTP 502).

### Testing signature-invalid handling

Point a type's path at `/mock-isam/{type}/tampered` (any type) to confirm
`RF-SAML-Signature-Invalid` (HTTP 502) actually fires when ISAM's signature
doesn't check out.

### Testing signing-cert pinning

The assertions are all signed by the same test key. Its SHA-256 thumbprint
(also in `mock-isam-signing-cert.pem` alongside this README):

```
9266C165C80B7128E208EA00827820DBC814E42375B4C087F0F8F2D947292566
```

Set a type's `trustedSigningCertThumbprints` KVM entry to this value (see
`../provision-kvm-dev.sh`'s `TRUSTED_THUMBPRINT` env var) to confirm
signature validation still passes when pinning is enforced; set it to some
other value instead to confirm pinning correctly *rejects* an otherwise-valid
signature from an untrusted cert.

## Deploying

Standard Apigee proxy bundle layout (`apiproxy/`), deploys like any proxy:

```bash
apigeecli apis create bundle -f apiproxy --name Mock-ISAM --org <org> --token <token>
apigeecli apis deploy --name Mock-ISAM --env <env> --org <org> --ovr --token <token>
```

No target/backend, no Java callout, no KVM of its own — every response is
a static `AssignMessage` (see `apiproxy/policies/AM-Respond-*.xml`), so
there's nothing else to provision before deploying this one.

## Regenerating the signed assertions

The five canned assertions embedded in `apiproxy/policies/AM-Respond-*.xml`
were generated with the JDK's own `javax.xml.crypto.dsig` (JSR-105) — the
same code path `SamlSignatureValidator` uses to verify them — via a
throwaway `keytool` + small Java program, not checked into this repo (it's
a one-off generation script, not part of the deployable artifact). If you
need to regenerate them (e.g. with a different subject or your own test
cert), open an issue/ask, since the exact byte content matters: the
assertion XML in each `AM-Respond-*.xml` must be embedded **verbatim** —
any re-indentation or whitespace change inside the signed element would
invalidate its signature.
