# TPRF validation

Extra authorization step, run after the ISAM flow: TPRF confirms that the third party (TPP) is onboarded and allowed to call the requested method.

## Flow

```
ISAM flow (PreFlow)             -> client certificate, SAML clientId, SAML permissions
KVM-TPRF-Method-Scopes (proxy)  -> scopes of the called method (key = current.flow.name)
FC-TPRF-Validation (proxy)      -> shared flow tprf-validation:
   KVM-TPRF-Config              host, basepath, keystore/truststore references
   JS-TPRF-Prepare-Request      requested scopes = method scopes ∩ SIGNED_SCOPES, build the body
   RF-TPRF-Unauthorized         if the request cannot be built
   AM-TPRF-Request + SC-TPRF-Certificate-Validation
                                POST https://{host}/party/third-party-status-validation/v1/certificate-validation (mTLS)
   JS-TPRF-Evaluate-Response    certificateFound = Y, clientId entry found, at least one requested scope in scopeName
   RF-TPRF-Unauthorized         if not authorized
```

Request sent to TPRF:

```json
{
  "identifierValueBinary": "<client certificate, base64 DER>",
  "clientId": "d4f82d6c20ed4fa5ac244b072994df63",
  "scopesAbbreviationList": ["crm.servicing-request-snow-inbound-front.cash-accounts.validate"]
}
```

## Authorization rules

| Check | Source | Failure |
|---|---|---|
| Certificate and clientId are present | ISAM flow | 401 |
| At least one method scope is in `SIGNED_SCOPES` | KVM + SAML `permissions` | 401 (TPRF not called) |
| TPRF answers 2xx with valid JSON | TPRF | 401 |
| `certificateFound` = `Y` | TPRF | 401 |
| An entry of `clientApplicationList` has our `clientId` | TPRF | 401 |
| At least one requested scope is a `scopeName` of that entry | TPRF | 401 |

All failures return the same generic 401 body. The detailed reason is kept in `tprf.failure.reason` for logging.

The SAML `permissions` attribute has the format `CLIENT_SCOPES=a,b;SIGNED_SCOPES=c,d`. Only `SIGNED_SCOPES` (the scopes requested at token time) filters the request. `CLIENT_SCOPES` is exposed as `tprf.client.scopes` for logging, since TPRF is the source of truth for onboarding.

## Files

| Path | Content |
|---|---|
| `sharedflowbundle/` | The `tprf-validation` shared flow bundle |
| `proxy/policies/KVM-TPRF-Method-Scopes.xml` | Proxy policy: reads the method scopes |
| `proxy/policies/FC-TPRF-Validation.xml` | Proxy policy: calls the shared flow |
| `proxy/flow-example.xml` | Where to attach both steps in the ProxyEndpoint |
| `config/kvm-tprf-config.json` | Environment KVM `tprf-config` (host and keystore references) |
| `config/kvm-tprf-method-scopes.json` | Proxy KVM `<organization>.<apcode>.<appname>.v<major>.tprfscopes` |
| `test/` | Unit tests of the JavaScript: `node --test test/tprf-validation.test.js` |

## Configuration

`tprf-config` (environment scope):

| Entry | Meaning |
|---|---|
| `host` | TPRF host (no scheme) |
| `basepath` | `/party/third-party-status-validation/v1/certificate-validation` |
| `key-reference-name` | Keystore reference used for mTLS (used as `ref://<value>`) |
| `key-alias` | Key alias in that keystore |
| `trust-reference-name` | Truststore reference (used as `ref://<value>`) |

`<...>.tprfscopes` (proxy scope): one entry per operation. The entry name is the conditional flow name (`current.flow.name`, i.e. the operationId), and the value is a comma-separated list of scope names. Every operation must have at least one scope. An operation without an entry is rejected with 401.

## To adapt

- In `FC-TPRF-Validation.xml`, replace the placeholders `isam.client.certificate`, `isam.saml.clientId` and `isam.saml.permissions` with the variables set by your ISAM flow. The certificate can be PEM or base64 DER.
- In `KVM-TPRF-Method-Scopes.xml`, set `mapIdentifier` to your proxy's KVM name.
- Attach `KVM-TPRF-Method-Scopes` and `FC-TPRF-Validation` in each conditional flow, not in the PreFlow: `current.flow.name` is the operation name only inside the conditional flow.
