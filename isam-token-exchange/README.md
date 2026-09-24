# ISAM token exchange (type5-jwt-saml)

Shared flow `isam-token-exchange`. It calls the ISAM token endpoint with an OAuth2 token exchange and gets back a SAML token. Then it extracts `clientId` and `permissions` from the SAML assertion for the TPRF validation (`../tprf-validation`).

## Request

The body is `application/x-www-form-urlencoded`, not JSON. The `subject_token` parameter holds a JSON object:

```
subject_token=<JSON, URL-encoded>
&subject_token_type=urn:bnppf:json:stsuu | urn:bnppf:json:access-token
&grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:bnppf:saml:tech
&audience=urn:bnppf:b2b
```

Two subject token types are supported. The proxy picks one with its FlowCallout:

| | `stsuu` (end user) | `access-token` (technical user) |
|---|---|---|
| FlowCallout | `FC-ISAM-Token-Exchange-Stsuu` | `FC-ISAM-Token-Exchange-AccessToken` |
| `principal` | `userID` | `TECHNICAL-USER` |
| `attributes` | `authenticationMeanId`, `distributorId`, `dacLevel` (3), `ip-address`, `requestorType`, `user-agent`, `xLogId` | `distributorId`, `ipAddress`, `userAgent`, `authenticationMeanId`, `xLogId`, `requestorType` |
| `contextAttributes` | – | `access_token`, `request-ctx-env`, `request-ctx-cert-dn`, `request-ctx-cert` (URL-encoded PEM) |
| Required inputs | `userID` | bearer token, certificate, certificate DN |

`requestorType` is always `External_application`. A `Bearer ` prefix on the access token is removed. The attribute names differ between the two types (`ip-address` vs `ipAddress`, `user-agent` vs `userAgent`), exactly as in the reference requests.

## Response

The shared flow expects an RFC 8693 JSON response. Its `access_token` holds the SAML assertion, either base64 / base64url encoded or as raw XML. Outputs:

| Variable | Content |
|---|---|
| `isam.token` | `access_token` as returned by ISAM |
| `isam.saml.assertion` | Decoded SAML assertion |
| `isam.saml.clientId` | SAML attribute `clientId` (mandatory) |
| `isam.saml.permissions` | SAML attribute `permissions` (`CLIENT_SCOPES=…;SIGNED_SCOPES=…`) |

The flow returns 401 when an input is missing, when the ISAM call fails or returns a non-2xx status, or when the SAML has no `clientId`. The reason is kept in `isam.failure.reason`.

## Configuration

Environment KVM `isam-config` (`config/kvm-isam-config.json`) holds `host`, `basepath`, `key-reference-name`, `key-alias` and `trust-reference-name`. The call uses mTLS with `ref://<key-reference-name>` and `ref://<trust-reference-name>`, the same way as the TPRF call.

The FlowCallout `ref`s use the variable names of the existing ISAM templates: `userID`, `requestdistributorId` / `distributorId`, `authenticationMeanId`, `requestXForwardedFor`, `requestUserAgent`, `xb3Traceid`, `accesstoken`, `requestCtxEnv`, `requestCtxCertFullDn` and `requestctxcert`. They must be set before the FlowCallout runs.

## Tests

`node --test test/isam-token-exchange.test.js`
