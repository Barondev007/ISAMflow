# ISAM-WSTrust-TokenExchange (Apigee Shared Flow)

An Apigee shared flow that exchanges an inbound bearer token for an ISAM-issued
token via WS-Trust, with:

- ISAM host/config lookup from an environment KVM (no hard-coded hosts)
- A dynamically built WS-Trust `RequestSecurityToken` (RST) SOAP request, mixing
  static config attributes with attributes pulled off the inbound request
  (bearer token, client IP, client certificate, user agent)
- Automatic failover from the primary to the secondary ISAM host
- Parsing of the `RequestSecurityTokenResponse` (RSTR) into flow variables the
  calling proxy can read

## Layout

```
sharedflowbundle/
  ISAM-WSTrust-TokenExchange.xml   # root bundle descriptor
  policies/                        # one XML file per policy, see below
  sharedflows/default.xml          # the flow, step order + conditions
  resources/jsc/build-wstrust-request.js
examples/
  FlowCallout-Sample.xml           # how to call this from an API proxy
scripts/
  provision-kvm.sh                 # creates/updates the KVM entry
```

## Flow

1. **KVM-Get-ISAMConfig** — `KeyValueMapOperations` reads a single JSON blob
   (key `isam.sts.config`) from the environment-scoped KVM `ISAM.WSTrust.Config`
   into `isam.config.raw`.
2. **JS-Build-WSTrust-Request** — parses/validates that JSON, pulls the
   `Authorization: Bearer …` header, `client.ip`, `User-Agent`, and (optionally)
   a forwarded client certificate header off the request, and builds the WS-Trust
   SOAP envelope (`wstrust.request.payload`) plus the two target URLs
   (`wstrust.target.url.primary` / `.secondary`).
3. **RF-ISAM-Config-Missing** / **RF-Missing-Bearer-Token** — short-circuit with
   a clear error if the KVM entry is missing/invalid or there's no bearer token.
4. **SC-Call-ISAM-Primary** — POSTs the SOAP request to the primary ISAM host
   (`continueOnError="true"` so failure doesn't abort the flow outright).
5. **SC-Call-ISAM-Secondary** — runs only if the primary call failed or didn't
   return HTTP 200, POSTing the same payload to the secondary host.
6. **RF-ISAM-Unavailable** — raised only if both hosts failed.
7. **EV-Parse-Primary-Response** / **EV-Parse-Secondary-Response** — whichever
   host actually answered gets its RSTR parsed via XPath into `isam.rstr.token`,
   `isam.rstr.tokenType`, `isam.rstr.created`, `isam.rstr.expires`, `isam.rstr.fault`.
8. **RF-WSTrust-Fault** — raised if no token was extracted (SOAP Fault, or ISAM
   rejected the request).
9. **AM-Set-TokenExchange-Response** — copies the parsed values into stable
   output variables: `isam.exchanged.token`, `isam.exchanged.token.type`,
   `isam.exchanged.token.expires`.

## KVM config shape

Single key `isam.sts.config` in KVM `ISAM.WSTrust.Config` (environment-scoped),
value is a JSON string:

```json
{
  "host1": "isam1.internal.example.com",
  "host2": "isam2.internal.example.com",
  "port": "443",
  "scheme": "https",
  "path": "/TrustServer/SecurityTokenService",
  "connectTimeoutMs": "5000",
  "ioTimeoutMs": "10000",
  "appliesTo": "urn:isam:relying-party:my-service",
  "tokenType": "urn:ietf:params:oauth:token-type:jwt",
  "keyType": "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer",
  "requestType": "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
  "clientCertHeader": "X-Client-Cert"
}
```

All fields except `connectTimeoutMs`/`ioTimeoutMs`/`clientCertHeader` are
required — `JS-Build-WSTrust-Request` treats the config as invalid otherwise.
Use `scripts/provision-kvm.sh` to create/update this entry:

```bash
ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
  ./scripts/provision-kvm.sh
```

Edit the JSON block in the script (or point `CONFIG_JSON_FILE` at a file)
before running it against a real environment.

## Dynamic (per-request) attributes

| WS-Trust element                                | Source                                                             |
|--------------------------------------------------|----------------------------------------------------------------------|
| `wsse:BinarySecurityToken` (header + OnBehalfOf) | `Authorization: Bearer <token>` request header                     |
| `AdditionalContext/ContextItem[@Name='ip']`      | `client.ip`, falling back to first hop of `X-Forwarded-For`         |
| `AdditionalContext/ContextItem[@Name='userAgent']` | `User-Agent` request header (omitted if absent)                   |
| `AdditionalContext/ContextItem[@Name='clientCertificate']` | Header named by `clientCertHeader` in the KVM config (omitted if absent) |
| `wsa:MessageID`                                   | Generated UUID per request                                          |

The client certificate is expected as a URL-encoded PEM in a header, which is
the common convention when TLS/mTLS is terminated by a load balancer or NGINX
in front of Apigee (e.g. NGINX's `$ssl_client_escaped_cert`, or an ALB's
`X-Amzn-Mtls-Clientcert`). Confirm the actual header name/format with whoever
terminates mTLS and set `clientCertHeader` accordingly. If Apigee itself
terminates mutual TLS on the ProxyEndpoint, adjust `JS-Build-WSTrust-Request`
to read the appropriate `ssl_info.*` flow variables instead.

## TLS trust for the outbound call to ISAM

The `ServiceCallout` policies reference `ref://isam-truststore-ref`. If ISAM's
TLS certificate is signed by an internal/private CA, create a Keystore
containing that CA chain in the target environment and create a Reference
named `isam-truststore-ref` pointing at it:

```
apigeecli keystores create -n isam-truststore --env <env> --org <org> --token <token>
apigeecli keystores certs create -k isam-truststore --certfile isam-ca-chain.pem ...
apigeecli references create -n isam-truststore-ref --restype TrustStore --refers isam-truststore --env <env> --org <org> --token <token>
```

If ISAM's cert chains to a public/well-known CA already trusted by Apigee,
you can drop the `<SSLInfo>` block from both `SC-Call-ISAM-*` policies.

## Calling this shared flow from a proxy

See `examples/FlowCallout-Sample.xml`. Attach a `FlowCallout` step (referencing
`SharedFlowBundle: ISAM-WSTrust-TokenExchange`) in your proxy's PreFlow, then
read `isam.exchanged.token` to set the header your backend expects.

## Deploying

This directory follows the standard Apigee shared flow bundle layout, so it
deploys the same way any shared flow does — via `apigeecli`, Maven
(`apigee-config-maven-plugin` / `apigee-deploy-maven-plugin`), or by zipping
`sharedflowbundle/` and importing it through the Apigee UI/Management API.
Example with `apigeecli`:

```bash
apigeecli sharedflows create -n ISAM-WSTrust-TokenExchange \
  -f sharedflowbundle --org <org> --token <token>
apigeecli sharedflows deploy -n ISAM-WSTrust-TokenExchange \
  --env <env> --org <org> --ovr --token <token>
```

## Notes / things to confirm with the ISAM side

- The RST/RSTR shape here (SOAP 1.2, WS-Trust 1.3 `Issue`, `AdditionalContext`
  with `ContextItem`s for IP/cert/UA) matches ISAM's common Federation/STS
  chain pattern where a JavaScript STS module maps `AdditionalContext` into
  custom claims — confirm the exact `ContextItem` names your ISAM mapping rule
  expects.
- `TokenType`, `KeyType`, `RequestType`, and `AppliesTo` are all pulled from
  KVM as static values — adjust them per relying party if you end up needing
  more than one profile.
- Bearer token is embedded both in the WS-Security header (`wsse:Security`)
  and in `wst:OnBehalfOf`; drop whichever one your ISAM STS chain doesn't
  expect to keep the request minimal.
