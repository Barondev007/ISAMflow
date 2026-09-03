# SF-SAML-Extractor

Reads a SAML assertion from a request header and, per the calling
proxy's `saml.extract.profile` flag, runs that profile's native
`ExtractVariables` policy (real, compiled XPath) to pull elements out
of it into flow variables.

- `JS-Decode-SAML-Assertion` reads `request.header.<saml.header.name>`
  (default `X-SAML-Assertion`, override by setting `saml.header.name`
  before calling) and, unless it's already raw XML (starts with `<`),
  base64-decodes it into `saml.assertion.xml`.
- Add a profile: copy `policies/EV-Extract-SAML-orders-api.xml`, give
  it a new name and XPath set (use `local-name()` so it doesn't matter
  what namespace prefix the IdP emits), add a `<Step>` for it in
  `sharedflows/default.xml` gated on
  `saml.extract.profile = "<new profile>"`, and add that profile to
  `RF-Unsupported-SAML-Extract-Profile`'s `Condition`.
- The calling proxy sets `saml.extract.profile` (e.g. via
  `AssignMessage`) **before** the `FlowCallout` into this shared flow —
  see `examples/orders-api-proxy/apiproxy/policies/AM-Set-SAML-Extract-Profile.xml`.

## Operational requirement: header size

A real signed assertion (with an embedded X.509 certificate) easily
runs several KB once base64-encoded — comfortably past the default
header-size limits most WAFs, load balancers, and gateways enforce.
If the assertion is silently truncated before it reaches this shared
flow, XML parsing fails with:

```
Premature end of document while parsing at line 1
```

`JS-Decode-SAML-Assertion` and its base64 decoder are not the cause —
both are verified correct up to 50KB. If you see this error, check the
raw header length in Apigee trace ("Received Request") against what
the IdP actually issued; if it's shorter, the fix is a WAF/gateway
exception permitting a larger header size for this route, not a code
change here. There's no way to detect or work around truncation from
inside the shared flow — by the time Apigee sees the header, the
missing bytes are already gone.
