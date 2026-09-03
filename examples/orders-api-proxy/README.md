# Example proxy: orders-api

Shows how a proxy calls `SF-SAML-Extractor` to decode an inbound SAML
assertion, extracts claims from it with a native `ExtractVariables`
policy, then calls `SF-Signature-Router` to JWT-sign its request body
using one of them. See `../kvm` for the matching KVM entries.

PreFlow (request):
1. `FC-Extract-SAML` — `FlowCallout` into `SF-SAML-Extractor`, which
   reads the SAML assertion from the `X-SAML-Assertion` request header
   (base64 or raw XML, auto-detected) and sets `saml.assertion.xml`.
2. `EV-Extract-SAML-Claims` — a plain `ExtractVariables` policy,
   `<Source>saml.assertion.xml</Source>`, with `local-name()`-based
   XPath (namespace-prefix-agnostic) pulling out `saml.subject`,
   `saml.email` and `saml.sessionIndex`. This is proxy-specific and
   hardcoded on purpose: XPath expressions are static per policy in
   Apigee, so each proxy that knows its own SAML shape just gets its
   own copy of this policy rather than a shared, KVM-driven engine.
3. `AM-Set-Signature-Type` — sets `signature.type = jwt` and stages
   `orders.txnId` from the `x-txn-id` request header (referenced by
   the KVM header template as `${orders.txnId}`).
4. `FC-Sign-JWT` — `FlowCallout` into `SF-Signature-Router`, which
   builds the JOSE header from KVM — including `"sub": "${saml.email}"`,
   set by step 2 — base64url-encodes header and payload, and sets
   `signature.jwt.signing.string`.

Try it (after deploying both shared flows and this proxy, and creating
the KVM):

```bash
SAML='<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Subject><saml2:NameID>jdoe@example.org</saml2:NameID></saml2:Subject>
  <saml2:AuthnStatement SessionIndex="sess-98765"/>
  <saml2:AttributeStatement>
    <saml2:Attribute Name="email"><saml2:AttributeValue>jdoe@example.org</saml2:AttributeValue></saml2:Attribute>
  </saml2:AttributeStatement>
</saml2:Assertion>'

curl -i "https://$HOST/orders" \
  -H "x-txn-id: txn-12345" \
  -H "X-SAML-Assertion: $(printf '%s' "$SAML" | base64 -w0)" \
  -d '{"orderId": "A-1"}'
```

Today this returns the shared flow's `501 Not Implemented` from
`NI-Signature-JWT-Sign` (the call to the external signature API isn't
wired up yet), with the computed `signature.jwt.signing.string` in the
response body so you can inspect it — or check the same variable in
Apigee trace, along with `saml.email` etc. set by `EV-Extract-SAML-Claims`.

If your real assertion is wrapped in something deeper (e.g. a WS-Trust
`RequestSecurityTokenResponse` around the `Assertion`), there's no
architectural change needed — just extend the XPath, e.g.
`//*[local-name()='RequestedSecurityToken']/*[local-name()='Assertion']/*[local-name()='Subject']/*[local-name()='NameID']/text()`.
