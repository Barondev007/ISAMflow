# Example proxy: orders-api

Shows how a proxy calls `SF-SAML-Extractor` — which decodes an inbound
SAML assertion and runs this proxy's `ExtractVariables` profile,
centralized inside the shared flow — then calls `SF-Signature-Router`
to JWT-sign its request body using one of the extracted claims. See
`../kvm` for the matching KVM entries.

PreFlow (request):
1. `AM-Set-SAML-Extract-Profile` — sets `saml.extract.profile = orders-api`,
   telling `SF-SAML-Extractor` which `ExtractVariables` profile to run.
   Must run before `FC-Extract-SAML` (a shared flow only sees a flow
   variable if it's already set when the `FlowCallout` executes).
2. `FC-Extract-SAML` — `FlowCallout` into `SF-SAML-Extractor`, which
   reads the SAML assertion from the `X-SAML-Assertion` request header
   (base64 or raw XML, auto-detected), sets `saml.assertion.xml`, then
   — because `saml.extract.profile = "orders-api"` — runs
   `EV-Extract-SAML-orders-api` (defined inside the shared flow, not
   this proxy): a plain `ExtractVariables` policy with
   `local-name()`-based XPath (namespace-prefix-agnostic) pulling out
   `saml.subject`, `saml.email` and `saml.sessionIndex`.
3. `AM-Set-Signature-Type` — sets `signature.type = jwt` and stages
   `orders.txnId` from the `x-txn-id` request header (referenced by
   the KVM header template as `${orders.txnId}`).
4. `FC-Sign-JWT` — `FlowCallout` into `SF-Signature-Router`, which
   builds the JOSE header from KVM — including `"sub": "${saml.email}"`,
   set by step 2 — base64url-encodes header and payload, and sets
   `signature.jwt.signing.string`.

Why the profile lives in the shared flow rather than a policy in this
proxy: XPath expressions are static per policy in Apigee (no `{var}`
substitution inside `<XPath>`, not even the `Parameter ref` indirection
KVM keys get), so a KVM can't drive them at runtime. Centralizing every
profile's `ExtractVariables` policy inside `SF-SAML-Extractor`, gated
by `saml.extract.profile`, means proxies with the same assertion shape
can share one profile, and a proxy that needs SAML extraction doesn't
need to carry its own copy of the policy — it just sets the flag. To
add a profile: see the comment in
`SF-SAML-Extractor/sharedflows/default.xml`.

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
Apigee trace, along with `saml.email` etc. set by
`EV-Extract-SAML-orders-api`.

If your real assertion is wrapped in something deeper (e.g. a WS-Trust
`RequestSecurityTokenResponse` around the `Assertion`), there's no
architectural change needed — just extend the XPath, e.g.
`//*[local-name()='RequestedSecurityToken']/*[local-name()='Assertion']/*[local-name()='Subject']/*[local-name()='NameID']/text()`.
