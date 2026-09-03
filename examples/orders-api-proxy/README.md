# Example proxy: orders-api

Shows how a proxy calls `SF-SAML-Extractor` to pull claims out of an
inbound SAML assertion, then `SF-Signature-Router` to JWT-sign its
request body using one of them. See `../kvm` for the matching KVM
entries.

PreFlow (request):
1. `FC-Extract-SAML` — `FlowCallout` into `SF-SAML-Extractor`, which
   reads the SAML assertion from the `X-SAML-Assertion` request header
   and, per `orders-api.saml.elements` in the shared `saml` KVM, sets
   `saml.subject`, `saml.email` and `saml.sessionIndex`.
2. `AM-Set-Signature-Type` — sets `signature.type = jwt` and stages
   `orders.txnId` from the `x-txn-id` request header (referenced by
   the KVM header template as `${orders.txnId}`).
3. `FC-Sign-JWT` — `FlowCallout` into `SF-Signature-Router`, which
   builds the JOSE header from KVM — including `"sub": "${saml.email}"`,
   set by step 1 — base64url-encodes header and payload, and sets
   `signature.jwt.signing.string`.

Try it (after deploying both shared flows and this proxy, and creating
the KVMs):

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
Apigee trace, along with `saml.email` etc. set by `FC-Extract-SAML`.
