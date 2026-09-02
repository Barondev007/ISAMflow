# Example proxy: orders-api

Shows how a proxy calls `SF-Signature-Router` to JWT-sign its request
body. See `../kvm` for the matching `orders-api.jwt.header` entry in
the shared `signature` KVM.

PreFlow (request):
1. `AM-Set-Signature-Type` — sets `signature.type = jwt` and stages
   `orders.txnId` from the `x-txn-id` request header (referenced by
   the KVM header template as `${orders.txnId}`).
2. `FC-Sign-JWT` — `FlowCallout` into `SF-Signature-Router`, which
   builds the JOSE header from KVM, base64url-encodes header and
   payload, and sets `signature.jwt.signing.string`.

Try it (after deploying both the shared flow and this proxy, and
creating the KVM):

```bash
curl -i "https://$HOST/orders" \
  -H "x-txn-id: txn-12345" \
  -d '{"orderId": "A-1"}'
```

Today this returns the shared flow's `501 Not Implemented` from
`NI-Signature-JWT-Sign` (the call to the external signature API isn't
wired up yet), with the computed `signature.jwt.signing.string` in the
response body so you can inspect it — or check the same variable in
Apigee trace.
