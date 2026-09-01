# Dev testing

Two throwaway Apigee proxies for exercising all six `ISAM-*` shared flows
without a real ISAM:

- **`Mock-ISAM/`** — stands in for ISAM. Returns canned, genuinely-signed
  SAML assertions (types 1-5) or a mock JWT (type 6), plus dedicated routes
  to simulate failover and an invalid signature.
- **`ISAM-Test-Caller/`** — calls each of the six shared flows and reports
  the result as JSON, so `curl`/Postman is enough to test with.

**Neither proxy has real auth or validation. Deploy both only into a
throwaway dev/test Apigee environment, never anything shared or
production-adjacent.**

## Quickstart

1. Build the Java callout jar (needed by two of the four `common/`
   bundles) and deploy the four common bundles, then whichever
   `types/type*` bundles you want to test:

   ```bash
   cd java-callouts/isam-saml-callouts && mvn -B package && cd -

   for b in ISAM-Common-CallISAM ISAM-Common-ValidateSignature ISAM-Common-CompressAssertion ISAM-Common-SetSamlHeaders; do
     apigeecli sharedflows create -n "$b" -f "common/$b/sharedflowbundle" --org "$ORG" --token "$TOKEN"
     apigeecli sharedflows deploy -n "$b" --env "$ENV" --org "$ORG" --ovr --token "$TOKEN"
   done

   for t in type1-light-saml type2-user-saml type3-tp-saml type4-technical-saml type5-jwt-saml type6-jwt-token; do
     name=$(grep -o 'name="ISAM-[A-Za-z-]*"' "types/$t/sharedflowbundle"/*.xml | head -1 | sed 's/name="//;s/"//')
     apigeecli sharedflows create -n "$name" -f "types/$t/sharedflowbundle" --org "$ORG" --token "$TOKEN"
     apigeecli sharedflows deploy -n "$name" --env "$ENV" --org "$ORG" --ovr --token "$TOKEN"
   done
   ```

2. Deploy the two dev-testing proxies:

   ```bash
   apigeecli apis create bundle -f dev-testing/Mock-ISAM/apiproxy --name Mock-ISAM --org "$ORG" --token "$TOKEN"
   apigeecli apis deploy --name Mock-ISAM --env "$ENV" --org "$ORG" --ovr --token "$TOKEN"

   apigeecli apis create bundle -f dev-testing/ISAM-Test-Caller/apiproxy --name ISAM-Test-Caller --org "$ORG" --token "$TOKEN"
   apigeecli apis deploy --name ISAM-Test-Caller --env "$ENV" --org "$ORG" --ovr --token "$TOKEN"
   ```

3. Point every type's KVM at Mock-ISAM:

   ```bash
   ORG=$ORG ENV=$ENV TOKEN=$TOKEN MOCK_HOST=your-org-your-env.apigee.net \
     ./dev-testing/provision-kvm-dev.sh
   ```

4. Call it:

   ```bash
   curl -s -X POST https://your-org-your-env.apigee.net/isam-test/user \
     -H 'Authorization: Bearer dev-test-token' | jq .
   ```

See each proxy's own README for its full route table, and
`Mock-ISAM/README.md` for how to simulate failover / a bad signature /
signing-cert pinning.

## Why two proxies instead of one

A single combined proxy could technically both call ISAM and mock it, but
that's not how the real deployment ever looks — the type-specific shared
flows always call a *separate* ISAM. Keeping the two proxies apart here
means the test setup matches production shape (proxy → shared flow →
external ISAM-shaped endpoint) and either one can be swapped out
independently: point `ISAM-Test-Caller`-equivalent traffic at a real ISAM
once you have one, or reuse `Mock-ISAM` standalone for testing something
else that expects an ISAM-shaped backend.
