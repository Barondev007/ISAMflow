# signature-keystore-callout

JavaCallout that reads a certificate's public key out of an Apigee-managed
KeyStore and writes it as PEM text into a flow variable, so
`VerifyJWS`'s `<PublicKey><Value ref="..."/></PublicKey>` can consume it.

This exists because `VerifyJWS`'s own
`<PublicKey><KeyStore ref="..."/><Alias ref="..."/></PublicKey>` does **not**
resolve a dynamic `ref` at runtime — confirmed against a live Apigee
instance. Only `ServiceCallout`/`TargetEndpoint`'s
`<SSLInfo><KeyStore ref="...">` does that. Apigee's JS engine has no API to
read KeyStore key material either, so this one piece has to be compiled
Java, unlike everything else in this project.

## Before you build: one line is unverified

`PublicKeyFromKeystoreCallout.getExecutionContextKeystore()` calls
`execContext.getKeystore(keystoreName, false)` to get a
`java.security.KeyStore` handle for an Apigee-configured KeyStore by name.
That method name/signature is my best-confidence guess, not something I
could compile-check against the real SDK jar from here. See the class-level
comment in `PublicKeyFromKeystoreCallout.java` for what to do if it doesn't
compile as-is (check `ExecutionContext`'s real public API with
`javap -public com.apigee.flow.execution.ExecutionContext`, or fall back to
loading the cert from a bundled resource instead of the Apigee KeyStore —
only that one method needs to change either way).

## Getting the SDK jars

Apigee doesn't publish its Java Callout SDK to Maven Central under any
coordinates I can confirm. You need `message-flow-*.jar` and
`expressions-*.jar` (plus whatever they transitively require) from Apigee
itself — these ship with the Java callout samples/documentation for your
Apigee edition (Edge, Edge Microgateway, or Apigee X/hybrid — the download
location differs by edition, so check your Apigee docs/console for
"Java callout" or "Java callout SDK" rather than a link here, since I don't
have one I've verified). Once you have them:

```
mkdir -p lib
cp /path/to/message-flow-*.jar lib/message-flow.jar
cp /path/to/expressions-*.jar  lib/expressions.jar
```

## Build

```
mvn clean package
```

Produces `target/signature-keystore-callout.jar`.

## Deploy

Copy the built jar to:

```
SF-Signature-Validator/resources/java/signature-keystore-callout.jar
```

(overwriting the placeholder there, if any). This path is what
`JC-JWT-Verify-Extract-Public-Key.xml` references via
`<ResourceURL>java://signature-keystore-callout.jar</ResourceURL>`. If this
callout ever gains a dependency beyond the JDK and the Apigee SDK, its jar
also needs to go into `resources/java/` alongside it — Apigee doesn't
resolve dependencies at deploy time, it just loads every jar under
`resources/java/`.

## Config (set via the policy's `<Properties>`, not in this source)

- `keystore-name` — `{signature.verify.jwt.keystore.name}` (a flow-variable
  reference, resolved at request time — see the class-level comment for why
  it's `{...}` and not auto-resolved by Apigee)
- `alias` — `{signature.verify.jwt.keystore.alias}`
- `output-variable` — `signature.verify.jwt.publicKey.pem` (a literal flow-variable
  *name* to write the PEM into, not a ref)

Both `keystore-name`/`alias` ultimately come from the shared KVM `signature`
(see `EV-JWT-Verify-Parse-Config.xml`), same as before this change — only
how they reach `VerifyJWS` changed (through this callout's PEM output
instead of a direct `KeyStore`/`Alias` ref).
