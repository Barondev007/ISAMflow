# xmldsig-verify-callout

JavaCallout that verifies an enveloped XML Signature end to end —
canonicalization, digest, and the SignatureValue cryptographic check —
using the JDK's built-in JSR 105 implementation
(`javax.xml.crypto.dsig`, part of the standard Java platform since
Java 6, in the `java.xml.crypto` module).

This is the piece neither JavaScript nor any native Apigee policy can
do: Apigee's JS engine can't perform RSA/ECDSA math, and there is no
policy analogous to `VerifyJWS` for XML Signatures. Once a compiled
component is unavoidable for the actual crypto check anyway, doing
canonicalization *and* the digest *and* the signature-value check in
one conformant implementation is better than splitting canonicalization
into hand-written JS and only the crypto into Java — see
`XmlDsigVerifyCallout.java`'s class comment for the fixed
algorithm/shape allow-list this enforces (deliberately narrower than
"whatever the document declares," to close off XML Signature wrapping
attacks).

## No extra XML-security dependency

Unlike the earlier (now-removed) JWT KeyStore callout attempt, this one
needs **no** Apache Santuario or other XML-security library —
`javax.xml.crypto.dsig` ships with the JDK itself. The only dependency
is the Apigee Java Callout SDK, same as before.

## Getting the SDK jars

Apigee doesn't publish its Java Callout SDK to Maven Central under any
coordinates I can confirm. You need `message-flow-*.jar` and
`expressions-*.jar` from Apigee for your edition (Edge, Edge
Microgateway, or Apigee X/hybrid — check your Apigee docs/console for
"Java callout" or "Java callout SDK" rather than a link here, since I
don't have one I've verified). Once you have them:

```
mkdir -p lib
cp /path/to/message-flow-*.jar lib/message-flow.jar
cp /path/to/expressions-*.jar  lib/expressions.jar
```

## Build

```
mvn clean package
```

Produces `target/xmldsig-verify-callout.jar`. Compile with the same
JDK major version your Apigee message processor runs — `java.xml.crypto`
has shipped as a standard module in every mainstream JDK release to
date, but building against the same version you'll run on is good
practice regardless.

## Deploy

Copy the built jar to:

```
SF-Signature-Validator/resources/java/xmldsig-verify-callout.jar
```

`JC-XmlDsig-Verify-Signature.xml` references it via
`<ResourceURL>java://xmldsig-verify-callout.jar</ResourceURL>`.

## Config (set via the policy's `<Properties>`, not in this source)

- `document` — `{signature.verify.payload}` (a flow-variable reference,
  resolved at request time)
- `document-fallback` — `{message.content}`, used when `document` is
  empty
- `public-key-pem` — `{signature.verify.xmldsig.publicKey.pem}`
- `key-algorithm` — `{signature.verify.xmldsig.keyAlgorithm}` (defaults
  to `"RSA"` if the KVM entry leaves it blank)
- `output-prefix` — `signature.verify.xmldsig` (a literal flow-variable
  name *prefix* to write results under, not a ref)

`public-key-pem`/`key-algorithm` come from the shared KVM `signature`,
entry key `{apiproxy.name}.xmldsig.verify` — same pattern as JWT
verification (see `EV-XmlDsig-Verify-Parse-Config.xml`).
