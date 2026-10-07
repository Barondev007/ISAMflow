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

## Trust model: the verification key comes from the document, not KVM

**This is a deliberate choice, made explicitly after being warned about
its consequence — not an oversight.** The verification key is resolved
via a `javax.xml.crypto.KeySelector` that reads it straight out of the
signed document's own `KeyInfo` (preferring `KeyValue`, falling back to
the first certificate in `X509Data`) — there is no KVM entry for
XML-DSig verification config any more.

Validating a signature against a key that travels inside the same
message it signs proves only "whoever sent this possesses a private
key." It does **not** prove the message came from any specific,
previously-known party: an attacker able to modify the message in
transit can replace the signature *and* the embedded key/certificate
together with their own, and this callout will still report the result
as valid. If this bundle ever needs to assert *who* signed something —
not just that it wasn't altered after some signing event — that needs
either:
- pinning the embedded certificate against a known-expected one (e.g. a
  KVM-configured fingerprint, checked before trusting the key it
  contains), or
- full certificate-chain validation against a trusted CA
  (`java.security.cert.CertPathValidator`).

Neither is implemented here. The previous revision of this class (see
git history) took a `public-key-pem` KVM-configured Property instead of
reading the key from the document at all — restore that approach, or add
pinning on top of this one, if the "prove who signed it" guarantee turns
out to matter.

**Verified, not just reasoned about**: the `KeySelector` was run end to
end (via the real `Execution.execute()` entry point, not just a unit of
the canonicalization logic) against a genuinely signed document (passes,
resolving the key via `KeyValue`), a document whose `KeyInfo` only has
`X509Data` (passes, resolving via the certificate fallback), a precisely
tampered copy — one word changed in the payload, `KeyInfo` untouched —
(correctly rejected, the Reference digest check catches it), a document
with no `KeyInfo` at all, and a document whose `KeyInfo` has neither
`KeyValue` nor `X509Data` (both correctly rejected with a clear error,
not a crash).

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
- `output-prefix` — `signature.verify.xmldsig` (a literal flow-variable
  name *prefix* to write results under, not a ref)

No key-related config — see "Trust model" above for why.
