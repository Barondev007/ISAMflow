# xmldsig-sign-callout

One jar, two JavaCallout classes, covering all of XML-DSig signature
generation in Java — no JavaScript anywhere in this path:

- **`XmlDsigSignCallout`** (policy `JC-Build-XmlDsig-Signing-String`) —
  canonicalizes the target document, computes its digest, builds
  `<SignedInfo>`, and canonicalizes that too, producing the exact bytes
  an external signing API needs to RSA/ECDSA-sign.
- **`XmlDsigAssembleSignatureCallout`** (policy
  `JC-Assemble-XmlDsig-Signature`) — once that external API has signed
  those bytes, assembles the final `<Signature>` — SignedInfo +
  SignatureValue + KeyInfo — and inserts it into the document. KeyInfo
  carries the signer's key two ways, both derived from the same
  KVM-configured certificate: `<KeyValue><RSAKeyValue><Modulus>`/
  `<Exponent>` (the raw key, no certificate parsing needed — RSA only)
  and `<X509Data><X509Certificate>` (the full certificate — any key
  type). Embedding both is what makes the result independently
  verifiable: **any** compliant XML-DSig verifier can check it using
  nothing but the document itself, not just this gateway's own validator,
  regardless of which KeyInfo child that verifier happens to prefer.

Both use the JDK's own `org.w3c.dom`/`javax.xml.parsers` APIs plus a
from-scratch Exclusive C14N implementation (`XmlC14n.java`), not
`javax.xml.crypto.dsig` (JSR 105).

## Why not JSR 105, when the verify-side callout uses it?

Verification (`xmldsig-verify-callout`, in the sibling
`SF-Signature-Validator` module) hands the whole signed document to
`XMLSignatureFactory.unmarshalXMLSignature()` + `signature.validate()` —
JSR 105 does canonicalization internally as part of that one all-in-one
call, and never needs to expose the canonical bytes back to the caller.

Generation is a different shape of problem: the actual RSA/ECDSA signing
happens on an **external** signing API (see
`../policies/NI-Signature-XmlDsig-Sign.xml`), not with a local private
key, so `XmlDsigSignCallout` needs the raw canonicalized `<SignedInfo>`
bytes as an output, to hand to that external API. JSR 105's public API
doesn't support that:

- `CanonicalizationMethod.transform(Data, XMLCryptoContext, OutputStream)`
  needs a `Data`/`NodeSetData` wrapping the DOM subtree, and the JDK ships
  no public class that constructs one from an arbitrary `org.w3c.dom.Node`
  (`javax.xml.crypto.dom.DOMSubTreeData` does not exist — this was
  checked directly against this JDK's `java.xml.crypto` module, not
  assumed).
- The internal canonicalizer the JSR 105 reference implementation itself
  uses (`com.sun.org.apache.xml.internal.security.c14n.Canonicalizer`) is
  in a package the `java.xml.crypto` module does not export — confirmed
  with a direct `javac` attempt: *"package
  com.sun.org.apache.xml.internal.security.c14n is not visible ...
  declared in module java.xml.crypto, which does not export it."*
- The remaining option — do a real `XMLSignature.sign()` with a throwaway
  key pair, using a substitute `java.security.Provider` to intercept and
  capture the bytes it's asked to sign instead of actually signing them —
  works, but only via `Security.insertProviderAt()`, a **JVM-global**
  mutation. On a shared, multi-tenant Apigee Message Processor running
  many proxies concurrently, that's a real risk: any other thread's
  unrelated RSA/EC signing (or even a TLS handshake) could be intercepted
  by the substitute provider during the window it's registered. Not an
  acceptable default.

So `XmlDsigSignCallout` canonicalizes the target document (and the
synthetic `<SignedInfo>` it builds) with its own `XmlC14n`, operating on a
`org.w3c.dom.Document` parsed by the standard `DocumentBuilder` — the same
parser the verify-side callout already uses. This is a direct port of the
rendering logic from the former `resources/jsc/xml-exc-c14n.js`, with that
script's hand-rolled regex-based XML *parser* replaced entirely by the
JDK's real one (the highest-risk part of the original), and one bug fixed
along the way: the JS version silently dropped processing instructions,
which Canonical XML 1.0 requires to be preserved (only comments are
dropped). Found by cross-checking this port's output against an
independent third implementation (Python's `lxml`,
`etree.tostring(method="c14n", exclusive=True)`) on a document containing
a PI, where the two disagreed.

`XmlDsigAssembleSignatureCallout` embeds the already-canonicalized
`<SignedInfo>` text verbatim, unchanged, rather than rebuilding it from
the `XMLSignatureFactory` object model — see that class's own comment for
why that's not just simpler but *necessary* for correctness (Exclusive
C14N canonicalizes a subtree using only that subtree's own namespace
declarations, independent of where it ends up nested afterward).

## Verified before being wired in

**Canonicalization**: byte-for-byte identical output to both the JS
version it replaces and to `lxml`'s canonicalizer, across documents
exercising default-namespace declaration/undeclaration at multiple
depths, prefixed/unprefixed attribute sorting by namespace URI, the
implicit `xml` prefix, CDATA, comments, and processing instructions. The
full signing-string pipeline (digest + SignedInfo construction, not just
canonicalization) was also diffed end-to-end against the real, unmodified
`xmldsig-build-signing-string.js` running under Node — only the
PI-handling difference above showed up, exactly as expected.

**Assembly + embedded key material**: a full dry run — build signing
string, sign with a real throwaway RSA keypair standing in for the
external signing API, assemble the final document with its `KeyValue`
and certificate embedded — was validated multiple ways, using *only*
what's in the assembled document, no out-of-band config:

1. JSR 105's own `XMLSignature.validate()` (the same engine
   `xmldsig-verify-callout` uses), with the public key pulled from the
   document's own embedded `<X509Certificate>`.
2. The same validation again, this time with the public key built
   *only* from the embedded `<RSAKeyValue>`'s Modulus/Exponent — the
   certificate ignored entirely — to prove `KeyValue` is independently
   sufficient, not just decorative alongside `X509Data`.
3. `xmlsec1` — an independent, widely-used C implementation (libxmlsec,
   unrelated to the JDK) — `xmlsec1 verify --insecure signed.xml`
   reported `OK`, `SignedInfo References (ok/all): 1/1`.
4. The embedded Modulus bytes cross-checked against `openssl x509
   -noout -modulus` on the same certificate — byte-for-byte identical —
   and the Exponent decoded to the expected `65537`.

A tampered copy of the same signed document (one digit changed in a
value) was correctly **rejected** by `xmlsec1` with a digest mismatch —
confirming the signature actually protects content integrity, not just
producing a document that happens to parse.

Both classes were also compile-checked against stand-in Apigee SDK types,
since the real SDK jars aren't available in this environment.

## No extra XML-security dependency

Same as the sibling `xmldsig-verify-callout`: no Apache Santuario or other
XML-security library. Everything here is `org.w3c.dom`,
`javax.xml.parsers`, `javax.xml.transform` (for final serialization),
`java.security.MessageDigest`, `java.security.cert.CertificateFactory`,
and `java.util.Base64` — all standard since Java 5/6. The only dependency
is the Apigee Java Callout SDK.

## Getting the SDK jars

Same as `xmldsig-verify-callout` — see
`../../SF-Signature-Validator/java-src/README.md` for the general
instructions (Apigee doesn't publish `message-flow-*.jar`/
`expressions-*.jar` to Maven Central under any coordinates confirmed from
here). Once you have them:

```
mkdir -p lib
cp /path/to/message-flow-*.jar lib/message-flow.jar
cp /path/to/expressions-*.jar  lib/expressions.jar
```

## Build

```
mvn clean package
```

Produces `target/xmldsig-sign-callout.jar`, containing both classes.

## Deploy

Copy the built jar to:

```
SF-Signature-Router/resources/java/xmldsig-sign-callout.jar
```

Both `JC-Build-XmlDsig-Signing-String.xml` and
`JC-Assemble-XmlDsig-Signature.xml` reference it via
`<ResourceURL>java://xmldsig-sign-callout.jar</ResourceURL>`.

## Config (set via each policy's `<Properties>`, not in this source)

### `XmlDsigSignCallout` / `JC-Build-XmlDsig-Signing-String.xml`

- `document` — `{signature.payload}` (a flow-variable reference, resolved
  at request time)
- `document-fallback` — `{message.content}`, used when `document` is empty
- `signature-method` — `{signature.xmldsig.signatureMethod}`
- `default-signature-method` — a literal value, used when
  `signature-method` resolves empty (defaults to
  `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` even if this
  property is left out entirely)
- `output-prefix` — `signature.xmldsig` (a literal flow-variable name
  *prefix* to write results under, not a ref)

Sets `<output-prefix>.signatureMethod`, `<output-prefix>.digest.value`,
`<output-prefix>.signedinfo.canonical`, and
`<output-prefix>.signing.string`.

### `XmlDsigAssembleSignatureCallout` / `JC-Assemble-XmlDsig-Signature.xml`

- `document` / `document-fallback` — same as above; must be the **same**
  document that was signed.
- `signed-info` — `{signature.xmldsig.signedinfo.canonical}`, from the
  build step above.
- `signature-value` — `{signature.xmldsig.signatureValue}`, the base64
  SignatureValue the external signing API must set (see
  `NI-Signature-XmlDsig-Sign.xml` — still a placeholder for that call).
- `certificate-pem` — `{signature.xmldsig.certificate.pem}`, from this
  proxy's KVM entry (`{apiproxy.name}.xmldsig.sign`, see
  `EV-XmlDsig-Sign-Parse-Config.xml` and
  `../../examples/kvm/orders-api.signature.xmldsig-sign.json`). A full
  X.509 certificate, not just the bare public key — `<X509Certificate>`
  needs the whole cert.
- `output-prefix` — `signature.xmldsig`

**Known pitfall, now handled**: `XmlDsigAssembleSignatureCallout` runs
`certificate-pem` through `normalizePem()` before parsing it, which turns
literal two-character `\n`/`\r\n`/`\r` escape sequences into real
newlines. This matters because `EV-XmlDsig-Sign-Parse-Config.xml`'s own
comment claims Apigee's `ExtractVariables`/JSONPath unescapes a JSON
string's `\n` into a real newline automatically — that claim was
documented but never actually verified against a live Apigee instance,
and a user hit exactly the failure mode you'd expect if it's wrong on
their Apigee version: `CertificateFactory` refusing a PEM string whose
`-----BEGIN CERTIFICATE-----` line never actually ends (because the
"newline" after it is still the two characters `\`+`n`, not a real
line break), with an error to the effect of "not a valid X.509
certificate" / "unexpected data in stream" (exact wording is JDK-version
dependent — confirmed to vary across JDK versions for this same
underlying cause, so don't pattern-match on the literal text). The
normalization is a no-op on PEM text that's already correctly escaped,
so this costs nothing when the assumption does hold.

**The same assumption is unverified everywhere else in this project a
PEM value is pulled out of a KVM-backed JSON config via
`ExtractVariables`/JSONPath** — most notably JWT verification's
`signature.verify.jwt.publicKey.pem`, consumed directly by the native
`VerifyJWS` policy's `<PublicKey><Value ref="...">`. Unlike here, there's
no Java callout in that path to add a normalization step to — if the
same symptom shows up there (`VerifyJWS` rejecting a KVM-configured
public key that looks correct), the fix is a native `AssignMessage` or
`JS` step before `VerifyJWS` that does the same `\n`-literal-to-real-
newline substitution before the PEM is used.

Sets `<output-prefix>.signed.document` — the complete signed XML, ready
for the calling proxy to use as its response or request body.
