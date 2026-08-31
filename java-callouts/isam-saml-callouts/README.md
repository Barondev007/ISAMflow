# isam-saml-callouts

Two Apigee Java callouts shared by both the `ISAM-WSTrust-TokenExchange` and
`ISAM-JSON-TokenExchange` shared flows (same jar, same classes — each policy
instance just points the `assertionVariable`/etc. properties at that bundle's
own variable names; see the class reference below). Apigee has no native
policy for XML-DSig signature verification or zip compression, so both are
implemented here using JDK standard-library APIs only (`javax.xml.crypto.dsig`,
`java.util.zip`) — no third-party dependency beyond Apigee's own callout SDK.

- **`SamlSignatureValidator`** (`JC-Validate-SAML-Signature`) — verifies the
  `ds:Signature` wrapped around the SAML assertion using the X.509 certificate
  embedded in the signature's own `ds:KeyInfo`, with optional SHA-256
  thumbprint pinning against `isam.config.trustedThumbprints`.
- **`SamlAssertionCompressor`** (`JC-Compress-SAML-Assertion`) — when
  `compressSaml` is true, zips the assertion (single `assertion.xml` entry)
  and base64-encodes the archive; otherwise just base64-encodes the raw XML.

Both were exercised against a real self-signed-cert-signed assertion (valid
signature, tampered assertion, correct/incorrect pinning, unsigned input) and
the compressor round-tripped through actual zip/base64 decode, during
development — see the shared flow's top-level README for the security
rationale behind pinning.

## Build

Requires JDK 11+ and network access to Google's Artifact Registry (the
`message-flow` / `expressions` SDK jars aren't on Maven Central):

```bash
cd java-callouts/isam-saml-callouts
mvn -B package
```

This compiles the two classes, packages `isam-saml-callouts.jar`, and copies
it into both `../../sharedflowbundle/resources/java/` and
`../../sharedflowbundle-json/resources/java/` (via the `maven-antrun-plugin`
step in `pom.xml`) so it's ready to deploy with either bundle.

If your build environment can't reach
`https://us-maven.pkg.dev/apigee-release/apigee-java-callout-dependencies`,
download `message-flow-1.0.0.jar` and `expressions-1.0.0.jar` another way and
install them into your local repo:

```bash
mvn install:install-file -Dfile=message-flow-1.0.0.jar \
  -DgroupId=com.apigee.gateway.libraries -DartifactId=message-flow -Dversion=1.0.0 -Dpackaging=jar
mvn install:install-file -Dfile=expressions-1.0.0.jar \
  -DgroupId=com.apigee.infra.libraries -DartifactId=expressions -Dversion=1.0.0 -Dpackaging=jar
```

## Class reference

### `com.example.isam.callout.SamlSignatureValidator`

Policy properties (both optional, shown with their JDK/class-level defaults —
both bundles set them explicitly rather than relying on the default, since
their variable names differ):

| Property | Default | WS-Trust bundle | JSON bundle | Meaning |
|---|---|---|---|---|
| `assertionVariable` | `isam.rstr.assertion.xml` | `isam.rstr.assertion.xml` | `isamjson.response.assertion.xml` | flow variable holding the `<saml:Assertion>` XML |
| `trustedThumbprintsVariable` | `isam.config.trustedThumbprints` | `isam.config.trustedThumbprints` | `isamjson.config.trustedThumbprints` | flow variable holding a comma-separated SHA-256 thumbprint allowlist (empty = no pinning) |

Output variables (same names in both bundles): `saml.signature.valid`,
`.error`, `.cert.subject`, `.cert.issuer`, `.cert.serial`, `.cert.expired`,
`.cert.thumbprint`, `.pinned`.

Also sets `saml.subject.id`, `saml.assertion.notBefore`, and
`saml.assertion.notOnOrAfter`, parsed from the same DOM this class already
builds to check the signature — regardless of how validation itself turns
out. These exist because the WS-Trust bundle originally extracted subject/
lifetime via XPath against the *outer* SOAP response, which only works when
the assertion is a real nested XML element there; some STS implementations
(confirmed for this repo's actual ISAM) instead embed it as XML-escaped text,
in which case there's no such element to point an XPath at. Since this
callout re-parses the (already-unescaped) assertion string into its own DOM
regardless, extracting these three fields here works in both cases.

### `com.example.isam.callout.SamlAssertionCompressor`

| Property | Default | WS-Trust bundle | JSON bundle | Meaning |
|---|---|---|---|---|
| `assertionVariable` | `isam.rstr.assertion.xml` | `isam.rstr.assertion.xml` | `isamjson.response.assertion.xml` | flow variable holding the assertion XML to compress |
| `compressFlagVariable` | `compressSaml` | `compressSaml` | `compressSaml` | flow variable (boolean/`"true"`/`"1"`/`"yes"`) gating compression |

Output variables (same names in both bundles): `saml.assertion.output`
(base64), `saml.assertion.compressed` (bool), `saml.assertion.compress.error`
(only on exception).
