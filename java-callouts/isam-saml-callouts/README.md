# isam-saml-callouts

Two Apigee Java callouts used by the `ISAM-WSTrust-TokenExchange` shared flow.
Apigee has no native policy for XML-DSig signature verification or zip
compression, so both are implemented here using JDK standard-library APIs only
(`javax.xml.crypto.dsig`, `java.util.zip`) — no third-party dependency beyond
Apigee's own callout SDK.

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
it into `../../sharedflowbundle/resources/java/` (via the `maven-antrun-plugin`
step in `pom.xml`) so it's ready to deploy with the bundle.

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

Policy properties (both optional, shown with their defaults):

| Property | Default | Meaning |
|---|---|---|
| `assertionVariable` | `isam.rstr.assertion.xml` | flow variable holding the `<saml:Assertion>` XML |
| `trustedThumbprintsVariable` | `isam.config.trustedThumbprints` | flow variable holding a comma-separated SHA-256 thumbprint allowlist (empty = no pinning) |

Output variables: `saml.signature.valid`, `.error`, `.cert.subject`,
`.cert.issuer`, `.cert.serial`, `.cert.expired`, `.cert.thumbprint`, `.pinned`.

### `com.example.isam.callout.SamlAssertionCompressor`

| Property | Default | Meaning |
|---|---|---|
| `assertionVariable` | `isam.rstr.assertion.xml` | flow variable holding the assertion XML to compress |
| `compressFlagVariable` | `compressSaml` | flow variable (boolean/`"true"`/`"1"`/`"yes"`) gating compression |

Output variables: `saml.assertion.output` (base64), `saml.assertion.compressed`
(bool), `saml.assertion.compress.error` (only on exception).
