# isam-saml-callouts

Two Apigee Java callouts, each used by exactly one common shared flow:
`SamlSignatureValidator` by `ISAM-Common-ValidateSignature`,
`SamlAssertionCompressor` by `ISAM-Common-CompressAssertion`. Both of those
common flows are in turn called via `FlowCallout` by every SAML-bearing
type-specific flow (types 1-5) — so this one jar backs all of them, and
none of the six type-specific bundles reference it directly. Apigee has no
native policy for XML-DSig signature verification or zip compression, so
both are implemented here using JDK standard-library APIs only
(`javax.xml.crypto.dsig`, `java.util.zip`) — no third-party dependency
beyond Apigee's own callout SDK.

- **`SamlSignatureValidator`** (`JC-Validate-SAML-Signature`) — verifies the
  `ds:Signature` wrapped around the SAML assertion using the X.509 certificate
  embedded in the signature's own `ds:KeyInfo`, with optional SHA-256
  thumbprint pinning against `saml.trustedThumbprints`.
- **`SamlAssertionCompressor`** (`JC-Compress-SAML-Assertion`) — when
  `compressSaml` is true, zips the assertion (single `assertion.xml` entry)
  and base64-encodes the archive; otherwise just base64-encodes the raw XML.

Both were exercised against a real self-signed-cert-signed assertion (valid
signature, tampered assertion, correct/incorrect pinning, unsigned input,
correct subject/lifetime extraction) and the compressor round-tripped
through actual zip/base64 decode, during development — see the top-level
README for the security rationale behind pinning.

## Build

Requires JDK 11+ and network access to Google's Artifact Registry (the
`message-flow` / `expressions` SDK jars aren't on Maven Central):

```bash
cd java-callouts/isam-saml-callouts
mvn -B package
```

This compiles the two classes, packages `isam-saml-callouts.jar`, and copies
it into both `../../common/ISAM-Common-ValidateSignature/sharedflowbundle/resources/java/`
and `../../common/ISAM-Common-CompressAssertion/sharedflowbundle/resources/java/`
(via the `maven-antrun-plugin` step in `pom.xml`) so it's ready to deploy
with either common bundle.

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

Both classes take their input/output variable names from policy
`Properties` rather than hardcoding them — this is what let the common/type
split happen without touching the Java code at all. Both common bundles
that use these classes set the properties to the same canonical names
(`saml.assertion.xml`, `saml.trustedThumbprints`, `compressSaml`), since
every type-specific flow coalesces its own response shape into those same
names before calling in.

### `com.example.isam.callout.SamlSignatureValidator`

Policy properties (both optional, shown with their defaults — the same
values `ISAM-Common-ValidateSignature` sets explicitly):

| Property | Default | Meaning |
|---|---|---|
| `assertionVariable` | `saml.assertion.xml` | flow variable holding the `saml:Assertion` XML |
| `trustedThumbprintsVariable` | `saml.trustedThumbprints` | flow variable holding a comma-separated SHA-256 thumbprint allowlist (empty = no pinning) |

Output variables: `saml.signature.valid`, `.error`, `.cert.subject`,
`.cert.issuer`, `.cert.serial`, `.cert.expired`, `.cert.thumbprint`,
`.pinned`.

Also sets `saml.subject.id`, `saml.assertion.notBefore`, and
`saml.assertion.notOnOrAfter`, parsed from the same DOM this class already
builds to check the signature, regardless of how validation itself turns
out. These exist because a naive design would extract subject/lifetime via
XPath against the *outer* ISAM response, which only works when the
assertion is a real nested XML element there; some STS implementations
(confirmed for the WS-Trust types in this repo) instead embed it as
XML-escaped text, in which case there's no such element to point an XPath
at. Since this callout re-parses the assertion string into its own DOM
regardless, extracting these three fields here works either way.

### `com.example.isam.callout.SamlAssertionCompressor`

| Property | Default | Meaning |
|---|---|---|
| `assertionVariable` | `saml.assertion.xml` | flow variable holding the assertion XML to compress |
| `compressFlagVariable` | `compressSaml` | flow variable (boolean/`"true"`/`"1"`/`"yes"`) gating compression |

Output variables: `saml.assertion.output` (base64), `saml.assertion.compressed`
(bool), `saml.assertion.compress.error` (only on exception).
