# resources/java

The compiled `isam-saml-callouts.jar` (built from `java-callouts/isam-saml-callouts/`)
goes in this directory before the shared flow bundle is deployed. It's not checked
into git — build it with:

```bash
cd java-callouts/isam-saml-callouts
mvn -B package
```

The build's `maven-antrun-plugin` step copies `target/isam-saml-callouts.jar` here
automatically. See `java-callouts/isam-saml-callouts/README.md` for details and
`../../../README.md` ("Signature validation & trust") for what the callouts do.
