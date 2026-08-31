# resources/java

The compiled `isam-saml-callouts.jar` goes here before this bundle is
deployed. Not checked into git. Build it with:

```bash
cd java-callouts/isam-saml-callouts
mvn -B package
```

The build's `maven-antrun-plugin` step copies the jar here (and into
`ISAM-Common-ValidateSignature`'s own `resources/java/`) automatically.
