# resources/java

The compiled `isam-saml-callouts.jar` goes here before this bundle is
deployed. It's the exact same jar as `sharedflowbundle/resources/java/`
(built from `java-callouts/isam-saml-callouts/`) — not checked into git.
Build it with:

```bash
cd java-callouts/isam-saml-callouts
mvn -B package
```

The build's `maven-antrun-plugin` step copies the jar here (and into
`sharedflowbundle/resources/java/`) automatically.
