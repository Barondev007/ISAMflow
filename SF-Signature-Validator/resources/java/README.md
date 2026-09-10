Build `signature-keystore-callout.jar` from `../../java-src` (see
`java-src/README.md`) and place it here as `signature-keystore-callout.jar`
before deploying this shared flow bundle — it can't be built in this
environment (no Apigee SDK jars available here), so this directory is a
placeholder until you build and drop it in.

`JC-JWT-Verify-Extract-Public-Key.xml` references it via:

```
<ResourceURL>java://signature-keystore-callout.jar</ResourceURL>
```
