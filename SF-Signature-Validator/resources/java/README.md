Build `xmldsig-verify-callout.jar` from `../../java-src` (see
`java-src/README.md`) and place it here as `xmldsig-verify-callout.jar`
before deploying this shared flow bundle — it can't be built in this
environment (no Apigee SDK jars available here), so this directory is a
placeholder until you build and drop it in.

`JC-XmlDsig-Verify-Signature.xml` references it via:

```
<ResourceURL>java://xmldsig-verify-callout.jar</ResourceURL>
```
