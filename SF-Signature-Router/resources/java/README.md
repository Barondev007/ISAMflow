Build `xmldsig-sign-callout.jar` from `../../java-src` (see
`java-src/README.md`) and place it here as `xmldsig-sign-callout.jar`
before deploying this shared flow bundle — it can't be built in this
environment (no Apigee SDK jars available here), so this directory is a
placeholder until you build and drop it in.

One jar, two classes: `JC-Build-XmlDsig-Signing-String.xml` and
`JC-Assemble-XmlDsig-Signature.xml` both reference it via:

```
<ResourceURL>java://xmldsig-sign-callout.jar</ResourceURL>
```
