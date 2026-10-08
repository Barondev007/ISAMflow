package com.orders.signature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;

/**
 * Builds the digest and SignedInfo signing string for an enveloped XML
 * signature -- the SignedInfo bytes an external signing API needs to
 * RSA/ECDSA-sign to produce a &lt;ds:Signature&gt; to embed in the
 * document -- over the whole document (Reference URI=""). Replaces
 * JS-Build-XmlDsig-Signing-String (xmldsig-build-signing-string.js +
 * xml-exc-c14n.js): same three-step algorithm, same output flow
 * variables, but canonicalization now runs on a real org.w3c.dom tree
 * (parsed by the JDK's own DocumentBuilder, same as the sibling
 * XmlDsigVerifyCallout) via XmlC14n, instead of a hand-rolled JS
 * regex-based parser and renderer -- see XmlC14n's class comment for why
 * javax.xml.crypto.dsig (JSR 105) itself can't be reused for this half of
 * the problem, and for the processing-instruction bug this port fixes
 * along the way.
 *
 * 0) Resolve the target XML (signature.payload if the calling proxy
 *    staged one, else message.content) and immediately pin it back into
 *    signature.payload -- so JC-Assemble-XmlDsig-Signature, which
 *    resolves its own "document" Property the same way but runs later
 *    (after the external signing-API call in between), is guaranteed to
 *    embed the EXACT bytes this step hashed, not whatever message.content
 *    happens to hold by then. Closes a real failure mode: a calling
 *    proxy relying on the message.content fallback (never explicitly
 *    staging signature.payload) can end up with the two steps reading
 *    different content if anything mutates message.content in between --
 *    producing a signature that's internally consistent with neither the
 *    document it claims to cover nor this gateway's own verifier, while
 *    an externally-signed document (no such two-read gap) verifies fine.
 * 1) Canonicalize that same XML with Exclusive C14N and SHA-256 it -&gt;
 *    DigestValue.
 * 2) Build &lt;SignedInfo&gt; (CanonicalizationMethod = exc-c14n,
 *    SignatureMethod = signature.xmldsig.signatureMethod, one Reference
 *    with the enveloped-signature + exc-c14n Transforms, DigestMethod =
 *    sha256, and the DigestValue from step 1).
 * 3) Canonicalize &lt;SignedInfo&gt; itself -- this is the exact byte
 *    sequence an external signing API needs to RSA/ECDSA-sign to produce
 *    &lt;SignatureValue&gt;. base64-encoded into signature.xmldsig.signing.string.
 *
 * Only SHA-256 digest and Exclusive C14N (no comments, no
 * InclusiveNamespaces PrefixList) are actually implemented -- that's what
 * CanonicalizationMethod/DigestMethod are hardcoded to, the same fixed,
 * non-KVM-configurable security decision XmlDsigVerifyCallout documents
 * for its own allow-list. signatureMethod is the one genuinely
 * configurable piece, since it doesn't affect what this class computes --
 * it just labels what the external signing step is expected to do.
 *
 * Scope: this signs the whole document as-is (no pre-existing
 * &lt;Signature&gt;/&lt;ds:Signature&gt; is stripped before digesting) --
 * correct for generating a brand-new signature, not for re-signing an
 * already-signed document. Same scope as the script this replaces.
 *
 * Policy config (see JC-Build-XmlDsig-Signing-String.xml):
 *   &lt;Properties&gt;
 *     &lt;Property name="document"&gt;{signature.payload}&lt;/Property&gt;
 *     &lt;Property name="document-fallback"&gt;{message.content}&lt;/Property&gt;
 *     &lt;Property name="signature-method"&gt;{signature.xmldsig.signatureMethod}&lt;/Property&gt;
 *     &lt;Property name="default-signature-method"&gt;http://www.w3.org/2001/04/xmldsig-more#rsa-sha256&lt;/Property&gt;
 *     &lt;Property name="output-prefix"&gt;signature.xmldsig&lt;/Property&gt;
 *   &lt;/Properties&gt;
 *
 * "document"/"document-fallback"/"signature-method" are resolved as
 * flow-variable references the same way XmlDsigVerifyCallout resolves its
 * own config: a property value wrapped in "{...}" is looked up via
 * MessageContext.getVariable() at request time. "default-signature-method"
 * and "output-prefix" are always literal values, never refs.
 *
 * Sets &lt;output-prefix&gt;.signatureMethod (echoing back whichever
 * value -- configured or default -- was actually used, same as the JS
 * version setting signature.xmldsig.signatureMethod when it was empty),
 * &lt;output-prefix&gt;.digest.value, &lt;output-prefix&gt;.signedinfo.canonical,
 * and &lt;output-prefix&gt;.signing.string. This callout never raises the
 * fault itself on a bad/missing document -- the same
 * sets-a-flag/RaiseFault-checks-it pattern every other guard in this
 * bundle uses -- RF-JWT-Header-Config-Missing's sibling for this step
 * would check &lt;output-prefix&gt;.error, same shape as the validator
 * side's XmlDsigVerifyCallout.
 */
public class XmlDsigSignCallout implements Execution {

    private static final String DEFAULT_SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private final Map properties;

    public XmlDsigSignCallout(Map properties) {
        this.properties = properties;
    }

    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext execContext) {
        String outputPrefix = getLiteralProperty("output-prefix", "signature.xmldsig");
        try {
            String xml = resolveConfigValue(msgCtxt, "document");
            if (isBlank(xml)) {
                xml = resolveConfigValue(msgCtxt, "document-fallback");
            }
            if (isBlank(xml)) {
                return fail(msgCtxt, outputPrefix, "no document to sign (both 'document' and 'document-fallback' were empty)");
            }

            // Pin down exactly what gets hashed below, so
            // JC-Assemble-XmlDsig-Signature -- which runs later, after
            // the external signing-API call, and resolves ITS OWN
            // "document" Property the same way ({signature.payload},
            // falling back to {message.content}) -- is guaranteed to
            // read the SAME bytes, not whatever message.content happens
            // to hold by the time it runs. Without this, a calling proxy
            // that relies on the message.content fallback (rather than
            // explicitly staging signature.payload itself) risks the two
            // steps disagreeing if anything mutates message.content in
            // between -- e.g. another policy reformatting the body, or
            // Apigee's own internal handling of it -- which produces
            // exactly "signs fine, then fails its own verification"
            // (confirmed as the actual root cause of a real report: the
            // same proxy's own signature failed its own verification
            // while an externally-signed document, with no such
            // two-read gap, verified correctly). Writing this is a
            // harmless no-op when the calling proxy already set
            // signature.payload explicitly -- same value either way.
            msgCtxt.setVariable("signature.payload", xml);

            String signatureMethod = resolveConfigValue(msgCtxt, "signature-method");
            if (isBlank(signatureMethod)) {
                String defaultMethod = getLiteralProperty("default-signature-method", DEFAULT_SIGNATURE_METHOD);
                signatureMethod = defaultMethod;
            }
            msgCtxt.setVariable(outputPrefix + ".signatureMethod", signatureMethod);

            Document targetDoc;
            try {
                targetDoc = parseSecurely(xml);
            } catch (Exception parseError) {
                return fail(msgCtxt, outputPrefix, "document is not well-formed XML; cannot build an XML signature over it: " + parseError.getMessage());
            }

            String canonicalTarget = XmlC14n.canonicalize(targetDoc.getDocumentElement());
            String digestValue = base64(sha256(canonicalTarget));
            msgCtxt.setVariable(outputPrefix + ".digest.value", digestValue);

            String signedInfoXml =
                    "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
                    "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "<SignatureMethod Algorithm=\"" + escapeXmlAttr(signatureMethod) + "\"/>" +
                    "<Reference URI=\"\">" +
                    "<Transforms>" +
                    "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" +
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
                    "</Transforms>" +
                    "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>" +
                    "<DigestValue>" + digestValue + "</DigestValue>" +
                    "</Reference>" +
                    "</SignedInfo>";

            Document signedInfoDoc = parseSecurely(signedInfoXml);
            String canonicalSignedInfo = XmlC14n.canonicalize(signedInfoDoc.getDocumentElement());
            msgCtxt.setVariable(outputPrefix + ".signedinfo.canonical", canonicalSignedInfo);
            msgCtxt.setVariable(outputPrefix + ".signing.string", base64(canonicalSignedInfo.getBytes(StandardCharsets.UTF_8)));

            return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);

        } catch (Exception e) {
            return fail(msgCtxt, outputPrefix, e.toString());
        }
    }

    private Document parseSecurely(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setCoalescing(true);
        // XXE / entity-expansion hardening -- same as XmlDsigVerifyCallout;
        // the target document comes from the request, not a trusted source
        // (the synthetic SignedInfo XML built above is trusted, but parsing
        // it the same hardened way costs nothing and keeps one code path).
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }

    private byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    private String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private String escapeXmlAttr(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;");
    }

    private ExecutionResult fail(MessageContext msgCtxt, String outputPrefix, String message) {
        msgCtxt.setVariable(outputPrefix + ".error", message);
        return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);
    }

    /**
     * "{flow.var.name}" -&gt; the value of that flow variable (null if
     * unset); anything else is returned as a literal. Same resolution
     * rule XmlDsigVerifyCallout uses.
     */
    private String resolveConfigValue(MessageContext msgCtxt, String propertyName) {
        String raw = (String) properties.get(propertyName);
        if (raw == null) {
            return null;
        }
        raw = raw.trim();
        if (raw.length() > 2 && raw.startsWith("{") && raw.endsWith("}")) {
            Object value = msgCtxt.getVariable(raw.substring(1, raw.length() - 1));
            return (value == null) ? null : value.toString();
        }
        return raw;
    }

    private String getLiteralProperty(String propertyName, String defaultValue) {
        String raw = (String) properties.get(propertyName);
        if (raw == null || raw.trim().isEmpty()) {
            return defaultValue;
        }
        return raw.trim();
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}
