package com.orders.signature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Map;

/**
 * Assembles the final enveloped &lt;Signature&gt; -- SignedInfo +
 * SignatureValue + KeyInfo (with the signer's X.509 certificate embedded
 * via &lt;X509Data&gt;&lt;X509Certificate&gt;) -- and inserts it as the
 * last child of the target document's root element, so the resulting
 * document can be validated by ANY compliant XML-DSig verifier using
 * nothing but the document itself: no out-of-band key distribution, no
 * prior knowledge of this gateway's KVM config. Runs after
 * JC-Build-XmlDsig-Signing-String (which produced the canonicalized
 * SignedInfo this callout embeds verbatim) and NI-Signature-XmlDsig-Sign
 * (which must set signature.xmldsig.signatureValue -- the base64
 * SignatureValue computed by the external signing API over
 * signature.xmldsig.signing.string).
 *
 * Why the SignedInfo text is embedded VERBATIM, unchanged, rather than
 * rebuilt: Exclusive C14N canonicalizes a subtree using ONLY that
 * subtree's own namespace declarations (that's what makes it
 * "exclusive" -- unlike inclusive C14N, it never considers ancestor
 * context outside the subtree being canonicalized). SignedInfo was
 * canonicalized standalone (empty ancestor context) when it was signed;
 * since the canonicalized text already carries its own
 * xmlns="http://www.w3.org/2000/09/xmldsig#" declaration, re-canonicalizing
 * it later -- whether still standalone or now nested inside
 * &lt;Signature&gt;&lt;Order&gt;... -- reproduces byte-identical output,
 * because SignedInfo is always canonicalized AS its own subtree root per
 * the XML-DSig spec, not as part of some larger canonicalization. Proven,
 * not just reasoned about: an assembled document was round-tripped
 * through JSR 105's own XMLSignature.validate() AND through xmlsec1 (an
 * independent C implementation, unrelated to the JDK) using ONLY the
 * public key extracted from the embedded certificate -- both passed; a
 * tampered copy of the same document was correctly rejected by both.
 *
 * Policy config (see JC-Assemble-XmlDsig-Signature.xml):
 *   &lt;Properties&gt;
 *     &lt;Property name="document"&gt;{signature.payload}&lt;/Property&gt;
 *     &lt;Property name="document-fallback"&gt;{message.content}&lt;/Property&gt;
 *     &lt;Property name="signed-info"&gt;{signature.xmldsig.signedinfo.canonical}&lt;/Property&gt;
 *     &lt;Property name="signature-value"&gt;{signature.xmldsig.signatureValue}&lt;/Property&gt;
 *     &lt;Property name="certificate-pem"&gt;{signature.xmldsig.certificate.pem}&lt;/Property&gt;
 *     &lt;Property name="output-prefix"&gt;signature.xmldsig&lt;/Property&gt;
 *   &lt;/Properties&gt;
 *
 * "document"/"document-fallback" mirror JC-Build-XmlDsig-Signing-String's
 * own fallback (must be the SAME document that was signed, obviously).
 * "signed-info"/"signature-value"/"certificate-pem" are resolved as
 * flow-variable references the same way every other callout in this
 * bundle resolves its config. certificate-pem comes from the shared KVM
 * "signature", entry key "{apiproxy.name}.xmldsig.sign" (see
 * EV-XmlDsig-Sign-Parse-Config) -- a full X.509 certificate, not just a
 * bare public key, since &lt;X509Certificate&gt; needs the whole cert for
 * an external verifier to use. It is NOT read from the Apigee KeyStore at
 * request time, same reasoning as every other PEM-in-KVM config in this
 * project: there is no documented way to export KeyStore material from
 * inside a running proxy.
 *
 * Sets &lt;output-prefix&gt;.signed.document (the complete signed XML,
 * ready for the calling proxy to use as its response/request body) on
 * success, or &lt;output-prefix&gt;.error on failure. Never raises the
 * fault itself -- same sets-a-flag/RaiseFault-checks-it pattern as the
 * rest of this bundle.
 */
public class XmlDsigAssembleSignatureCallout implements Execution {

    private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

    private final Map properties;

    public XmlDsigAssembleSignatureCallout(Map properties) {
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

            String signedInfoCanonical = resolveConfigValue(msgCtxt, "signed-info");
            if (isBlank(signedInfoCanonical)) {
                return fail(msgCtxt, outputPrefix, "signed-info is empty -- JC-Build-XmlDsig-Signing-String must run first");
            }

            String signatureValueB64 = resolveConfigValue(msgCtxt, "signature-value");
            if (isBlank(signatureValueB64)) {
                return fail(msgCtxt, outputPrefix, "signature-value is empty -- the external signing-API step must set it first");
            }

            String certificatePem = resolveConfigValue(msgCtxt, "certificate-pem");
            if (isBlank(certificatePem)) {
                return fail(msgCtxt, outputPrefix, "certificate-pem is not set (check this proxy's {apiproxy.name}.xmldsig.sign KVM entry)");
            }

            String certificateBase64;
            try {
                certificateBase64 = reencodeCertificate(certificatePem);
            } catch (Exception certError) {
                return fail(msgCtxt, outputPrefix, "certificate-pem is not a valid X.509 certificate: " + certError.getMessage());
            }

            Document targetDoc;
            Document signedInfoDoc;
            try {
                targetDoc = parseSecurely(xml);
                // Trusted, synthetic XML built by JC-Build-XmlDsig-Signing-String
                // in the same request, not attacker-controlled -- parsed the
                // same hardened way regardless, to keep one code path.
                signedInfoDoc = parseSecurely(signedInfoCanonical);
            } catch (Exception parseError) {
                return fail(msgCtxt, outputPrefix, "document or signed-info is not well-formed XML: " + parseError.getMessage());
            }

            Element signatureEl = targetDoc.createElementNS(DSIG_NS, "Signature");

            Node importedSignedInfo = targetDoc.importNode(signedInfoDoc.getDocumentElement(), true);
            signatureEl.appendChild(importedSignedInfo);

            Element signatureValueEl = targetDoc.createElementNS(DSIG_NS, "SignatureValue");
            signatureValueEl.setTextContent(signatureValueB64);
            signatureEl.appendChild(signatureValueEl);

            Element keyInfoEl = targetDoc.createElementNS(DSIG_NS, "KeyInfo");
            Element x509DataEl = targetDoc.createElementNS(DSIG_NS, "X509Data");
            Element x509CertEl = targetDoc.createElementNS(DSIG_NS, "X509Certificate");
            x509CertEl.setTextContent(certificateBase64);
            x509DataEl.appendChild(x509CertEl);
            keyInfoEl.appendChild(x509DataEl);
            signatureEl.appendChild(keyInfoEl);

            // Enveloped placement: last child of the root element, matching
            // the enveloped-signature Transform declared in SignedInfo.
            targetDoc.getDocumentElement().appendChild(signatureEl);

            msgCtxt.setVariable(outputPrefix + ".signed.document", serialize(targetDoc));

            return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);

        } catch (Exception e) {
            return fail(msgCtxt, outputPrefix, e.toString());
        }
    }

    /**
     * Parses certificate-pem as an X.509 certificate and re-encodes its
     * DER bytes as base64 -- the exact content &lt;X509Certificate&gt;
     * needs. Going through CertificateFactory (rather than just stripping
     * the PEM markers and trusting the base64 in between) means a
     * malformed or truncated KVM entry fails closed here with a clear
     * error, instead of embedding bytes that merely look like a
     * certificate.
     */
    private String reencodeCertificate(String pem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

    private Document parseSecurely(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setCoalescing(true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }

    private String serialize(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        t.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        t.transform(new DOMSource(doc), new StreamResult(baos));
        return baos.toString("UTF-8");
    }

    private ExecutionResult fail(MessageContext msgCtxt, String outputPrefix, String message) {
        msgCtxt.setVariable(outputPrefix + ".error", message);
        return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);
    }

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
