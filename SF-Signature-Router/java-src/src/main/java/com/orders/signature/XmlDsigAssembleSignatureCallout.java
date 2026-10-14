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
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

/**
 * Assembles the final enveloped &lt;Signature&gt; -- SignedInfo +
 * SignatureValue + KeyInfo -- and inserts it as the last child of the
 * target document's root element, so the resulting document can be
 * validated by ANY compliant XML-DSig verifier using nothing but the
 * document itself: no out-of-band key distribution, no prior knowledge of
 * this gateway's KVM config. KeyInfo carries the signer's key two ways,
 * both derived from the same KVM-configured certificate so they can never
 * disagree with each other: &lt;KeyValue&gt;&lt;RSAKeyValue&gt; (the raw
 * modulus/exponent, for verifiers that read the key directly, no
 * certificate parsing needed -- RSA only, see the Java class comment
 * below) and &lt;X509Data&gt;&lt;X509Certificate&gt; (the full
 * certificate, for verifiers that want to check the cert itself, e.g.
 * its chain or validity window). Runs after
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
 * independent C implementation, unrelated to the JDK), validated once
 * using only the public key extracted from the embedded certificate and
 * once using only the embedded &lt;RSAKeyValue&gt; (ignoring the
 * certificate entirely) -- all passed, with the Modulus/Exponent bytes
 * cross-checked against openssl's own reading of the same certificate; a
 * tampered copy of the same document was correctly rejected.
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

            Certificate certificate;
            byte[] certDer = null;
            try {
                certDer = certificateDer(certificatePem);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                certificate = cf.generateCertificate(new ByteArrayInputStream(certDer));
            } catch (Exception certError) {
                // Deliberately verbose but still safe to log/return: length,
                // a short prefix/suffix (not the sensitive middle, and not
                // sensitive by itself -- most certs share a common prefix
                // shape), and whether base64-decoding itself succeeded
                // (and to how many DER bytes) BEFORE CertificateFactory
                // ever saw it. Added because "not a valid X.509
                // certificate" alone wasn't enough to tell two reportedly
                // byte-identical inputs (one wrapped in a PEM header with
                // line breaks, one not) apart -- this surfaces whatever
                // the actual difference is without requiring the
                // certificate's real content to be pasted anywhere.
                String detail = certError.getMessage();
                Throwable cause = certError.getCause();
                if (cause != null && cause.getMessage() != null && !cause.getMessage().equals(detail)) {
                    detail = detail + " (caused by: " + cause.getMessage() + ")";
                }
                return fail(msgCtxt, outputPrefix, "certificate-pem is not a valid X.509 certificate: " + detail
                        + " [diagnostic: input length=" + certificatePem.length()
                        + ", prefix=" + safeEdge(certificatePem, true)
                        + ", suffix=" + safeEdge(certificatePem, false)
                        + ", base64-decoded bytes=" + (certDer == null ? "decode itself failed" : String.valueOf(certDer.length))
                        + "]");
            }
            String certificateBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());

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

            // <KeyValue><RSAKeyValue> gives a verifier the raw key
            // directly, with no certificate parsing needed -- some
            // tooling expects it alongside (or instead of) X509Data. Only
            // emitted for RSA keys: XML-DSig 1.0 (the namespace this
            // bundle uses throughout) defines RSAKeyValue and
            // DSAKeyValue, but no EC representation -- ECKeyValue is a
            // 1.1 addition this project doesn't otherwise use. An EC
            // signing certificate still works fine; it just won't get a
            // KeyValue block, only X509Data, which remains fully
            // sufficient on its own.
            PublicKey publicKey = certificate.getPublicKey();
            if (publicKey instanceof RSAPublicKey) {
                RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                Element keyValueEl = targetDoc.createElementNS(DSIG_NS, "KeyValue");
                Element rsaKeyValueEl = targetDoc.createElementNS(DSIG_NS, "RSAKeyValue");
                Element modulusEl = targetDoc.createElementNS(DSIG_NS, "Modulus");
                modulusEl.setTextContent(base64Unsigned(rsaPublicKey.getModulus()));
                Element exponentEl = targetDoc.createElementNS(DSIG_NS, "Exponent");
                exponentEl.setTextContent(base64Unsigned(rsaPublicKey.getPublicExponent()));
                rsaKeyValueEl.appendChild(modulusEl);
                rsaKeyValueEl.appendChild(exponentEl);
                keyValueEl.appendChild(rsaKeyValueEl);
                keyInfoEl.appendChild(keyValueEl);
            }

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
     * certificate-pem in KVM has been seen in several shapes: a properly
     * formatted PEM (-----BEGIN CERTIFICATE-----, base64 body wrapped
     * across lines, -----END CERTIFICATE-----), the raw base64 body
     * alone with no header/footer and no line breaks at all, and (the
     * case that kept failing even after header/CRLF handling was added)
     * a single base64 string using the URL-safe alphabet (RFC 4648 '-'
     * and '_' in place of '+' and '/') instead of standard base64 --
     * something external signing/KMS-style APIs commonly hand back,
     * since the same project already pipes other base64 values to and
     * from an external signing API. That case doesn't fail loudly: '-'
     * and '_' are simply outside the standard alphabet, so a strict
     * decoder either throws on them or (with a lenient decoder) silently
     * skips them, corrupting the decoded bytes and surfacing as
     * CertificateFactory's generic "not a valid X.509 certificate" --
     * indistinguishable, from the error message alone, from an actually
     * malformed certificate.
     *
     * Handles every shape above the same way: strip whatever header/
     * footer is present, un-escape literal "\n"/"\r\n"/"\r" sequences
     * (the same ones a raw-JSON-string KVM value can carry), translate
     * '-'/'_' to the standard '+'/'/' alphabet (a no-op when the input
     * was already standard base64 -- neither character ever appears in
     * standard base64 output), and base64-decode what's left straight to
     * DER bytes via the MIME decoder, which -- unlike Base64.getDecoder()
     * -- ignores any remaining character outside the base64 alphabet
     * (stray whitespace, quotes left over from JSON extraction, etc.)
     * instead of throwing on it, and tolerates missing padding. The
     * result feeds CertificateFactory directly, sidestepping its own PEM
     * parser (and whatever line-length/CRLF assumptions that parser
     * makes) entirely.
     */
    private byte[] certificateDer(String pem) {
        String unescaped = pem.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n");
        String body = unescaped
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace('-', '+')
                .replace('_', '/');
        return Base64.getMimeDecoder().decode(body);
    }

    /**
     * First or last 12 characters of s, for safe inclusion in a
     * diagnostic error message -- enough to spot a stray leading/trailing
     * quote character, a BOM, unexpected whitespace, or truncation
     * without exposing the sensitive middle (the actual modulus-bearing
     * content) of the certificate.
     */
    private String safeEdge(String s, boolean leading) {
        int n = Math.min(12, s.length());
        return leading ? s.substring(0, n) : s.substring(s.length() - n);
    }

    /**
     * ds:CryptoBinary (what Modulus/Exponent hold) is an UNSIGNED
     * big-endian integer, but BigInteger.toByteArray() is two's-complement
     * and prepends a 0x00 sign byte whenever the value's high bit would
     * otherwise read as negative. RSA moduli/exponents are always
     * positive, so that leading byte -- when present -- is purely a
     * sign-disambiguation artifact, not part of the value itself, and
     * must be stripped or the encoded value is off by one leading zero
     * byte from what every XML-DSig implementation expects (the same
     * gotcha JWK n/e encoding has). Cross-checked against openssl's own
     * reading of a real certificate's modulus before relying on this.
     */
    private String base64Unsigned(BigInteger n) {
        byte[] bytes = n.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getEncoder().encodeToString(bytes);
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
