package com.orders.signature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Verifies an enveloped XML Signature end to end -- canonicalization,
 * digest, and the SignatureValue cryptographic check -- in one policy,
 * using the JDK's built-in JSR 105 implementation (javax.xml.crypto.dsig,
 * part of the standard Java platform since Java 6, in the java.xml.crypto
 * module; no extra library beyond the Apigee SDK). This replaces both
 * JS-Verify-XmlDsig-Digest (which only checked the digest against the
 * document's own claimed value -- proving content integrity but nothing
 * about authenticity) and the NI-XmlDsig-Verify-Signature placeholder:
 * neither JavaScript nor any native Apigee policy can perform RSA/ECDSA
 * math, so this piece has to be compiled Java, and once it is, doing
 * canonicalization + digest + signature-value checking together in one
 * conformant implementation is strictly better than keeping a hand-rolled
 * JS canonicalizer in the loop alongside it -- one less place a subtle
 * mismatch between two independent implementations could hide.
 *
 * Fixed (NOT KVM-configurable) security decisions, deliberately baked
 * into this compiled class rather than left to runtime config -- the
 * same "pin it in reviewed code, don't let config pick it" reasoning
 * VerifyJWS-Jwt-Compact.xml documents for its own Algorithm parameter:
 *   - CanonicalizationMethod must be Exclusive C14N (no comments).
 *   - SignatureMethod must be RSA-SHA256 or ECDSA-SHA256.
 *   - Exactly one &lt;Signature&gt; element in the document.
 *   - Exactly one &lt;Reference&gt;, URI="" (the whole document), with
 *     DigestMethod SHA-256 and EXACTLY the two Transforms
 *     [enveloped-signature, exclusive-c14n] in that order -- no XSLT
 *     transform, no extra transform, no reference to a sub-element by ID.
 * A looser check here is a real, well-known class of XML Signature
 * "wrapping" vulnerability: a maliciously crafted document can be built
 * so that *a* Reference validates against *some* element while the
 * content that actually matters has been altered or was never covered by
 * the signature at all. Anything outside this exact shape fails closed
 * -- this class never trusts whatever algorithm/structure the document
 * itself happens to declare.
 *
 * Policy config (see JC-XmlDsig-Verify-Signature.xml):
 *   &lt;Properties&gt;
 *     &lt;Property name="document"&gt;{signature.verify.payload}&lt;/Property&gt;
 *     &lt;Property name="document-fallback"&gt;{message.content}&lt;/Property&gt;
 *     &lt;Property name="public-key-pem"&gt;{signature.verify.xmldsig.publicKey.pem}&lt;/Property&gt;
 *     &lt;Property name="key-algorithm"&gt;{signature.verify.xmldsig.keyAlgorithm}&lt;/Property&gt;
 *     &lt;Property name="output-prefix"&gt;signature.verify.xmldsig&lt;/Property&gt;
 *   &lt;/Properties&gt;
 *
 * "document"/"document-fallback"/"public-key-pem"/"key-algorithm" are
 * resolved as flow-variable references the same way
 * PublicKeyFromKeystoreCallout (the earlier, now-removed JWT KeyStore
 * callout) resolved its config: a property value wrapped in "{...}" is
 * looked up via MessageContext.getVariable() at request time, since this
 * class is instantiated once at policy load and reused across requests.
 * "output-prefix" is always a literal flow-variable name PREFIX, never a
 * ref.
 *
 * Sets &lt;output-prefix&gt;.valid ("true"/"false") and, when not valid,
 * &lt;output-prefix&gt;.error with a human-readable reason, plus (only when
 * the core validation itself failed, to help diagnose WHICH part failed)
 * &lt;output-prefix&gt;.signatureValueValid and
 * &lt;output-prefix&gt;.reference0Valid. This callout never raises the fault
 * itself -- the shared flow's RF-XmlDsig-Verify-Failed step does that,
 * gated on &lt;output-prefix&gt;.valid != "true", the same
 * JS/Java-sets-a-flag / RaiseFault-checks-it pattern every other guard in
 * this bundle uses.
 */
public class XmlDsigVerifyCallout implements Execution {

    private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SIG_ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    private static final String TRANSFORM_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    private final Map properties;

    public XmlDsigVerifyCallout(Map properties) {
        this.properties = properties;
    }

    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext execContext) {
        String outputPrefix = getLiteralProperty("output-prefix", "signature.verify.xmldsig");
        try {
            String xml = resolveConfigValue(msgCtxt, "document");
            if (isBlank(xml)) {
                xml = resolveConfigValue(msgCtxt, "document-fallback");
            }
            if (isBlank(xml)) {
                return fail(msgCtxt, outputPrefix, "no document to verify (both 'document' and 'document-fallback' were empty)");
            }

            String publicKeyPem = resolveConfigValue(msgCtxt, "public-key-pem");
            if (isBlank(publicKeyPem)) {
                return fail(msgCtxt, outputPrefix, "public-key-pem is not set (check this proxy's {apiproxy.name}.xmldsig.verify KVM entry)");
            }
            String keyAlgorithm = resolveConfigValue(msgCtxt, "key-algorithm");
            if (isBlank(keyAlgorithm)) {
                keyAlgorithm = "RSA";
            }

            Document doc;
            try {
                doc = parseSecurely(xml);
            } catch (Exception parseError) {
                return fail(msgCtxt, outputPrefix, "document is not well-formed XML: " + parseError.getMessage());
            }

            NodeList sigNodes = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
            if (sigNodes.getLength() == 0) {
                return fail(msgCtxt, outputPrefix, "no <Signature> element found in the document");
            }
            if (sigNodes.getLength() > 1) {
                return fail(msgCtxt, outputPrefix, "more than one <Signature> element found -- refusing to guess which one to verify");
            }
            Element sigElement = (Element) sigNodes.item(0);

            PublicKey publicKey;
            try {
                publicKey = decodePublicKey(publicKeyPem, keyAlgorithm);
            } catch (Exception keyError) {
                return fail(msgCtxt, outputPrefix, "could not decode public-key-pem as a " + keyAlgorithm + " key: " + keyError.getMessage());
            }

            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext validateContext = new DOMValidateContext(publicKey, sigElement);
            XMLSignature signature = factory.unmarshalXMLSignature(validateContext);

            String shapeError = checkExpectedShape(signature);
            if (shapeError != null) {
                return fail(msgCtxt, outputPrefix, shapeError);
            }

            boolean coreValid = signature.validate(validateContext);
            msgCtxt.setVariable(outputPrefix + ".valid", coreValid ? "true" : "false");

            if (!coreValid) {
                boolean sigValueValid = signature.getSignatureValue().validate(validateContext);
                msgCtxt.setVariable(outputPrefix + ".signatureValueValid", sigValueValid ? "true" : "false");

                List refs = signature.getSignedInfo().getReferences();
                for (int i = 0; i < refs.size(); i++) {
                    Reference ref = (Reference) refs.get(i);
                    boolean refValid = ref.validate(validateContext);
                    msgCtxt.setVariable(outputPrefix + ".reference" + i + "Valid", refValid ? "true" : "false");
                }

                msgCtxt.setVariable(outputPrefix + ".error", sigValueValid
                        ? "signature value is valid but a reference digest did not match -- content was altered after signing, or is malformed"
                        : "signature value does not validate against the configured public key");
            }

            return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);

        } catch (Exception e) {
            return fail(msgCtxt, outputPrefix, e.toString());
        }
    }

    /**
     * Enforces the fixed algorithm/shape allow-list documented in the
     * class comment. Returns null if the signature matches it, or a
     * human-readable reason if not -- checked BEFORE calling validate(),
     * so an out-of-policy document is rejected on structure alone, never
     * on trusting whatever it declares about itself.
     */
    private String checkExpectedShape(XMLSignature signature) {
        String canonAlg = signature.getSignedInfo().getCanonicalizationMethod().getAlgorithm();
        if (!C14N_EXCLUSIVE.equals(canonAlg)) {
            return "unsupported CanonicalizationMethod: " + canonAlg;
        }
        String sigAlg = signature.getSignedInfo().getSignatureMethod().getAlgorithm();
        if (!SIG_RSA_SHA256.equals(sigAlg) && !SIG_ECDSA_SHA256.equals(sigAlg)) {
            return "unsupported SignatureMethod: " + sigAlg;
        }
        List refs = signature.getSignedInfo().getReferences();
        if (refs.size() != 1) {
            return "expected exactly one <Reference>, found " + refs.size();
        }
        Reference ref = (Reference) refs.get(0);
        String uri = ref.getURI();
        if (uri != null && uri.length() > 0) {
            return "expected Reference URI=\"\" (the whole document), found \"" + uri + "\"";
        }
        if (ref.getDigestMethod() == null || !DIGEST_SHA256.equals(ref.getDigestMethod().getAlgorithm())) {
            return "unsupported or missing DigestMethod on the Reference";
        }
        List transforms = ref.getTransforms();
        if (transforms.size() != 2
                || !TRANSFORM_ENVELOPED.equals(((Transform) transforms.get(0)).getAlgorithm())
                || !C14N_EXCLUSIVE.equals(((Transform) transforms.get(1)).getAlgorithm())) {
            return "expected exactly [enveloped-signature, exclusive-c14n] Transforms on the Reference, in that order";
        }
        return null;
    }

    private Document parseSecurely(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // XXE / entity-expansion hardening -- this document comes from the
        // request, not a trusted source.
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }

    private PublicKey decodePublicKey(String pem, String keyAlgorithm) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance(keyAlgorithm);
        return kf.generatePublic(spec);
    }

    private ExecutionResult fail(MessageContext msgCtxt, String outputPrefix, String message) {
        msgCtxt.setVariable(outputPrefix + ".valid", "false");
        msgCtxt.setVariable(outputPrefix + ".error", message);
        return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);
    }

    /**
     * "{flow.var.name}" -> the value of that flow variable (null if unset);
     * anything else is returned as a literal.
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
