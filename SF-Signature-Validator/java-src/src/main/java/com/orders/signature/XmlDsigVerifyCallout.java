package com.orders.signature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Verifies an enveloped XML Signature end to end -- canonicalization,
 * digest, and the SignatureValue cryptographic check -- in one policy,
 * using the JDK's built-in JSR 105 implementation (javax.xml.crypto.dsig,
 * part of the standard Java platform since Java 6, in the java.xml.crypto
 * module; no extra library beyond the Apigee SDK).
 *
 * &lt;b&gt;Trust model: the verification key comes from the document's own
 * KeyInfo (KeyValue, else X509Data's certificate), not from any
 * separately configured, pre-trusted key material.&lt;/b&gt; This is a
 * DELIBERATE choice, made explicitly after being warned about its
 * consequence, not an oversight: validating a signature against a key
 * that travels inside the same message it signs proves only "whoever
 * sent this possesses a private key" -- it does NOT prove the message
 * came from any specific party, since an attacker able to modify the
 * message in transit can just as easily replace the signature AND the
 * embedded key/certificate together with their own, and this callout
 * would still report the signature as valid. If this bundle ever needs
 * to assert WHO signed something -- not just that it wasn't altered
 * after some signing event -- that requires either pinning the embedded
 * certificate against a known-expected one (e.g. a KVM-configured
 * fingerprint) or full certificate-chain validation against a trusted
 * CA, neither of which this class does. The earlier revision of this
 * file (git history) took a public-key-pem Property from this proxy's
 * KVM entry instead -- restore that approach (or add pinning on top of
 * this one) if that guarantee turns out to matter here after all.
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
 * itself happens to declare. This allow-list is independent of, and no
 * weaker because of, the KeyInfo trust-model choice above: it still
 * closes off wrapping attacks regardless of where the key came from.
 *
 * Policy config (see JC-XmlDsig-Verify-Signature.xml):
 *   &lt;Properties&gt;
 *     &lt;Property name="document"&gt;{signature.verify.payload}&lt;/Property&gt;
 *     &lt;Property name="document-fallback"&gt;{message.content}&lt;/Property&gt;
 *     &lt;Property name="output-prefix"&gt;signature.verify.xmldsig&lt;/Property&gt;
 *   &lt;/Properties&gt;
 *
 * "document"/"document-fallback" are resolved as flow-variable
 * references: a property value wrapped in "{...}" is looked up via
 * MessageContext.getVariable() at request time, since this class is
 * instantiated once at policy load and reused across requests.
 * "output-prefix" is always a literal flow-variable name PREFIX, never a
 * ref. There is no key-related config left -- see the trust-model note
 * above for why.
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

            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext validateContext = new DOMValidateContext(new FromDocumentKeySelector(), sigElement);
            XMLSignature signature;
            try {
                signature = factory.unmarshalXMLSignature(validateContext);
            } catch (Exception unmarshalError) {
                return fail(msgCtxt, outputPrefix, "could not read <Signature>: " + unmarshalError.getMessage());
            }

            String shapeError = checkExpectedShape(signature);
            if (shapeError != null) {
                return fail(msgCtxt, outputPrefix, shapeError);
            }

            boolean coreValid;
            try {
                coreValid = signature.validate(validateContext);
            } catch (Exception validateError) {
                // Covers KeySelectorException -- thrown when KeyInfo has
                // neither a KeyValue nor an X509Data/X509Certificate to
                // resolve a key from. JSR 105 wraps it in a generic
                // XMLSignatureException("cannot find validation key"),
                // so surface the cause's message (FromDocumentKeySelector's
                // own, specific text) when there is one -- confirmed by
                // direct test that the cause is where the useful detail
                // actually ends up, not the wrapping exception itself.
                String detail = (validateError.getCause() != null)
                        ? validateError.getCause().getMessage()
                        : validateError.getMessage();
                return fail(msgCtxt, outputPrefix, "could not resolve a verification key from KeyInfo: " + detail);
            }
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
                        : "signature value does not validate against the key found in KeyInfo");
            }

            return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);

        } catch (Exception e) {
            return fail(msgCtxt, outputPrefix, e.toString());
        }
    }

    /**
     * Resolves the verification key from the document's own KeyInfo --
     * see the class-level comment for why this is a deliberate trust-model
     * choice, not an oversight. Prefers KeyValue (the raw key, no
     * certificate parsing needed) and falls back to the first
     * X509Certificate found in X509Data; throws if KeyInfo has neither.
     */
    private static class FromDocumentKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("document has no KeyInfo -- nothing to resolve a verification key from");
            }
            for (Object infoObj : keyInfo.getContent()) {
                if (infoObj instanceof KeyValue) {
                    try {
                        return result(((KeyValue) infoObj).getPublicKey());
                    } catch (Exception e) {
                        throw new KeySelectorException(e);
                    }
                }
            }
            for (Object infoObj : keyInfo.getContent()) {
                if (infoObj instanceof X509Data) {
                    for (Object x509Obj : ((X509Data) infoObj).getContent()) {
                        if (x509Obj instanceof X509Certificate) {
                            return result(((X509Certificate) x509Obj).getPublicKey());
                        }
                    }
                }
            }
            throw new KeySelectorException("KeyInfo has neither a KeyValue nor an X509Data/X509Certificate");
        }

        private KeySelectorResult result(final Key key) {
            return new KeySelectorResult() {
                public Key getKey() { return key; }
            };
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
