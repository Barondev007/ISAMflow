package com.example.isam.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.Map;

/**
 * JC-Validate-SAML-Signature.
 *
 * Verifies the ds:Signature wrapped around (or enveloping) the SAML assertion using
 * the X.509 certificate embedded in the signature's own ds:KeyInfo -- i.e. exactly
 * "validate the SAML signature with the public cert available in the SAML".
 *
 * IMPORTANT: a signature that validates against a cert embedded in the same document
 * only proves internal consistency (the assertion wasn't tampered with after whoever
 * holds that cert's private key signed it) -- it does NOT by itself prove the signer
 * is actually ISAM, since nothing stops an attacker from generating their own keypair,
 * embedding their own cert, and self-signing a forged assertion. To close that gap,
 * configure isam.config.trustedSigningCertThumbprints (comma-separated SHA-256
 * thumbprints of ISAM's real signing cert(s)) in the KVM config; when set, this
 * callout also rejects assertions signed by any cert not in that list.
 *
 * Output variables (all under saml.signature.*):
 *   valid            boolean - overall pass/fail (crypto validity AND, if configured, pinning)
 *   error            string  - present when valid=false
 *   cert.subject     string
 *   cert.issuer      string
 *   cert.serial      string
 *   cert.expired     boolean
 *   cert.thumbprint  string  - SHA-256 hex, uppercase, no separators
 *   pinned           boolean - whether thumbprint pinning was enforced
 */
@IOIntensive
public class SamlSignatureValidator implements Execution {

    private static final String OUT_PREFIX = "saml.signature";

    private final Map properties;

    public SamlSignatureValidator(Map properties) {
        this.properties = properties;
    }

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            String assertionVarName = getProperty("assertionVariable", "isam.rstr.assertion.xml");
            String thumbprintsVarName = getProperty("trustedThumbprintsVariable", "isam.config.trustedThumbprints");

            String assertionXml = str(messageContext.getVariable(assertionVarName));
            if (assertionXml == null || assertionXml.trim().length() == 0) {
                fail(messageContext, "no SAML assertion present to validate");
                return ExecutionResult.SUCCESS;
            }

            Document doc = parse(assertionXml);
            markIdAttributes(doc);

            NodeList sigNodes = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (sigNodes.getLength() == 0) {
                fail(messageContext, "assertion is not signed (no ds:Signature element found)");
                return ExecutionResult.SUCCESS;
            }
            Element sigElement = (Element) sigNodes.item(0);

            X509Certificate[] certHolder = new X509Certificate[1];
            EmbeddedCertKeySelector keySelector = new EmbeddedCertKeySelector(certHolder);

            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext valContext = new DOMValidateContext(keySelector, sigElement);

            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            boolean coreValid = signature.validate(valContext);

            X509Certificate cert = certHolder[0];
            if (cert == null) {
                fail(messageContext, "no X.509 certificate found in ds:KeyInfo");
                return ExecutionResult.SUCCESS;
            }

            messageContext.setVariable(OUT_PREFIX + ".cert.subject", cert.getSubjectX500Principal().getName());
            messageContext.setVariable(OUT_PREFIX + ".cert.issuer", cert.getIssuerX500Principal().getName());
            messageContext.setVariable(OUT_PREFIX + ".cert.serial", cert.getSerialNumber().toString());

            boolean expired = false;
            try {
                cert.checkValidity();
            } catch (Exception ce) {
                expired = true;
            }
            messageContext.setVariable(OUT_PREFIX + ".cert.expired", expired);

            String thumbprint = sha256Thumbprint(cert);
            messageContext.setVariable(OUT_PREFIX + ".cert.thumbprint", thumbprint);

            if (!coreValid) {
                fail(messageContext, "signature did not validate against the embedded certificate");
                return ExecutionResult.SUCCESS;
            }

            if (expired) {
                fail(messageContext, "signing certificate is expired or not yet valid");
                return ExecutionResult.SUCCESS;
            }

            String trustedThumbprintsRaw = str(messageContext.getVariable(thumbprintsVarName));
            boolean pinningConfigured = trustedThumbprintsRaw != null && trustedThumbprintsRaw.trim().length() > 0;
            messageContext.setVariable(OUT_PREFIX + ".pinned", pinningConfigured);

            if (pinningConfigured && !isThumbprintTrusted(thumbprint, trustedThumbprintsRaw)) {
                fail(messageContext, "signature is cryptographically valid but signing certificate "
                        + thumbprint + " is not in the configured trusted thumbprint list");
                return ExecutionResult.SUCCESS;
            }

            messageContext.setVariable(OUT_PREFIX + ".valid", true);
        } catch (Exception e) {
            fail(messageContext, e.toString());
        }
        return ExecutionResult.SUCCESS;
    }

    private static void fail(MessageContext messageContext, String reason) {
        messageContext.setVariable(OUT_PREFIX + ".valid", false);
        messageContext.setVariable(OUT_PREFIX + ".error", reason);
    }

    private String getProperty(String name, String fallback) {
        if (properties == null) return fallback;
        Object v = properties.get(name);
        if (v == null) return fallback;
        String s = v.toString().trim();
        return s.length() == 0 ? fallback : s;
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // Harden against XXE / entity-expansion attacks in the parsed assertion.
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));
    }

    // The Signature's Reference URI="#<AssertionID>" is resolved against whichever
    // attribute the DOM considers an "ID". With no DTD/schema loaded, nothing tells
    // it that automatically, so mark the common SAML ID attribute names by hand.
    private static void markIdAttributes(Document doc) {
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element el = (Element) all.item(i);
            if (el.hasAttribute("ID")) {
                el.setIdAttribute("ID", true);
            }
            if (el.hasAttribute("Id")) {
                el.setIdAttribute("Id", true);
            }
        }
    }

    private static String sha256Thumbprint(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static boolean isThumbprintTrusted(String thumbprint, String trustedCsv) {
        String normalizedActual = thumbprint.replace(":", "").toUpperCase(Locale.ROOT);
        for (String p : trustedCsv.split(",")) {
            String normalizedTrusted = p.trim().replace(":", "").toUpperCase(Locale.ROOT);
            if (normalizedTrusted.length() > 0 && normalizedTrusted.equals(normalizedActual)) {
                return true;
            }
        }
        return false;
    }
}
