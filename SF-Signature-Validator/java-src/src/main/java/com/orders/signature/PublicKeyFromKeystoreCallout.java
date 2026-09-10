package com.orders.signature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Map;

/**
 * Reads a certificate's public key out of an Apigee-managed KeyStore and
 * writes it, PEM-encoded (X.509 SubjectPublicKeyInfo, "BEGIN PUBLIC KEY"),
 * into a flow variable — so VerifyJWS can consume it via
 * <PublicKey><Value ref="..."/></PublicKey>, since VerifyJWS's own
 * <PublicKey><KeyStore ref="..."/><Alias ref="..."/></PublicKey> does not
 * resolve a dynamic ref at runtime (confirmed against a live Apigee
 * instance — only ServiceCallout/TargetEndpoint's <SSLInfo><KeyStore
 * ref="..."> does that).
 *
 * Policy XML config (see JC-JWT-Verify-Extract-Public-Key.xml):
 *   <Properties>
 *     <Property name="keystore-name">{signature.verify.jwt.keystore.name}</Property>
 *     <Property name="alias">{signature.verify.jwt.keystore.alias}</Property>
 *     <Property name="output-variable">signature.verify.jwt.publicKey.pem</Property>
 *   </Properties>
 *
 * "keystore-name"/"alias" are resolved as flow-variable references: a
 * property value wrapped in "{...}" is looked up via
 * MessageContext.getVariable() at request time (this class is
 * instantiated once and reused across requests, so a literal value baked
 * in at policy-load time can't carry a per-proxy runtime value — only a
 * "{var}" reference resolved inside execute() can). This does NOT rely on
 * Apigee auto-resolving "{var}" inside <Property> text; resolution
 * happens explicitly in resolveConfigValue() below, using only the
 * well-documented MessageContext.getVariable() API. "output-variable" is
 * always a literal flow-variable NAME to write the PEM into, never a ref.
 *
 * ============================================================================
 * UNVERIFIED: the one line in this file that could not be checked from here
 * is the KeyStore lookup itself — getExecutionContextKeystore() below. I
 * recall Apigee's Java Callout SDK (com.apigee.flow.execution.ExecutionContext,
 * shipped in message-flow-*.jar) exposes a method to fetch a
 * java.security.KeyStore handle for a KeyStore configured in the
 * environment/org by name, and getKeystore(String name, boolean isTrustStore)
 * is my best-confidence guess at its signature — but I cannot compile this
 * against the real SDK jar from here to confirm the exact method name,
 * argument order, or return type. Before relying on this:
 *   1. Build with the real message-flow-*.jar on the classpath (see
 *      java-src/README.md) and let javac's "cannot find symbol" (if any)
 *      point at the real method.
 *   2. If getKeystore doesn't exist, check ExecutionContext's other
 *      methods for something equivalent (grep the jar's public API, e.g.
 *      `javap -public com.apigee.flow.execution.ExecutionContext`) — likely
 *      candidates by naming convention: getKeyStore (capital S), or a
 *      method on a "CalloutContext"/"SecurityContext"-style helper instead.
 *      Apigee's own Java-callout documentation page for KeyStore access
 *      from a callout, if your Apigee edition has one, is the authoritative
 *      source — I don't have a verified link to give you.
 *   3. If no such method exists at all in your SDK version, the fallback is
 *      to stop referencing the Apigee-managed KeyStore from Java and instead
 *      bundle the public certificate as a policy resource (e.g.
 *      resources/java/<alias>.pem read via this class's own classloader,
 *      or even resources/keystore/*.jks loaded with
 *      java.security.KeyStore.getInstance(...).load(InputStream, password)) —
 *      that part of this class (everything after you have a KeyStore
 *      object) needs no further change either way.
 * ============================================================================
 */
public class PublicKeyFromKeystoreCallout implements Execution {

    private final Map properties;

    public PublicKeyFromKeystoreCallout(Map properties) {
        this.properties = properties;
    }

    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext execContext) {
        String outputVariable = getLiteralProperty("output-variable", "signature.verify.jwt.publicKey.pem");
        String errorVariable = outputVariable + ".error";

        try {
            String keystoreName = resolveConfigValue(msgCtxt, "keystore-name");
            String alias = resolveConfigValue(msgCtxt, "alias");

            if (isBlank(keystoreName)) {
                return fail(msgCtxt, errorVariable, "keystore-name is not set (check signature.verify.jwt.keystore.name)");
            }
            if (isBlank(alias)) {
                return fail(msgCtxt, errorVariable, "alias is not set (check signature.verify.jwt.keystore.alias)");
            }

            KeyStore keystore = getExecutionContextKeystore(execContext, keystoreName);
            if (keystore == null) {
                return fail(msgCtxt, errorVariable, "no KeyStore named '" + keystoreName + "' is available to this callout");
            }

            Certificate cert = keystore.getCertificate(alias);
            if (cert == null) {
                return fail(msgCtxt, errorVariable, "no certificate under alias '" + alias + "' in KeyStore '" + keystoreName + "'");
            }

            PublicKey publicKey = cert.getPublicKey();
            String pem = toPem(publicKey.getEncoded());

            msgCtxt.setVariable(outputVariable, pem);
            msgCtxt.setVariable(outputVariable + ".algorithm", publicKey.getAlgorithm());
            return new ExecutionResult(true, ExecutionResult.Action.CONTINUE);

        } catch (Exception e) {
            return fail(msgCtxt, errorVariable, e.toString());
        }
    }

    /**
     * UNVERIFIED — see the class-level comment above. This is the single
     * line in this file that depends on an Apigee SDK method I could not
     * confirm from here.
     */
    private KeyStore getExecutionContextKeystore(ExecutionContext execContext, String keystoreName) throws Exception {
        return execContext.getKeystore(keystoreName, false);
    }

    private ExecutionResult fail(MessageContext msgCtxt, String errorVariable, String message) {
        msgCtxt.setVariable(errorVariable, message);
        return new ExecutionResult(false, ExecutionResult.Action.ABORT);
    }

    /**
     * "{flow.var.name}" -> the value of that flow variable (null if unset);
     * anything else is returned as a literal. Deliberately NOT relying on
     * Apigee resolving "{...}" inside <Property> text automatically — this
     * class is instantiated once at policy load and reused across requests,
     * so any per-request resolution has to happen here, inside execute(),
     * against the MessageContext of the current request.
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

    private static String toPem(byte[] der) {
        String base64 = Base64.getEncoder().encodeToString(der);
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }
        pem.append("-----END PUBLIC KEY-----\n");
        return pem.toString();
    }
}
