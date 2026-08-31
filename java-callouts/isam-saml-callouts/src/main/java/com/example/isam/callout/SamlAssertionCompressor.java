package com.example.isam.callout;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * JC-Compress-SAML-Assertion.
 *
 * When the resolved compressSaml flag is true, zips the SAML assertion XML (single
 * "assertion.xml" entry) and base64-encodes the archive. When false, just base64s
 * the raw XML. Either way the result lands in saml.assertion.output so downstream
 * steps can put it in a header without caring which case happened; saml.assertion.compressed
 * records which one it was.
 */
public class SamlAssertionCompressor implements Execution {

    private final Map properties;

    public SamlAssertionCompressor(Map properties) {
        this.properties = properties;
    }

    public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
        try {
            String assertionVarName = getProperty("assertionVariable", "isam.rstr.assertion.xml");
            String flagVarName = getProperty("compressFlagVariable", "compressSaml");

            String assertionXml = str(messageContext.getVariable(assertionVarName));
            if (assertionXml == null) {
                assertionXml = "";
            }
            boolean compress = truthy(messageContext.getVariable(flagVarName));

            byte[] utf8 = assertionXml.getBytes("UTF-8");
            String output;

            if (compress) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ZipOutputStream zos = new ZipOutputStream(baos);
                zos.putNextEntry(new ZipEntry("assertion.xml"));
                zos.write(utf8);
                zos.closeEntry();
                zos.close();
                output = Base64.getEncoder().encodeToString(baos.toByteArray());
            } else {
                output = Base64.getEncoder().encodeToString(utf8);
            }

            messageContext.setVariable("saml.assertion.output", output);
            messageContext.setVariable("saml.assertion.compressed", compress);
        } catch (Exception e) {
            messageContext.setVariable("saml.assertion.output", "");
            messageContext.setVariable("saml.assertion.compressed", false);
            messageContext.setVariable("saml.assertion.compress.error", e.toString());
        }
        return ExecutionResult.SUCCESS;
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

    private static boolean truthy(Object v) {
        if (v == null) return false;
        String s = v.toString().trim().toLowerCase(java.util.Locale.ROOT);
        return s.equals("true") || s.equals("1") || s.equals("yes");
    }
}
