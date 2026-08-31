package com.example.isam.callout;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Resolves the signing key straight from the ds:KeyInfo/ds:X509Data embedded in the
 * assertion itself (there's no separate keystore to look the signer up in) and hands
 * the certificate back to the caller via certOut so it can be inspected/pinned.
 */
class EmbeddedCertKeySelector extends KeySelector {

    private final X509Certificate[] certOut;

    EmbeddedCertKeySelector(X509Certificate[] certOut) {
        this.certOut = certOut;
    }

    @Override
    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
                                     AlgorithmMethod method, XMLCryptoContext context)
            throws KeySelectorException {
        if (keyInfo == null) {
            throw new KeySelectorException("no ds:KeyInfo present in the signature");
        }
        List<?> content = keyInfo.getContent();
        for (Object info : content) {
            if (!(info instanceof X509Data)) {
                continue;
            }
            X509Data x509Data = (X509Data) info;
            for (Object o : x509Data.getContent()) {
                if (o instanceof X509Certificate) {
                    final X509Certificate cert = (X509Certificate) o;
                    certOut[0] = cert;
                    final Key key = cert.getPublicKey();
                    return new KeySelectorResult() {
                        public Key getKey() {
                            return key;
                        }
                    };
                }
            }
        }
        throw new KeySelectorException("no X509Certificate found in ds:KeyInfo/ds:X509Data");
    }
}
