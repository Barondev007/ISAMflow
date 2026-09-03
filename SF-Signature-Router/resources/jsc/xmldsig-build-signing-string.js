// Builds the digest and SignedInfo signing string for an enveloped XML
// signature (the SignedInfo needed to produce a <ds:Signature> to embed in
// the signed document), over the whole document (Reference URI=""):
//
// 1) Canonicalize the target XML (signature.payload if the calling proxy
//    staged one, else message.content) with Exclusive C14N and SHA-256 it
//    -> DigestValue.
// 2) Build <SignedInfo> (CanonicalizationMethod = exc-c14n,
//    SignatureMethod = signature.xmldsig.signatureMethod, one Reference
//    with the enveloped-signature + exc-c14n Transforms, DigestMethod =
//    sha256, and the DigestValue from step 1).
// 3) Canonicalize <SignedInfo> itself -> this is the exact byte sequence
//    an external signing API needs to RSA/ECDSA-sign to produce
//    <SignatureValue>. base64-encoded into signature.xmldsig.signing.string.
//
// Only SHA-256 digest and Exclusive C14N (no comments, no
// InclusiveNamespaces PrefixList) are actually implemented — that's what
// CanonicalizationMethod/DigestMethod are hardcoded to. signatureMethod is
// the one genuinely configurable piece, since it doesn't affect what this
// script computes (it just labels what the external signing step is
// expected to do).
//
// Scope: this signs the whole document as-is (no pre-existing
// <Signature>/<ds:Signature> is stripped before digesting) — correct for
// generating a brand-new signature, not for re-signing an already-signed
// document.

(function buildXmlDsigSigningString() {
    var signatureMethod = context.getVariable('signature.xmldsig.signatureMethod');
    if (!signatureMethod) {
        signatureMethod = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        context.setVariable('signature.xmldsig.signatureMethod', signatureMethod);
    }

    var payload = context.getVariable('signature.payload');
    if (payload === null || payload === undefined || payload === '') {
        payload = context.getVariable('message.content') || '';
    }

    var targetRoot = c14nParseXml(payload);
    if (!targetRoot) {
        throw new Error('signature.payload / message.content is not well-formed XML; cannot build an XML signature over it.');
    }

    var canonicalTarget = canonicalizeExclusive(targetRoot);
    var digestValue = base64Encode(sha256Bytes(utf8ToByteString(canonicalTarget)));
    context.setVariable('signature.xmldsig.digest.value', digestValue);

    var signedInfoXml =
        '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">' +
        '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        '<SignatureMethod Algorithm="' + c14nEscapeAttr(signatureMethod) + '"/>' +
        '<Reference URI="">' +
        '<Transforms>' +
        '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>' +
        '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
        '</Transforms>' +
        '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>' +
        '<DigestValue>' + digestValue + '</DigestValue>' +
        '</Reference>' +
        '</SignedInfo>';

    var signedInfoRoot = c14nParseXml(signedInfoXml);
    var canonicalSignedInfo = canonicalizeExclusive(signedInfoRoot);
    context.setVariable('signature.xmldsig.signedinfo.canonical', canonicalSignedInfo);

    context.setVariable('signature.xmldsig.signing.string', base64Encode(utf8ToByteString(canonicalSignedInfo)));
})();
