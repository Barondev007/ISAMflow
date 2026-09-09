// Recomputes the digest over a signed XML document (signature.payload or
// message.content) and compares it to the DigestValue the embedded
// <Signature> claims, per the enveloped-signature + Exclusive C14N
// transforms — the same construction as the signing side, in reverse.
//
// IMPORTANT: this checks content integrity against the document's OWN
// claimed digest, not authenticity. An attacker controlling the document
// controls both the content and its claimed DigestValue, so a digest
// match here proves nothing about who signed it — only the actual
// SignatureValue crypto check (still a placeholder — see
// NI-XmlDsig-Verify-Signature) does that, since it's the only piece
// cryptographically bound to the signer's private key. Treat a digest
// mismatch as a hard failure (it means the content was altered after
// signing, or is simply malformed), but never treat a digest match alone
// as "verified."
//
// Only Exclusive C14N (no comments) canonicalization and SHA-256 digests
// are supported, matching what the signing side produces.

function c14nGetElementText(node) {
    var text = '';
    for (var i = 0; i < node.children.length; i++) {
        var child = node.children[i];
        if (child.type === 'text') {
            text += child.value;
        } else if (child.type === 'element') {
            text += c14nGetElementText(child);
        }
    }
    return text;
}

function xmldsigGetAttr(node, name) {
    for (var i = 0; i < node.attrs.length; i++) {
        if (node.attrs[i].qName === name) {
            return node.attrs[i].value;
        }
    }
    return null;
}

(function verifyXmlDsigDigest() {
    var payload = context.getVariable('signature.verify.payload');
    if (payload === null || payload === undefined || payload === '') {
        payload = context.getVariable('message.content') || '';
    }

    var root = c14nParseXml(payload);
    if (!root) {
        throw new Error('signature.verify.payload / message.content is not well-formed XML.');
    }

    var sigFound = findElementWithInheritedNs(root, 'Signature', {});
    if (!sigFound) {
        throw new Error('No <Signature> element found in the document to verify.');
    }

    var signedInfoFound = findElementWithInheritedNs(sigFound.node, 'SignedInfo', sigFound.inheritedNs);
    if (!signedInfoFound) {
        throw new Error('<Signature> has no <SignedInfo> child.');
    }
    var signedInfo = signedInfoFound.node;

    var canonMethodNode = null, refNode = null, sigValueNode = null, sigMethodNode = null;
    for (var i = 0; i < signedInfo.children.length; i++) {
        var c = signedInfo.children[i];
        if (c.type !== 'element') { continue; }
        if (c.local === 'CanonicalizationMethod') { canonMethodNode = c; }
        if (c.local === 'Reference') { refNode = c; }
        if (c.local === 'SignatureMethod') { sigMethodNode = c; }
    }
    for (var j = 0; j < sigFound.node.children.length; j++) {
        var c2 = sigFound.node.children[j];
        if (c2.type === 'element' && c2.local === 'SignatureValue') { sigValueNode = c2; }
    }
    if (!canonMethodNode || !refNode || !sigValueNode) {
        throw new Error('<SignedInfo>/<Signature> is missing CanonicalizationMethod, Reference, or SignatureValue.');
    }

    var canonAlgorithm = xmldsigGetAttr(canonMethodNode, 'Algorithm');
    if (canonAlgorithm !== 'http://www.w3.org/2001/10/xml-exc-c14n#') {
        throw new Error('Unsupported CanonicalizationMethod "' + canonAlgorithm + '" — only Exclusive C14N is implemented.');
    }

    var digestMethodNode = null, digestValueNode = null;
    for (var k = 0; k < refNode.children.length; k++) {
        var c3 = refNode.children[k];
        if (c3.type !== 'element') { continue; }
        if (c3.local === 'DigestMethod') { digestMethodNode = c3; }
        if (c3.local === 'DigestValue') { digestValueNode = c3; }
    }
    if (!digestMethodNode || !digestValueNode) {
        throw new Error('<Reference> is missing DigestMethod or DigestValue.');
    }
    var digestAlgorithm = xmldsigGetAttr(digestMethodNode, 'Algorithm');
    if (digestAlgorithm !== 'http://www.w3.org/2001/04/xmlenc#sha256') {
        throw new Error('Unsupported DigestMethod "' + digestAlgorithm + '" — only SHA-256 is implemented.');
    }

    // Real-world XML-DSig output routinely line-wraps base64 content
    // (embedded whitespace/CR/LF) — strip it before comparing/using it.
    var claimedDigest = c14nGetElementText(digestValueNode).replace(/\s+/g, '');
    var signatureValue = c14nGetElementText(sigValueNode).replace(/\s+/g, '');

    var strippedRoot = removeElementByLocalName(root, 'Signature');
    var canonicalTarget = canonicalizeExclusive(strippedRoot);
    var recomputedDigest = base64Encode(sha256Bytes(utf8ToByteString(canonicalTarget)));

    var signedInfoCanonical = canonicalizeExclusiveSubtree(signedInfo, signedInfoFound.inheritedNs);

    context.setVariable('signature.verify.xmldsig.digest.claimed', claimedDigest);
    context.setVariable('signature.verify.xmldsig.digest.recomputed', recomputedDigest);
    context.setVariable('signature.verify.xmldsig.digest.match', claimedDigest === recomputedDigest ? 'true' : 'false');
    context.setVariable('signature.verify.xmldsig.signedinfo.canonical', signedInfoCanonical);
    context.setVariable('signature.verify.xmldsig.signature.value', signatureValue);
    context.setVariable('signature.verify.xmldsig.signature.method', sigMethodNode ? xmldsigGetAttr(sigMethodNode, 'Algorithm') : null);
})();
