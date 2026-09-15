// Reads the "kid" (Key ID) claim out of the JWS header — WITHOUT
// verifying anything — so a JWKS-based proxy knows which key in the
// JWKS document to use. This has to run before VerifyJWS, since
// VerifyJWS is what does the actual verification and needs the key
// already resolved into signature.verify.jwt.publicKey.pem first.
//
// Self-contained: only used when this proxy's KVM config has no
// publicKeyPem and needs to resolve one from a JWKS endpoint instead
// (see EV-JWT-Verify-Parse-Config / JS-JWT-Verify-Resolve-JWKS-Key), so
// it doesn't pull in the shared base64url.js module for one function.

function base64UrlDecodeToByteString(input) {
    var s = String(input).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) {
        s += '=';
    }
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var out = '';
    var buffer = 0, bits = 0;
    for (var i = 0; i < s.length; i++) {
        var c = s.charAt(i);
        if (c === '=') {
            break;
        }
        var val = chars.indexOf(c);
        if (val === -1) {
            throw new Error('Invalid base64url character in JWS header segment.');
        }
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += String.fromCharCode((buffer >> bits) & 0xFF);
        }
    }
    return out;
}

(function extractJwtHeaderKid() {
    var jws = context.getVariable('signature.verify.jwt.jws');
    if (!jws) {
        throw new Error('signature.verify.jwt.jws is not set.');
    }
    var firstDot = jws.indexOf('.');
    if (firstDot === -1) {
        throw new Error('signature.verify.jwt.jws does not look like a JWS (no "." found).');
    }
    var headerSegment = jws.substring(0, firstDot);
    var headerJson;
    try {
        headerJson = base64UrlDecodeToByteString(headerSegment);
    } catch (e) {
        throw new Error('JWS header segment is not valid base64url: ' + e.message);
    }
    var header;
    try {
        header = JSON.parse(headerJson);
    } catch (e) {
        throw new Error('JWS header segment does not decode to valid JSON: ' + e.message);
    }

    context.setVariable('signature.verify.jwt.header.kid', header.kid || null);
    context.setVariable('signature.verify.jwt.header.alg', header.alg || null);
})();
