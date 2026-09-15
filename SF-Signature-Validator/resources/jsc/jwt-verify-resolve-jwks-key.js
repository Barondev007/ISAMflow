// Resolves this proxy's JWT verification public key from a JWKS
// document (signature.verify.jwt.jwks.response.content, fetched by
// SC-JWT-Verify-Fetch-JWKS from the jwksUri in this proxy's KVM
// config) by matching signature.verify.jwt.header.kid (see
// JS-JWT-Verify-Extract-Kid) against each entry's "kid", then
// re-packages that key's RSA modulus/exponent (n, e — base64url,
// unsigned big-endian) as a DER-encoded X.509 SubjectPublicKeyInfo,
// PEM-wrapped, into signature.verify.jwt.publicKey.pem — the SAME
// variable the static-publicKeyPem path (EV-JWT-Verify-Parse-Config)
// sets directly from KVM. VerifyJWS-Jwt-Compact/-Detached read that
// variable either way and don't know or care which path populated it.
//
// This is packaging, not cryptography: a JWKS endpoint hands back
// PUBLIC key material over HTTP by design (that's the entire point of
// JWKS), so there's no secret material here and no signing/verifying
// math — just repackaging existing bytes into a different container
// format (JWK's {n, e} versus PEM's DER/ASN.1 SubjectPublicKeyInfo).
// That's why this is plain JS, consistent with this project's other
// hand-rolled byte-level helpers (base64url.js, sha256.js,
// xml-exc-c14n.js in SF-Signature-Router) rather than a JavaCallout —
// unlike the actual signature-verification math a JavaCallout was
// needed for elsewhere in this project, packaging public bytes into a
// different container needs no access to protected key material, so
// the same "JS can't reach KeyStore key material" constraint that
// forced XML-DSig's SignatureValue check into Java simply doesn't
// apply here. A bug in this file can only make verification fail
// (VerifyJWS rejects a malformed key) — never accept something it
// shouldn't, since the actual n/e bytes it packages come unmodified
// from the JWKS response.
//
// Only RSA (kty "RSA") is implemented, matching VerifyJWS-Jwt-Compact/
// -Detached's Algorithm, which is pinned to RS256 (not KVM-driven, by
// design — see those policies' comments on algorithm-confusion
// downgrade protection). A JWKS entry with any other kty is skipped
// when matching by kid.

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
            throw new Error('Invalid base64url character in JWKS key material.');
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

function base64EncodeStandard(byteString) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '';
    var i = 0;
    for (; i + 3 <= byteString.length; i += 3) {
        var b0 = byteString.charCodeAt(i);
        var b1 = byteString.charCodeAt(i + 1);
        var b2 = byteString.charCodeAt(i + 2);
        out += chars.charAt(b0 >> 2);
        out += chars.charAt(((b0 & 0x03) << 4) | (b1 >> 4));
        out += chars.charAt(((b1 & 0x0F) << 2) | (b2 >> 6));
        out += chars.charAt(b2 & 0x3F);
    }
    var remaining = byteString.length - i;
    if (remaining === 1) {
        var r0 = byteString.charCodeAt(i);
        out += chars.charAt(r0 >> 2);
        out += chars.charAt((r0 & 0x03) << 4);
        out += '==';
    } else if (remaining === 2) {
        var s0 = byteString.charCodeAt(i);
        var s1 = byteString.charCodeAt(i + 1);
        out += chars.charAt(s0 >> 2);
        out += chars.charAt(((s0 & 0x03) << 4) | (s1 >> 4));
        out += chars.charAt((s1 & 0x0F) << 2);
        out += '=';
    }
    return out;
}

// DER length octets (definite form, short or long).
function derLength(n) {
    if (n < 0x80) {
        return String.fromCharCode(n);
    }
    var bytes = '';
    var v = n;
    while (v > 0) {
        bytes = String.fromCharCode(v & 0xFF) + bytes;
        v = Math.floor(v / 256);
    }
    return String.fromCharCode(0x80 | bytes.length) + bytes;
}

function derTag(tag, content) {
    return String.fromCharCode(tag) + derLength(content.length) + content;
}

// DER INTEGER: strip redundant leading 0x00 padding down to the
// minimal encoding, then re-add exactly one 0x00 iff the high bit of
// the first remaining byte is set (DER integers are signed two's
// complement; RSA modulus/exponent are always positive, so a set high
// bit would otherwise be read as negative).
function derInteger(byteStringBigEndianUnsigned) {
    var b = byteStringBigEndianUnsigned;
    var start = 0;
    while (start < b.length - 1 && b.charCodeAt(start) === 0x00) {
        start++;
    }
    b = b.substring(start);
    if (b.length === 0) {
        b = '\x00';
    }
    if (b.charCodeAt(0) & 0x80) {
        b = '\x00' + b;
    }
    return derTag(0x02, b);
}

function derSequence(contentByteString) {
    return derTag(0x30, contentByteString);
}

// DER BIT STRING wrapping a full byte-aligned DER value (SubjectPublicKeyInfo's
// second SEQUENCE member) — one leading 0x00 "number of unused bits" byte.
function derBitString(contentByteString) {
    return derTag(0x03, '\x00' + contentByteString);
}

// rsaEncryption OID 1.2.840.113549.1.1.1, already DER-encoded (tag 0x06,
// length 9), plus a DER NULL parameter — together the fixed
// AlgorithmIdentifier every RSA SubjectPublicKeyInfo uses.
var RSA_ALGORITHM_IDENTIFIER = derSequence(
    '\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01' + '\x05\x00'
);

function rsaJwkToSubjectPublicKeyInfoPem(nB64Url, eB64Url) {
    var modulus = base64UrlDecodeToByteString(nB64Url);
    var exponent = base64UrlDecodeToByteString(eB64Url);

    var rsaPublicKey = derSequence(derInteger(modulus) + derInteger(exponent));
    var subjectPublicKeyInfo = derSequence(RSA_ALGORITHM_IDENTIFIER + derBitString(rsaPublicKey));

    var base64 = base64EncodeStandard(subjectPublicKeyInfo);
    var pem = '-----BEGIN PUBLIC KEY-----\n';
    for (var i = 0; i < base64.length; i += 64) {
        pem += base64.substring(i, i + 64) + '\n';
    }
    pem += '-----END PUBLIC KEY-----\n';
    return pem;
}

(function resolveJwksKey() {
    var kid = context.getVariable('signature.verify.jwt.header.kid');
    if (!kid) {
        throw new Error('JWS header has no "kid" — cannot select a key from the JWKS document.');
    }

    var jwksJson = context.getVariable('signature.verify.jwt.jwks.response.content');
    if (!jwksJson) {
        throw new Error('signature.verify.jwt.jwks.response.content is empty — SC-JWT-Verify-Fetch-JWKS should have set it.');
    }
    var jwks;
    try {
        jwks = JSON.parse(jwksJson);
    } catch (e) {
        throw new Error('JWKS response is not valid JSON: ' + e.message);
    }
    if (!jwks || !(jwks.keys instanceof Array)) {
        throw new Error('JWKS response has no "keys" array.');
    }

    var matched = null;
    for (var i = 0; i < jwks.keys.length; i++) {
        var candidate = jwks.keys[i];
        if (candidate && candidate.kid === kid) {
            matched = candidate;
            break;
        }
    }
    if (!matched) {
        context.setVariable('signature.verify.jwt.jwks.key.found', 'false');
        return;
    }
    if (matched.kty !== 'RSA') {
        throw new Error('JWKS key "' + kid + '" has kty "' + matched.kty + '" — only RSA is supported (VerifyJWS is pinned to RS256).');
    }
    if (!matched.n || !matched.e) {
        throw new Error('JWKS key "' + kid + '" is missing "n" or "e".');
    }

    var pem = rsaJwkToSubjectPublicKeyInfoPem(matched.n, matched.e);
    context.setVariable('signature.verify.jwt.publicKey.pem', pem);
    context.setVariable('signature.verify.jwt.publicKey.source', 'jwks');
    context.setVariable('signature.verify.jwt.jwks.key.found', 'true');
})();
