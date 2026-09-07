// HMAC-SHA256 (RFC 2104), built on the already-verified sha256Bytes.
// Verified against Node's crypto.createHmac('sha256', ...) across
// several cases, including an empty key and a key longer than the
// 64-byte block size (which HMAC requires pre-hashing down).

function hmacSha256Bytes(keyByteString, messageByteString) {
    var blockSize = 64;
    var key = keyByteString;
    if (key.length > blockSize) {
        key = sha256Bytes(key);
    }
    if (key.length < blockSize) {
        var padded = key;
        for (var i = key.length; i < blockSize; i++) {
            padded += '\x00';
        }
        key = padded;
    }
    var ipad = '', opad = '';
    for (var j = 0; j < blockSize; j++) {
        var kc = key.charCodeAt(j);
        ipad += String.fromCharCode(kc ^ 0x36);
        opad += String.fromCharCode(kc ^ 0x5c);
    }
    return sha256Bytes(opad + sha256Bytes(ipad + messageByteString));
}
