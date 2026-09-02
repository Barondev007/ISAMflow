// Minimal SHA-256 (FIPS 180-4) for Apigee's JS engine, which has no
// native crypto. Operates on a byte string (chars 0-255, e.g. the
// output of utf8ToByteString in base64url.js) and returns the 32-byte
// digest as a byte string. Verified against the standard test vectors
// (SHA-256 of "", "abc", and the NIST two-block message).

function sha256Bytes(message) {
    var K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

    function rrot(x, n) {
        return (x >>> n) | (x << (32 - n));
    }

    var bytes = [];
    for (var i = 0; i < message.length; i++) {
        bytes.push(message.charCodeAt(i) & 0xff);
    }
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while ((bytes.length % 64) !== 56) {
        bytes.push(0);
    }
    var hi = Math.floor(bitLen / 0x100000000);
    var lo = bitLen >>> 0;
    var s;
    for (s = 24; s >= 0; s -= 8) { bytes.push((hi >>> s) & 0xff); }
    for (s = 24; s >= 0; s -= 8) { bytes.push((lo >>> s) & 0xff); }

    for (var chunkStart = 0; chunkStart < bytes.length; chunkStart += 64) {
        var w = new Array(64);
        var t;
        for (t = 0; t < 16; t++) {
            var o = chunkStart + t * 4;
            w[t] = ((bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3]) >>> 0;
        }
        for (t = 16; t < 64; t++) {
            var s0 = rrot(w[t - 15], 7) ^ rrot(w[t - 15], 18) ^ (w[t - 15] >>> 3);
            var s1 = rrot(w[t - 2], 17) ^ rrot(w[t - 2], 19) ^ (w[t - 2] >>> 10);
            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
        }

        var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (t = 0; t < 64; t++) {
            var S1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25);
            var ch = (e & f) ^ (~e & g);
            var temp1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
            var S0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22);
            var maj = (a & b) ^ (a & c) ^ (b & c);
            var temp2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + temp1) >>> 0;
            d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }

        H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    var out = '';
    for (var idx = 0; idx < 8; idx++) {
        out += String.fromCharCode((H[idx] >>> 24) & 0xff, (H[idx] >>> 16) & 0xff, (H[idx] >>> 8) & 0xff, H[idx] & 0xff);
    }
    return out;
}
