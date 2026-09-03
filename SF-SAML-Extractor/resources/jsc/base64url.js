// Self-contained base64url helpers for Apigee's JS engine (no Buffer/btoa).

function utf8ToByteString(str) {
    return unescape(encodeURIComponent(str));
}

function byteStringToUtf8(byteString) {
    return decodeURIComponent(escape(byteString));
}

function base64Encode(byteString) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var out = '';
    var i = 0;
    for (; i + 3 <= byteString.length; i += 3) {
        var n = (byteString.charCodeAt(i) << 16) |
                (byteString.charCodeAt(i + 1) << 8) |
                byteString.charCodeAt(i + 2);
        out += chars.charAt((n >>> 18) & 63) +
               chars.charAt((n >>> 12) & 63) +
               chars.charAt((n >>> 6) & 63) +
               chars.charAt(n & 63);
    }
    var remaining = byteString.length - i;
    if (remaining === 1) {
        var n1 = byteString.charCodeAt(i) << 16;
        out += chars.charAt((n1 >>> 18) & 63) + chars.charAt((n1 >>> 12) & 63) + '==';
    } else if (remaining === 2) {
        var n2 = (byteString.charCodeAt(i) << 16) | (byteString.charCodeAt(i + 1) << 8);
        out += chars.charAt((n2 >>> 18) & 63) + chars.charAt((n2 >>> 12) & 63) + chars.charAt((n2 >>> 6) & 63) + '=';
    }
    return out;
}

function base64Decode(b64) {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    // Accept base64url input too (- _ in place of + /) before stripping
    // anything else (padding, whitespace, newlines).
    var clean = b64.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
    var out = '';
    var i = 0;
    for (; i + 4 <= clean.length; i += 4) {
        var n = (chars.indexOf(clean.charAt(i)) << 18) |
                (chars.indexOf(clean.charAt(i + 1)) << 12) |
                (chars.indexOf(clean.charAt(i + 2)) << 6) |
                chars.indexOf(clean.charAt(i + 3));
        out += String.fromCharCode((n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
    }
    var remaining = clean.length - i;
    if (remaining === 2) {
        var n1 = (chars.indexOf(clean.charAt(i)) << 18) | (chars.indexOf(clean.charAt(i + 1)) << 12);
        out += String.fromCharCode((n1 >>> 16) & 0xff);
    } else if (remaining === 3) {
        var n2 = (chars.indexOf(clean.charAt(i)) << 18) | (chars.indexOf(clean.charAt(i + 1)) << 12) | (chars.indexOf(clean.charAt(i + 2)) << 6);
        out += String.fromCharCode((n2 >>> 16) & 0xff, (n2 >>> 8) & 0xff);
    }
    return out;
}

function base64UrlEncode(str) {
    return base64Encode(utf8ToByteString(str))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function generateUUIDv4() {
    var d = new Date().getTime();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}
