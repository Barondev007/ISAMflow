// Shared helpers for the mock signing-service endpoints.

function mockParsePathParams(pathsuffix, opSuffix) {
    // opSuffix e.g. "hmacs:compute" -> matches /scopes/{scope}/keys/{keyName}/hmacs:compute
    var pattern = new RegExp('^/scopes/([^/]+)/keys/([^/]+)/' + opSuffix.replace(':', '\\:') + '$');
    var m = pathsuffix.match(pattern);
    if (!m) {
        return null;
    }
    return { scope: decodeURIComponent(m[1]), keyName: decodeURIComponent(m[2]) };
}

// Deterministic, per (scope, keyName) mock HMAC key — NOT real KMS-backed
// key material, purely so this mock's compute/verify endpoints are
// self-consistent (the same scope/keyName always yields the same key, so
// a hmacs:compute result verifies successfully against hmacs:verify).
function mockDeriveHmacKey(scope, keyName) {
    return sha256Bytes(utf8ToByteString(scope + ':' + keyName + ':mock-hmac-key'));
}

function mockSendJson(statusCode, obj) {
    context.setVariable('response.status.code', statusCode);
    context.setVariable('response.header.Content-Type', 'application/json');
    context.setVariable('response.content', JSON.stringify(obj));
}

function mockSendError(statusCode, code, message) {
    mockSendJson(statusCode, { code: code, message: message });
}

function mockParseJsonBody() {
    var raw = context.getVariable('request.content');
    if (!raw) {
        return null;
    }
    try {
        return JSON.parse(raw);
    } catch (e) {
        return undefined; // signals "present but invalid JSON", distinct from "absent"
    }
}
