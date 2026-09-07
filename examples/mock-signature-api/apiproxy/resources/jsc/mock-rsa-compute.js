// Mocks POST /scopes/{scope}/keys/{keyName}/signature:compute
//
// This is NOT a real signature: generating one would need actual RSA/ECDSA
// private-key math (bignum modular exponentiation or elliptic-curve point
// operations), which is out of scope for a mock with no real key material.
// Instead it returns shape-correct, deterministic fake data (same input ->
// same output) so the calling side's wiring — request/response parsing,
// field extraction — can be tested without a real signing backend behind it.
// The "mechanism" value mirrors the example in the API spec verbatim.
(function mockRsaCompute() {
    var params = mockParsePathParams(context.getVariable('proxy.pathsuffix'), 'signature:compute');
    if (!params) {
        mockSendError(400, 'invalid_argument', 'Path does not match /scopes/{scope}/keys/{keyName}/signature:compute');
        return;
    }

    var body = mockParseJsonBody();
    if (body === undefined) {
        mockSendError(400, 'invalid_argument', 'Request body is not valid JSON.');
        return;
    }
    if (!body || typeof body.hash !== 'string' || typeof body.algorithm !== 'string') {
        mockSendError(400, 'invalid_argument', '"hash" and "algorithm" (strings) are required in the request body.');
        return;
    }

    var seed = params.scope + ':' + params.keyName + ':' + body.algorithm + ':' + body.hash;
    var fakeM = base64Encode(sha256Bytes(utf8ToByteString(seed + ':m')));
    var fakeR = base64Encode(sha256Bytes(utf8ToByteString(seed + ':r')));
    var fakeS = base64Encode(sha256Bytes(utf8ToByteString(seed + ':s')));

    mockSendJson(200, {
        mechanism: 'ECDSAhSHA256',
        signature: { m: fakeM, r: fakeR, s: fakeS }
    });
})();
