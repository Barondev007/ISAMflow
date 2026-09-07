// Mocks POST /scopes/{scope}/keys/{keyName}/hmacs:verify
(function mockHmacVerify() {
    var params = mockParsePathParams(context.getVariable('proxy.pathsuffix'), 'hmacs:verify');
    if (!params) {
        mockSendError(400, 'invalid_argument', 'Path does not match /scopes/{scope}/keys/{keyName}/hmacs:verify');
        return;
    }

    var body = mockParseJsonBody();
    if (body === undefined) {
        mockSendError(400, 'invalid_argument', 'Request body is not valid JSON.');
        return;
    }
    if (!body || typeof body.message !== 'string' || typeof body.hmac !== 'string') {
        mockSendError(400, 'invalid_argument', '"message" and "hmac" (strings) are required in the request body.');
        return;
    }

    var key = mockDeriveHmacKey(params.scope, params.keyName);
    var expected = base64Encode(hmacSha256Bytes(key, utf8ToByteString(body.message)));

    mockSendJson(200, { valid: expected === body.hmac ? 'true' : 'false' });
})();
