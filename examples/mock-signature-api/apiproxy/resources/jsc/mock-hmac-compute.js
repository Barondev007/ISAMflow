// Mocks POST /scopes/{scope}/keys/{keyName}/hmacs:compute
(function mockHmacCompute() {
    var params = mockParsePathParams(context.getVariable('proxy.pathsuffix'), 'hmacs:compute');
    if (!params) {
        mockSendError(400, 'invalid_argument', 'Path does not match /scopes/{scope}/keys/{keyName}/hmacs:compute');
        return;
    }

    var body = mockParseJsonBody();
    if (body === undefined) {
        mockSendError(400, 'invalid_argument', 'Request body is not valid JSON.');
        return;
    }
    if (!body || typeof body.message !== 'string') {
        mockSendError(400, 'invalid_argument', '"message" (string) is required in the request body.');
        return;
    }

    var key = mockDeriveHmacKey(params.scope, params.keyName);
    var hmac = base64Encode(hmacSha256Bytes(key, utf8ToByteString(body.message)));

    mockSendJson(200, { hmac: hmac });
})();
