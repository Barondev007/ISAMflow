// Mocks POST /scopes/{scope}/keys/{keyName}/hmacs:verify — always a
// dummy response, no real verification. Set X-Mock-Fail: true to get
// the failure branch instead.
(function mockHmacVerify() {
    if (mockShouldFail()) {
        mockSendError(400, 'mock_hmac_verify_failure', 'Simulated hmacs:verify failure (X-Mock-Fail).');
        return;
    }
    mockSendJson(200, { valid: 'true' });
})();
