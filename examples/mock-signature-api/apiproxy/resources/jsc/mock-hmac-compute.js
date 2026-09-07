// Mocks POST /scopes/{scope}/keys/{keyName}/hmacs:compute — always a
// dummy response, no real computation. Set X-Mock-Fail: true to get the
// failure branch instead.
(function mockHmacCompute() {
    if (mockShouldFail()) {
        mockSendError(400, 'mock_hmac_compute_failure', 'Simulated hmacs:compute failure (X-Mock-Fail).');
        return;
    }
    mockSendJson(200, { hmac: 'MOCK-HMAC-VALUE' });
})();
