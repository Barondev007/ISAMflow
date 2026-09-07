// Mocks POST /scopes/{scope}/keys/{keyName}/signature:compute — always a
// dummy response, no real signing. Set X-Mock-Fail: true to get the
// failure branch instead.
(function mockRsaCompute() {
    if (mockShouldFail()) {
        mockSendError(400, 'mock_signature_compute_failure', 'Simulated signature:compute failure (X-Mock-Fail).');
        return;
    }
    mockSendJson(200, {
        mechanism: 'ECDSAhSHA256',
        signature: { m: 'MOCK-M-VALUE', r: 'MOCK-R-VALUE', s: 'MOCK-S-VALUE' }
    });
})();
