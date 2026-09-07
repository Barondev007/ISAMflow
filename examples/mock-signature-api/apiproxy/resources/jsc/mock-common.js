// Shared helpers for the mock signing-service endpoints.

function mockSendJson(statusCode, obj) {
    context.setVariable('response.status.code', statusCode);
    context.setVariable('response.header.Content-Type', 'application/json');
    context.setVariable('response.content', JSON.stringify(obj));
}

function mockSendError(statusCode, code, message) {
    mockSendJson(statusCode, { code: code, message: message });
}

// Set the X-Mock-Fail request header to the string "true" to force
// whichever mock endpoint is called to return its failure response
// instead of its dummy success one — for testing the caller's error
// handling without needing a real backend failure.
function mockShouldFail() {
    return context.getVariable('request.header.X-Mock-Fail') === 'true';
}
