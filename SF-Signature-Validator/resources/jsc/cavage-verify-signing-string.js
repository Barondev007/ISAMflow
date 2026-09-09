// Parses the incoming HTTP Signature (draft-cavage-http-signatures)
// header, rebuilds the signing string from the CURRENT request per the
// headers list the signer claims to have used, and checks
// (expires)/expiry — all things verifiable without real crypto. Stages
// everything the actual cryptographic check needs (still a placeholder
// — see NI-Cavage-Verify-Signature) into signature.verify.cavage.*.
//
// Scope: verifies the current request's own signature (same
// request-scoped design as the signing side) — response signing isn't
// implemented.

function cavageParseSignatureHeader(headerValue) {
    var params = {};
    // Matches both quoted-string params (keyId="...") and bare numeric
    // ones (created=1700000000), per draft-cavage-http-signatures §2.1.
    var re = /(\w+)=(?:"([^"]*)"|([^,\s]*))/g;
    var m;
    while ((m = re.exec(headerValue)) !== null) {
        params[m[1]] = m[2] !== undefined ? m[2] : m[3];
    }
    return params;
}

(function verifyCavageSigningString() {
    var headerName = context.getVariable('signature.verify.cavage.header.name');
    if (!headerName) {
        headerName = 'Signature';
        context.setVariable('signature.verify.cavage.header.name', headerName);
    }

    var headerValue = context.getVariable('request.header.' + headerName);
    if (!headerValue) {
        throw new Error('No HTTP signature found in request header "' + headerName + '".');
    }

    var params = cavageParseSignatureHeader(headerValue);
    if (!params.headers || !params.algorithm || !params.signature) {
        throw new Error('HTTP signature header "' + headerName + '" is missing keyId/algorithm/headers/signature.');
    }

    context.setVariable('signature.verify.cavage.keyId', params.keyId || '');
    context.setVariable('signature.verify.cavage.algorithm', params.algorithm);
    context.setVariable('signature.verify.cavage.headers.list', params.headers);
    context.setVariable('signature.verify.cavage.signature.provided', params.signature);

    if (params.expires) {
        var nowSeconds = Math.floor(new Date().getTime() / 1000);
        if (parseInt(params.expires, 10) < nowSeconds) {
            throw new Error('Signature expired: expires=' + params.expires + ' is in the past.');
        }
    }

    var headerNames = params.headers.split(/\s+/);
    var lines = [];
    for (var i = 0; i < headerNames.length; i++) {
        var name = headerNames[i].toLowerCase();
        var value;
        if (name === '(request-target)') {
            value = context.getVariable('request.verb').toLowerCase() + ' ' + context.getVariable('request.uri');
        } else if (name === '(created)') {
            value = params.created;
            if (value === undefined) {
                throw new Error('Signature header lists "(created)" but has no created param.');
            }
        } else if (name === '(expires)') {
            value = params.expires;
            if (value === undefined) {
                throw new Error('Signature header lists "(expires)" but has no expires param.');
            }
        } else {
            value = context.getVariable('request.header.' + name);
            if (value === null || value === undefined) {
                throw new Error('Signed header "' + name + '" listed in the Signature header is not present on this request.');
            }
        }
        lines.push(name + ': ' + value);
    }

    context.setVariable('signature.verify.cavage.signing.string', lines.join('\n'));
})();
