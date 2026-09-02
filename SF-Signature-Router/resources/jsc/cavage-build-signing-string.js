// Builds the HTTP Signature (draft-cavage-http-signatures) signing
// string for the current REQUEST from the per-proxy header list loaded
// from KVM (signature.cavage.headers.template, see
// KVM-Get-Cavage-Headers-Template): for each name, one line
// "lowercase(name): value", joined by "\n" (no trailing newline).
//
// (created) / (expires) auto-populate signature.cavage.created / .expires
// with sensible defaults when not already set. "digest", if listed, is
// computed (SHA-256 of the body) and set as the request's Digest header
// when the request doesn't already carry one. Every other name must be
// an actual request header.
//
// Scope: this builds the signing string for the current request only
// (uses request.verb / request.uri / request.header.*) — response
// signing isn't implemented.

(function buildCavageSigningString() {
    // 1) Calculated pseudo-header values: reuse if the calling proxy
    //    already set them, otherwise compute sensible defaults.
    var created = context.getVariable('signature.cavage.created');
    if (!created) {
        created = Math.floor(new Date().getTime() / 1000);
        context.setVariable('signature.cavage.created', created);
    }

    var expires = context.getVariable('signature.cavage.expires');
    if (!expires) {
        var ttlSeconds = context.getVariable('signature.cavage.ttlSeconds');
        ttlSeconds = ttlSeconds ? parseInt(ttlSeconds, 10) : 300;
        expires = parseInt(created, 10) + ttlSeconds;
        context.setVariable('signature.cavage.expires', expires);
    }

    // 2) Parse the per-proxy ordered header list loaded from KVM.
    var templateJson = context.getVariable('signature.cavage.headers.template');
    var headerNames = JSON.parse(templateJson);
    if (!(headerNames instanceof Array) || headerNames.length === 0) {
        throw new Error('Cavage headers template must be a non-empty JSON array of header names.');
    }

    // 3) "digest": reuse the existing request Digest header if present,
    //    otherwise compute SHA-256 of the body. Kept in a local var
    //    (not round-tripped through setVariable+getVariable) so this
    //    doesn't depend on header-name case handling.
    var digestForSigning = null;
    for (var i = 0; i < headerNames.length; i++) {
        if (headerNames[i].toLowerCase() === 'digest') {
            digestForSigning = context.getVariable('request.header.digest');
            if (!digestForSigning) {
                var payload = context.getVariable('signature.payload');
                if (payload === null || payload === undefined || payload === '') {
                    payload = context.getVariable('request.content') || '';
                }
                digestForSigning = 'SHA-256=' + base64Encode(sha256Bytes(utf8ToByteString(payload)));
                context.setVariable('request.header.Digest', digestForSigning);
            }
            break;
        }
    }

    // 4) Resolve each header line, in the configured order.
    var lines = [];
    for (var idx = 0; idx < headerNames.length; idx++) {
        var name = headerNames[idx].toLowerCase();
        var value;
        if (name === '(request-target)') {
            value = context.getVariable('request.verb').toLowerCase() + ' ' + context.getVariable('request.uri');
        } else if (name === '(created)') {
            value = created;
        } else if (name === '(expires)') {
            value = expires;
        } else if (name === 'digest') {
            value = digestForSigning;
        } else {
            value = context.getVariable('request.header.' + name);
            if (value === null || value === undefined) {
                throw new Error('Cavage signing header template references "' + name + '" but the request has no such header.');
            }
        }
        lines.push(name + ': ' + value);
    }

    context.setVariable('signature.cavage.headers.list', headerNames.join(' '));
    context.setVariable('signature.cavage.signing.string', lines.join('\n'));
})();
