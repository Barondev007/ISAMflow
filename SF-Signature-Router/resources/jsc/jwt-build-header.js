// Builds the JOSE header for the current proxy from its KVM template
// (signature.jwt.header.template, see KVM-Get-JWT-Header-Template) and
// produces the JWS signing string: base64url(header) + "." + base64url(payload).
//
// Header template values containing "${flowVariableName}" are resolved
// against Apigee flow variables (calculated attributes); any other
// string is used as-is (static attributes). signature.jwt.iat, .exp and
// .jti are auto-populated with sensible defaults when not already set,
// so a template can reference them without the calling proxy having to
// compute them itself.

function resolveTemplateValue(value) {
    if (typeof value !== 'string') {
        return value;
    }
    return value.replace(/\$\{([^}]+)\}/g, function (match, varName) {
        var resolved = context.getVariable(varName);
        if (resolved === null || resolved === undefined) {
            throw new Error('JOSE header template references unresolved variable: ' + varName);
        }
        return resolved;
    });
}

// RFC 7515 §4.1.11: "crit" lists the names of extension header
// parameters the header uses that a verifier MUST understand. Every
// name it lists has to actually be present in the header, and it must
// not list itself.
function validateCrit(header) {
    var crit = header.crit;
    if (crit === undefined) {
        return;
    }
    if (!(crit instanceof Array) || crit.length === 0) {
        throw new Error('JOSE header "crit" must be a non-empty array of header parameter names.');
    }
    for (var i = 0; i < crit.length; i++) {
        var name = crit[i];
        if (name === 'crit') {
            throw new Error('JOSE header "crit" must not list itself.');
        }
        if (!header.hasOwnProperty(name) || header[name] === undefined) {
            throw new Error('JOSE header "crit" lists "' + name + '" but no such header parameter is present.');
        }
    }
}

(function buildJwtSigningString() {
    // 1) Calculated claims: reuse if the calling proxy already set them,
    //    otherwise compute sensible defaults.
    var iat = context.getVariable('signature.jwt.iat');
    if (!iat) {
        iat = Math.floor(new Date().getTime() / 1000);
        context.setVariable('signature.jwt.iat', iat);
    }

    var jti = context.getVariable('signature.jwt.jti');
    if (!jti) {
        jti = generateUUIDv4();
        context.setVariable('signature.jwt.jti', jti);
    }

    var exp = context.getVariable('signature.jwt.exp');
    if (!exp) {
        var ttlSeconds = context.getVariable('signature.jwt.ttlSeconds');
        ttlSeconds = ttlSeconds ? parseInt(ttlSeconds, 10) : 300;
        exp = parseInt(iat, 10) + ttlSeconds;
        context.setVariable('signature.jwt.exp', exp);
    }

    // 2) Parse the per-proxy header template loaded from KVM.
    var templateJson = context.getVariable('signature.jwt.header.template');
    var template = JSON.parse(templateJson);

    // 3) Resolve every attribute: "${var}" -> calculated, anything else -> static.
    var header = {};
    for (var key in template) {
        if (template.hasOwnProperty(key)) {
            header[key] = resolveTemplateValue(template[key]);
        }
    }
    if (!header.typ) {
        header.typ = 'JWT';
    }
    validateCrit(header);

    var headerJson = JSON.stringify(header);
    context.setVariable('signature.jwt.header.json', headerJson);

    var headerEncoded = base64UrlEncode(headerJson);
    context.setVariable('signature.jwt.header.encoded', headerEncoded);

    // 4) Payload: whatever the calling proxy staged in signature.payload,
    //    otherwise the current message body.
    var payload = context.getVariable('signature.payload');
    if (payload === null || payload === undefined || payload === '') {
        payload = context.getVariable('message.content') || '';
    }
    context.setVariable('signature.jwt.payload.raw', payload);

    var payloadEncoded = base64UrlEncode(payload);
    context.setVariable('signature.jwt.payload.encoded', payloadEncoded);

    // 5) The JWS signing input, ready for the (not-yet-implemented) call
    //    to the signature API in NI-Signature-JWT-Sign.
    context.setVariable('signature.jwt.signing.string', headerEncoded + '.' + payloadEncoded);
})();
