// Runs AFTER VerifyJWS has already confirmed the signature is
// cryptographically valid. Decodes the JOSE header (the header segment
// is always the first "."-delimited part, whether the JWS is compact or
// detached) and explicitly enforces RFC 7515 §4.1.11's "crit" rule: if
// present, it must be a non-empty array, must not list itself, and every
// name in it must (a) actually be present as a header parameter and
// (b) be one this proxy has been told it understands.
//
// This exists because VerifyJWS is a generic policy with no way to know
// what an application-specific extension like "x-txn-id" means — rather
// than assume (either way) whether it enforces "crit" per spec, this
// enforces it ourselves so the outcome doesn't depend on undocumented
// native behavior. signature.verify.jwt.understood.crit.json (a JSON
// array) comes from this proxy's KVM config — see
// JS-JWT-Verify-Parse-Config.

(function checkCrit() {
    var jws = context.getVariable('signature.verify.jwt.jws');
    if (!jws) {
        throw new Error('signature.verify.jwt.jws is not set.');
    }

    var headerSegment = jws.split('.')[0];
    var headerJson = byteStringToUtf8(base64Decode(headerSegment));
    var header = JSON.parse(headerJson);
    context.setVariable('signature.verify.jwt.decoded.header.json', headerJson);

    if (header.crit === undefined) {
        return;
    }
    if (!(header.crit instanceof Array) || header.crit.length === 0) {
        throw new Error('JOSE header "crit" must be a non-empty array.');
    }

    var understoodJson = context.getVariable('signature.verify.jwt.understood.crit.json');
    var understood = understoodJson ? JSON.parse(understoodJson) : [];

    for (var i = 0; i < header.crit.length; i++) {
        var name = header.crit[i];
        if (name === 'crit') {
            throw new Error('JOSE header "crit" must not list itself.');
        }
        if (header[name] === undefined) {
            throw new Error('JOSE header "crit" lists "' + name + '" but no such header parameter is present.');
        }
        if (understood.indexOf(name) === -1) {
            throw new Error('JOSE header "crit" lists "' + name + '", which this proxy does not understand — rejecting per RFC 7515 4.1.11.');
        }
    }
})();
