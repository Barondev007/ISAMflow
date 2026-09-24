/*
 * TPRF validation - step 1: prepare the certificate-validation request.
 *
 * Inputs (set by the FlowCallout parameters of the calling proxy):
 *   tprf.input.certificate   client certificate, PEM or base64 DER
 *   tprf.input.clientId      clientId from the ISAM SAML assertion
 *   tprf.input.permissions   SAML "permissions" attribute:
 *                            CLIENT_SCOPES=a,b;SIGNED_SCOPES=c,d
 *   tprf.input.methodScopes  comma-separated scopes of the called method (KVM)
 *
 * Outputs:
 *   tprf.request.body        JSON body sent to TPRF
 *   tprf.requested.scopes    method scopes also present in SIGNED_SCOPES
 *   tprf.client.scopes / tprf.signed.scopes   parsed permissions (for logging)
 *   tprf.failed / tprf.failure.reason         set when the request cannot be built
 */

function splitScopes(value) {
    var result = [];
    if (!value) {
        return result;
    }
    var parts = String(value).split(',');
    for (var i = 0; i < parts.length; i++) {
        var scope = parts[i].trim();
        if (scope && result.indexOf(scope) === -1) {
            result.push(scope);
        }
    }
    return result;
}

function parsePermissions(value) {
    var permissions = { CLIENT_SCOPES: [], SIGNED_SCOPES: [] };
    if (!value) {
        return permissions;
    }
    var entries = String(value).split(';');
    for (var i = 0; i < entries.length; i++) {
        var separator = entries[i].indexOf('=');
        if (separator === -1) {
            continue;
        }
        var name = entries[i].substring(0, separator).trim().toUpperCase();
        if (permissions.hasOwnProperty(name)) {
            permissions[name] = splitScopes(entries[i].substring(separator + 1));
        }
    }
    return permissions;
}

// Accepts a PEM certificate or a base64 DER string and returns base64 DER on one line.
function normalizeCertificate(value) {
    if (!value) {
        return '';
    }
    return String(value)
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
}

function intersect(left, right) {
    var result = [];
    for (var i = 0; i < left.length; i++) {
        if (right.indexOf(left[i]) !== -1) {
            result.push(left[i]);
        }
    }
    return result;
}

function fail(reason) {
    context.setVariable('tprf.failed', 'true');
    context.setVariable('tprf.failure.reason', reason);
}

var certificate = normalizeCertificate(context.getVariable('tprf.input.certificate'));
var clientId = context.getVariable('tprf.input.clientId');
var permissions = parsePermissions(context.getVariable('tprf.input.permissions'));
var methodScopes = splitScopes(context.getVariable('tprf.input.methodScopes'));
var requestedScopes = intersect(methodScopes, permissions.SIGNED_SCOPES);

context.setVariable('tprf.failed', 'false');
context.setVariable('tprf.client.scopes', permissions.CLIENT_SCOPES.join(','));
context.setVariable('tprf.signed.scopes', permissions.SIGNED_SCOPES.join(','));
context.setVariable('tprf.requested.scopes', requestedScopes.join(','));

if (!certificate) {
    fail('client certificate is missing');
} else if (!clientId) {
    fail('clientId is missing from the SAML assertion');
} else if (methodScopes.length === 0) {
    fail('no scope configured in the KVM for this method');
} else if (requestedScopes.length === 0) {
    fail('none of the method scopes was granted in SIGNED_SCOPES');
} else {
    context.setVariable('tprf.request.body', JSON.stringify({
        identifierValueBinary: certificate,
        clientId: String(clientId),
        scopesAbbreviationList: requestedScopes
    }));
}
