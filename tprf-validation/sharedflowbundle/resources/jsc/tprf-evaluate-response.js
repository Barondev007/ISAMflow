/*
 * TPRF validation - step 2: evaluate the certificate-validation response.
 *
 * The TPP is authorized when:
 *   - TPRF answered 2xx with certificateFound = "Y", and
 *   - the clientApplicationList entry of our clientId holds at least one
 *     scopeName that is part of tprf.requested.scopes.
 *
 * Outputs:
 *   tprf.authorized          "true" or "false"
 *   tprf.granted.scopes      requested scopes confirmed by TPRF
 *   tprf.thirdPartyId        thirdPartyId returned by TPRF
 *   tprf.failure.reason      set when not authorized
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

function reject(reason) {
    context.setVariable('tprf.authorized', 'false');
    context.setVariable('tprf.failure.reason', reason);
}

function evaluate() {
    if (String(context.getVariable('servicecallout.SC-TPRF-Certificate-Validation.failed')) === 'true') {
        return reject('TPRF call failed');
    }

    var status = parseInt(context.getVariable('tprfResponse.status.code'), 10);
    if (isNaN(status) || status < 200 || status > 299) {
        return reject('TPRF returned HTTP ' + status);
    }

    var body;
    try {
        body = JSON.parse(context.getVariable('tprfResponse.content'));
    } catch (e) {
        return reject('TPRF response is not valid JSON');
    }
    if (!body) {
        return reject('TPRF response is empty');
    }

    context.setVariable('tprf.thirdPartyId', body.thirdPartyId ? String(body.thirdPartyId) : '');

    if (String(body.certificateFound).toUpperCase() !== 'Y') {
        return reject('certificate not found in TPRF');
    }

    var clientId = String(context.getVariable('tprf.input.clientId'));
    var applications = body.clientApplicationList || [];
    var application = null;
    for (var i = 0; i < applications.length; i++) {
        if (applications[i] && String(applications[i].clientId) === clientId) {
            application = applications[i];
            break;
        }
    }
    if (!application) {
        return reject('clientId not linked to the certificate in TPRF');
    }

    var requested = splitScopes(context.getVariable('tprf.requested.scopes'));
    var scopeList = application.clientApplicationScopeList || [];
    var granted = [];
    for (var j = 0; j < scopeList.length; j++) {
        var name = scopeList[j] && scopeList[j].scopeName;
        if (name && requested.indexOf(String(name)) !== -1 && granted.indexOf(String(name)) === -1) {
            granted.push(String(name));
        }
    }
    context.setVariable('tprf.granted.scopes', granted.join(','));

    if (granted.length === 0) {
        return reject('no requested scope granted by TPRF');
    }
    context.setVariable('tprf.authorized', 'true');
}

context.setVariable('tprf.authorized', 'false');
evaluate();
