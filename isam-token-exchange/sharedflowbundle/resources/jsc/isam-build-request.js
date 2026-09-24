/*
 * ISAM token exchange (type5-jwt-saml) - build the application/x-www-form-urlencoded body.
 *
 * isam.input.subjectTokenType selects the subject token:
 *   stsuu         end-user call: principal = userId
 *   access-token  technical call: principal = TECHNICAL-USER, bearer token + client certificate
 *
 * Inputs (FlowCallout parameters):
 *   common        isam.input.distributorId, isam.input.authenticationMeanId, isam.input.ipAddress,
 *                 isam.input.userAgent, isam.input.xLogId
 *   stsuu         isam.input.userId, isam.input.dacLevel (default "3")
 *   access-token  isam.input.accessToken, isam.input.requestCtxEnv,
 *                 isam.input.certificateDn, isam.input.certificate
 *
 * Outputs: isam.request.body, or isam.failed / isam.failure.reason
 */

var SUBJECT_TOKEN_TYPES = {
    'stsuu': 'urn:bnppf:json:stsuu',
    'access-token': 'urn:bnppf:json:access-token'
};
var GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
var REQUESTED_TOKEN_TYPE = 'urn:bnppf:saml:tech';
var AUDIENCE = 'urn:bnppf:b2b';
var REQUESTOR_TYPE = 'External_application';

function input(name) {
    var value = context.getVariable('isam.input.' + name);
    return value === null || value === undefined ? '' : String(value).trim();
}

function fail(reason) {
    context.setVariable('isam.failed', 'true');
    context.setVariable('isam.failure.reason', reason);
}

function stsuuSubjectToken() {
    return {
        attributes: {
            'authenticationMeanId': input('authenticationMeanId'),
            'distributorId': input('distributorId'),
            'dacLevel': input('dacLevel') || '3',
            'ip-address': input('ipAddress'),
            'requestorType': REQUESTOR_TYPE,
            'user-agent': input('userAgent'),
            'xLogId': input('xLogId')
        },
        principal: input('userId')
    };
}

function accessTokenSubjectToken() {
    return {
        principal: 'TECHNICAL-USER',
        attributes: {
            'distributorId': input('distributorId'),
            'ipAddress': input('ipAddress'),
            'userAgent': input('userAgent'),
            'authenticationMeanId': input('authenticationMeanId'),
            'xLogId': input('xLogId'),
            'requestorType': REQUESTOR_TYPE
        },
        contextAttributes: {
            'access_token': input('accessToken').replace(/^Bearer\s+/i, ''),
            'request-ctx-env': input('requestCtxEnv'),
            'request-ctx-cert-dn': input('certificateDn'),
            'request-ctx-cert': encodeURIComponent(input('certificate'))
        }
    };
}

function missing(names) {
    for (var i = 0; i < names.length; i++) {
        if (!input(names[i])) {
            return names[i];
        }
    }
    return null;
}

function formEncode(params) {
    var parts = [];
    for (var i = 0; i < params.length; i++) {
        parts.push(encodeURIComponent(params[i][0]) + '=' + encodeURIComponent(params[i][1]));
    }
    return parts.join('&');
}

function build() {
    var type = input('subjectTokenType').toLowerCase();
    if (!SUBJECT_TOKEN_TYPES.hasOwnProperty(type)) {
        return fail('unknown subject token type: ' + type);
    }
    var absent = type === 'stsuu' ?
        missing(['userId']) :
        missing(['accessToken', 'certificate', 'certificateDn']);
    if (absent) {
        return fail(absent + ' is missing for subject token type ' + type);
    }
    var subjectToken = type === 'stsuu' ? stsuuSubjectToken() : accessTokenSubjectToken();
    context.setVariable('isam.request.body', formEncode([
        ['subject_token', JSON.stringify(subjectToken)],
        ['subject_token_type', SUBJECT_TOKEN_TYPES[type]],
        ['grant_type', GRANT_TYPE],
        ['requested_token_type', REQUESTED_TOKEN_TYPE],
        ['audience', AUDIENCE]
    ]));
}

context.setVariable('isam.failed', 'false');
build();
