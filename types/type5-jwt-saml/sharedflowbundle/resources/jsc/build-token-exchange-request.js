// Builds the request actually expected by ISAM's JWT-SAML endpoint: NOT a
// JSON body, but application/x-www-form-urlencoded with a subject_token
// field whose value is a JSON *string*, alongside subject_token_type,
// grant_type, requested_token_type and audience as sibling form fields
// (OAuth 2.0 Token Exchange, RFC 8693 shape).
//
// Two variants, chosen by which identity the caller presented -- exactly
// one of the two is guaranteed present by the flow's own
// RF-Missing-Subject-Identity step, which runs before this policy:
//   - bearer token (+ client certificate)  -> "access-token" variant:
//     principal is the fixed "TECHNICAL-USER"; the token and the
//     certificate/DN go in contextAttributes.
//   - X-User-Id header, no bearer token    -> "stsuu" variant:
//     principal is that user ID; no contextAttributes at all.
// The two variants' attribute keys are NOT the same shape (e.g. "ip-address"
// vs "ipAddress") -- that is preserved deliberately, matching the two
// request examples this was built from, rather than homogenized.
//
// Real JSON.stringify()/encodeURIComponent() are used rather than native
// message-template functions: Apigee's message-template functions have no
// URL-encoding function at all, and hand-building nested JSON through an
// XML Payload template is exactly the kind of thing that caused repeated,
// hard-to-diagnose bugs elsewhere in this project (see
// JS-Extract-Client-Cert-Strip for the same reasoning applied to a
// different problem).

var bearerToken = context.getVariable('bearer.token');
var userId = context.getVariable('request.header.X-User-Id');

var subjectToken;
var subjectTokenType;

if (bearerToken) {
    subjectToken = {
        principal: 'TECHNICAL-USER',
        attributes: {
            distributorId: context.getVariable('request.header.X-Distributor-Id'),
            ipAddress: context.getVariable('request.header.X-Forwarded-For'),
            userAgent: context.getVariable('request.header.User-Agent'),
            authenticationMeanId: context.getVariable('request.header.X-Authentication-Mean-Id'),
            xLogId: context.getVariable('request.header.X-B3-TraceId'),
            requestorType: 'External_application'
        },
        contextAttributes: {
            access_token: bearerToken,
            'request-ctx-env': context.getVariable('environment.name'),
            'request-ctx-cert-dn': context.getVariable('isam.client.cert.subject.dn'),
            'request-ctx-cert': context.getVariable('isam.client.cert.base64')
        }
    };
    subjectTokenType = context.getVariable('isam.config.subjectTokenTypeAccessToken');
} else {
    subjectToken = {
        attributes: {
            authenticationMeanId: context.getVariable('request.header.X-Authentication-Mean-Id'),
            distributorId: context.getVariable('request.header.X-Distributor-Id'),
            dacLevel: '3',
            'ip-address': context.getVariable('request.header.X-Forwarded-For'),
            requestorType: 'External_application',
            'user-agent': context.getVariable('request.header.User-Agent'),
            xLogId: context.getVariable('request.header.X-B3-TraceId')
        },
        principal: userId
    };
    subjectTokenType = context.getVariable('isam.config.subjectTokenTypeUserId');
}

var form = 'subject_token=' + encodeURIComponent(JSON.stringify(subjectToken)) +
    '&subject_token_type=' + encodeURIComponent(subjectTokenType) +
    '&grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:token-exchange') +
    '&requested_token_type=' + encodeURIComponent(context.getVariable('isam.config.requestedTokenType')) +
    '&audience=' + encodeURIComponent(context.getVariable('isam.config.audience'));

context.setVariable('isam.tokenexchange.request.body', form);
