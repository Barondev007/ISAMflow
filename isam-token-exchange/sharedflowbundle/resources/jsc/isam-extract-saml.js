/*
 * ISAM token exchange - extract the SAML assertion and its attributes.
 *
 * Expects an RFC 8693 JSON response whose access_token holds the SAML assertion,
 * base64 / base64url encoded or as raw XML.
 *
 * Outputs:
 *   isam.token              access_token as returned by ISAM
 *   isam.saml.assertion     SAML assertion (XML)
 *   isam.saml.clientId      value of the SAML attribute "clientId"
 *   isam.saml.permissions   value of the SAML attribute "permissions"
 *                           (CLIENT_SCOPES=a,b;SIGNED_SCOPES=c,d)
 *   isam.failed / isam.failure.reason
 */

var BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// Rhino has no atob: decode base64 / base64url to a UTF-8 string.
function decodeBase64(value) {
    var input = String(value).replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+\/]/g, '');
    var bytes = '';
    var buffer = 0;
    var bits = 0;
    for (var i = 0; i < input.length; i++) {
        buffer = (buffer << 6) | BASE64.indexOf(input.charAt(i));
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes += String.fromCharCode((buffer >> bits) & 0xff);
        }
    }
    return decodeURIComponent(escape(bytes));
}

function decodeXml(value) {
    return value
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&amp;/g, '&');
}

// Returns the first AttributeValue of the SAML attribute with this Name, whatever the namespace prefix.
function samlAttribute(assertion, name) {
    var pattern = new RegExp(
        '<(?:\\w+:)?Attribute\\b[^>]*\\bName\\s*=\\s*"' + name + '"[^>]*>[\\s\\S]*?' +
        '<(?:\\w+:)?AttributeValue\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?AttributeValue>');
    var match = pattern.exec(assertion);
    return match ? decodeXml(match[1].trim()) : '';
}

function fail(reason) {
    context.setVariable('isam.failed', 'true');
    context.setVariable('isam.failure.reason', reason);
}

function extract() {
    if (String(context.getVariable('servicecallout.SC-ISAM-Token-Exchange.failed')) === 'true') {
        return fail('ISAM call failed');
    }
    var status = parseInt(context.getVariable('isamResponse.status.code'), 10);
    if (isNaN(status) || status < 200 || status > 299) {
        return fail('ISAM returned HTTP ' + status);
    }

    var body;
    try {
        body = JSON.parse(context.getVariable('isamResponse.content'));
    } catch (e) {
        return fail('ISAM response is not valid JSON');
    }
    var token = body && body.access_token ? String(body.access_token).trim() : '';
    if (!token) {
        return fail('ISAM response has no access_token');
    }
    context.setVariable('isam.token', token);

    var assertion;
    try {
        assertion = token.charAt(0) === '<' ? token : decodeBase64(token);
    } catch (e) {
        return fail('SAML assertion cannot be decoded');
    }
    context.setVariable('isam.saml.assertion', assertion);

    var clientId = samlAttribute(assertion, 'clientId');
    if (!clientId) {
        return fail('SAML assertion has no clientId attribute');
    }
    context.setVariable('isam.saml.clientId', clientId);
    context.setVariable('isam.saml.permissions', samlAttribute(assertion, 'permissions'));
}

extract();
