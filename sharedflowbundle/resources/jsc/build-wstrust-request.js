// JS-Build-WSTrust-Request
//
// Reads the ISAM host/config JSON retrieved from KVM (KVM-Get-ISAMConfig) plus
// attributes off the inbound request, and builds a WS-Trust 1.3 RequestSecurityToken
// (RST) SOAP envelope to send to ISAM. Static attributes come from the KVM config;
// dynamic attributes (bearer token, client IP, client certificate, user agent) come
// from the inbound request.
//
// Outputs:
//   isam.config.valid            boolean
//   isam.config.host1/host2/...  individual config fields (for RaiseFault messages, logging)
//   wstrust.bearer.present       boolean
//   wstrust.request.payload      the SOAP XML to POST to ISAM
//   wstrust.message.id           correlation id used as wsa:MessageID
//   wstrust.target.url.primary   full URL for the primary ISAM host
//   wstrust.target.url.secondary full URL for the secondary ISAM host

function xmlEscape(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

// Manual base64 encoder so this works regardless of whether the JS engine
// exposes Buffer/btoa (Apigee's JS runtime has varied across versions).
function base64Encode(input) {
    var keyStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;
    input = utf8Encode(input);
    while (i < input.length) {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = isNaN(chr2) ? 64 : ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = isNaN(chr2) || isNaN(chr3) ? 64 : chr3 & 63;
        output += keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
    }
    return output;
}

function utf8Encode(str) {
    var out = '';
    for (var n = 0; n < str.length; n++) {
        var c = str.charCodeAt(n);
        if (c < 128) {
            out += String.fromCharCode(c);
        } else if (c > 127 && c < 2048) {
            out += String.fromCharCode((c >> 6) | 192);
            out += String.fromCharCode((c & 63) | 128);
        } else {
            out += String.fromCharCode((c >> 12) | 224);
            out += String.fromCharCode(((c >> 6) & 63) | 128);
            out += String.fromCharCode((c & 63) | 128);
        }
    }
    return out;
}

function newMessageId() {
    // RFC4122-ish v4 UUID for correlation only, not a security token.
    var d = new Date().getTime();
    var uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (d + Math.random() * 16) % 16 | 0;
        d = Math.floor(d / 16);
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
    return uuid;
}

// ---- 1. Load + validate KVM config ----------------------------------------

var rawConfig = context.getVariable('isam.config.raw');
var config = null;
try {
    if (rawConfig) {
        config = JSON.parse(rawConfig);
    }
} catch (e) {
    config = null;
}

var requiredFields = ['host1', 'host2', 'port', 'scheme', 'path', 'appliesTo', 'tokenType', 'keyType', 'requestType'];
var configValid = !!config;
if (configValid) {
    for (var i = 0; i < requiredFields.length; i++) {
        if (!config[requiredFields[i]]) {
            configValid = false;
            break;
        }
    }
}

context.setVariable('isam.config.valid', configValid);
if (!configValid) {
    // RF-ISAM-Config-Missing picks this flow up; stop building the request.
    context.setVariable('isam.config.host1', config && config.host1 ? config.host1 : '');
    context.setVariable('isam.config.host2', config && config.host2 ? config.host2 : '');
    return;
}

context.setVariable('isam.config.host1', config.host1);
context.setVariable('isam.config.host2', config.host2);
context.setVariable('isam.config.connectTimeoutMs', config.connectTimeoutMs || '5000');
context.setVariable('isam.config.ioTimeoutMs', config.ioTimeoutMs || '10000');

var primaryUrl = config.scheme + '://' + config.host1 + ':' + config.port + config.path;
var secondaryUrl = config.scheme + '://' + config.host2 + ':' + config.port + config.path;
context.setVariable('wstrust.target.url.primary', primaryUrl);
context.setVariable('wstrust.target.url.secondary', secondaryUrl);

// ---- 2. Pull dynamic attributes off the inbound request --------------------

var authHeader = context.getVariable('request.header.Authorization') || '';
var bearerMatch = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
var bearerToken = bearerMatch ? bearerMatch[1].trim() : '';
context.setVariable('wstrust.bearer.present', !!bearerToken);
if (!bearerToken) {
    // RF-Missing-Bearer-Token picks this flow up.
    return;
}

var clientIp = context.getVariable('client.ip') || context.getVariable('request.header.X-Forwarded-For') || '';
if (clientIp.indexOf(',') !== -1) {
    clientIp = clientIp.split(',')[0].trim();
}

var userAgent = context.getVariable('request.header.User-Agent') || '';

// Client certificate: when Apigee terminates mTLS at an upstream LB/NGINX,
// the cert is typically forwarded as a URL-encoded PEM in a header. The
// header name is configurable via KVM (config.clientCertHeader) so this
// can be aligned with whatever the network team actually forwards.
var certHeaderName = config.clientCertHeader || 'X-Client-Cert';
var rawClientCert = context.getVariable('request.header.' + certHeaderName) || '';
var clientCertPresent = !!rawClientCert;
var clientCertB64 = '';
if (clientCertPresent) {
    try {
        var decoded = decodeURIComponent(rawClientCert);
        var pemBody = decoded
            .replace('-----BEGIN CERTIFICATE-----', '')
            .replace('-----END CERTIFICATE-----', '')
            .replace(/\r?\n/g, '')
            .trim();
        // If it wasn't PEM to begin with, pemBody === decoded (already base64/DER-ish); pass through.
        clientCertB64 = pemBody || decoded;
    } catch (e) {
        clientCertPresent = false;
    }
}
context.setVariable('wstrust.clientcert.present', clientCertPresent);

var messageId = newMessageId();
context.setVariable('wstrust.message.id', messageId);

// ---- 3. Build the AdditionalContext block (optional items only when present) ----

var contextItems = '';
contextItems += '      <wsc:ContextItem Name="ip"><wsc:Value>' + xmlEscape(clientIp) + '</wsc:Value></wsc:ContextItem>\n';
if (userAgent) {
    contextItems += '      <wsc:ContextItem Name="userAgent"><wsc:Value>' + xmlEscape(userAgent) + '</wsc:Value></wsc:ContextItem>\n';
}
if (clientCertPresent) {
    contextItems += '      <wsc:ContextItem Name="clientCertificate"><wsc:Value>' + xmlEscape(clientCertB64) + '</wsc:Value></wsc:ContextItem>\n';
}

var onBehalfOfB64 = base64Encode(bearerToken);

// ---- 4. Assemble the WS-Trust RST SOAP envelope -----------------------------

var payload =
    '<soapenv:Envelope xmlns:soapenv="http://www.w3.org/2003/05/soap-envelope"\n' +
    '                   xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"\n' +
    '                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"\n' +
    '                   xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"\n' +
    '                   xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"\n' +
    '                   xmlns:wsc="http://schemas.xmlsoap.org/ws/2006/12/authorization"\n' +
    '                   xmlns:wsa="http://www.w3.org/2005/08/addressing">\n' +
    '  <soapenv:Header>\n' +
    '    <wsa:Action>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action>\n' +
    '    <wsa:MessageID>urn:uuid:' + messageId + '</wsa:MessageID>\n' +
    '    <wsse:Security soapenv:mustUnderstand="1">\n' +
    '      <wsse:BinarySecurityToken wsu:Id="bearerToken"\n' +
    '          ValueType="urn:ietf:params:oauth:token-type:jwt"\n' +
    '          EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' +
    xmlEscape(onBehalfOfB64) +
    '</wsse:BinarySecurityToken>\n' +
    '    </wsse:Security>\n' +
    '  </soapenv:Header>\n' +
    '  <soapenv:Body>\n' +
    '    <wst:RequestSecurityToken>\n' +
    '      <wst:RequestType>' + xmlEscape(config.requestType) + '</wst:RequestType>\n' +
    '      <wst:TokenType>' + xmlEscape(config.tokenType) + '</wst:TokenType>\n' +
    '      <wst:KeyType>' + xmlEscape(config.keyType) + '</wst:KeyType>\n' +
    '      <wsp:AppliesTo>\n' +
    '        <wsa:EndpointReference>\n' +
    '          <wsa:Address>' + xmlEscape(config.appliesTo) + '</wsa:Address>\n' +
    '        </wsa:EndpointReference>\n' +
    '      </wsp:AppliesTo>\n' +
    '      <wst:OnBehalfOf>\n' +
    '        <wsse:BinarySecurityToken\n' +
    '            ValueType="urn:ietf:params:oauth:token-type:jwt"\n' +
    '            EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' +
    xmlEscape(onBehalfOfB64) +
    '</wsse:BinarySecurityToken>\n' +
    '      </wst:OnBehalfOf>\n' +
    '      <wst:AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">\n' +
    contextItems +
    '      </wst:AdditionalContext>\n' +
    '    </wst:RequestSecurityToken>\n' +
    '  </soapenv:Body>\n' +
    '</soapenv:Envelope>';

context.setVariable('wstrust.request.payload', payload);
