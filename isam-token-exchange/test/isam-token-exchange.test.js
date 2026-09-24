// Runs the shared flow JavaScript against a mocked Apigee context: node --test test/isam-token-exchange.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const jsc = path.join(__dirname, '..', 'sharedflowbundle', 'resources', 'jsc');
const buildScript = fs.readFileSync(path.join(jsc, 'isam-build-request.js'), 'utf8');
const extractScript = fs.readFileSync(path.join(jsc, 'isam-extract-saml.js'), 'utf8');

function run(script, variables) {
    const context = {
        getVariable: (name) => (name in variables ? variables[name] : null),
        setVariable: (name, value) => { variables[name] = value; }
    };
    vm.runInNewContext(script, { context });
    return variables;
}

const common = {
    'isam.input.distributorId': '1',
    'isam.input.authenticationMeanId': 'MEAN',
    'isam.input.ipAddress': '10.0.0.1',
    'isam.input.userAgent': 'curl/8',
    'isam.input.xLogId': 'trace-1'
};
const PEM = '-----BEGIN CERTIFICATE-----\nMIIDCC+/=\n-----END CERTIFICATE-----';

function form(body) {
    return Object.fromEntries(new URLSearchParams(body));
}

test('stsuu: form body with userID as principal', () => {
    const vars = run(buildScript, Object.assign({ 'isam.input.subjectTokenType': 'stsuu', 'isam.input.userId': 'U123' }, common));
    assert.strictEqual(vars['isam.failed'], 'false');
    const params = form(vars['isam.request.body']);
    assert.strictEqual(params.subject_token_type, 'urn:bnppf:json:stsuu');
    assert.strictEqual(params.grant_type, 'urn:ietf:params:oauth:grant-type:token-exchange');
    assert.strictEqual(params.requested_token_type, 'urn:bnppf:saml:tech');
    assert.strictEqual(params.audience, 'urn:bnppf:b2b');
    assert.deepStrictEqual(JSON.parse(params.subject_token), {
        attributes: {
            'authenticationMeanId': 'MEAN',
            'distributorId': '1',
            'dacLevel': '3',
            'ip-address': '10.0.0.1',
            'requestorType': 'External_application',
            'user-agent': 'curl/8',
            'xLogId': 'trace-1'
        },
        principal: 'U123'
    });
});

test('access-token: technical user with token and certificate context', () => {
    const vars = run(buildScript, Object.assign({
        'isam.input.subjectTokenType': 'access-token',
        'isam.input.accessToken': 'Bearer abc.def',
        'isam.input.requestCtxEnv': 'dev',
        'isam.input.certificateDn': 'CN=tpp,O=Bank',
        'isam.input.certificate': PEM
    }, common));
    const params = form(vars['isam.request.body']);
    assert.strictEqual(params.subject_token_type, 'urn:bnppf:json:access-token');
    const token = JSON.parse(params.subject_token);
    assert.strictEqual(token.principal, 'TECHNICAL-USER');
    assert.strictEqual(token.attributes.ipAddress, '10.0.0.1');
    assert.strictEqual(token.attributes.userAgent, 'curl/8');
    assert.deepStrictEqual(token.contextAttributes, {
        'access_token': 'abc.def',
        'request-ctx-env': 'dev',
        'request-ctx-cert-dn': 'CN=tpp,O=Bank',
        'request-ctx-cert': encodeURIComponent(PEM)
    });
});

test('build fails on unknown type or missing type-specific input', () => {
    assert.strictEqual(run(buildScript, Object.assign({ 'isam.input.subjectTokenType': 'jwt' }, common))['isam.failed'], 'true');
    assert.strictEqual(run(buildScript, Object.assign({ 'isam.input.subjectTokenType': 'stsuu' }, common))['isam.failed'], 'true');
    assert.strictEqual(run(buildScript, Object.assign({ 'isam.input.subjectTokenType': 'access-token', 'isam.input.accessToken': 'x' }, common))['isam.failed'], 'true');
});

const SAML = '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"><saml2:AttributeStatement>' +
    '<saml2:Attribute Name="clientId" NameFormat="basic"><saml2:AttributeValue>d4f82d6c20ed4fa5ac244b072994df63</saml2:AttributeValue></saml2:Attribute>' +
    '<saml2:Attribute Name="permissions"><saml2:AttributeValue xsi:type="xs:string">CLIENT_SCOPES=a,b;SIGNED_SCOPES=a</saml2:AttributeValue></saml2:Attribute>' +
    '</saml2:AttributeStatement></saml2:Assertion>';

function extract(accessToken, extra) {
    return run(extractScript, Object.assign({
        'isamResponse.status.code': 200,
        'isamResponse.content': JSON.stringify({ access_token: accessToken, issued_token_type: 'urn:bnppf:saml:tech' })
    }, extra));
}

test('extract reads clientId and permissions from a base64url SAML token', () => {
    const vars = extract(Buffer.from(SAML).toString('base64url'));
    assert.strictEqual(vars['isam.saml.clientId'], 'd4f82d6c20ed4fa5ac244b072994df63');
    assert.strictEqual(vars['isam.saml.permissions'], 'CLIENT_SCOPES=a,b;SIGNED_SCOPES=a');
    assert.strictEqual(vars['isam.saml.assertion'], SAML);
    assert.notStrictEqual(vars['isam.failed'], 'true');
});

test('extract accepts standard base64 and raw XML', () => {
    assert.strictEqual(extract(Buffer.from(SAML).toString('base64'))['isam.saml.clientId'], 'd4f82d6c20ed4fa5ac244b072994df63');
    assert.strictEqual(extract(SAML)['isam.saml.clientId'], 'd4f82d6c20ed4fa5ac244b072994df63');
});

test('extract fails on call error, HTTP error or missing clientId', () => {
    assert.strictEqual(extract(SAML, { 'servicecallout.SC-ISAM-Token-Exchange.failed': true })['isam.failed'], 'true');
    assert.strictEqual(extract(SAML, { 'isamResponse.status.code': 400 })['isam.failed'], 'true');
    assert.strictEqual(extract('<Assertion/>')['isam.failed'], 'true');
});
