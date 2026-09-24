// Runs the shared flow JavaScript against a mocked Apigee context: node --test test/
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const jsc = path.join(__dirname, '..', 'sharedflowbundle', 'resources', 'jsc');
const prepareScript = fs.readFileSync(path.join(jsc, 'tprf-prepare-request.js'), 'utf8');
const evaluateScript = fs.readFileSync(path.join(jsc, 'tprf-evaluate-response.js'), 'utf8');

const CLIENT_ID = 'd4f82d6c20ed4fa5ac244b072994df63';
const SCOPE = 'crm.servicing-request-snow-inbound-front.cash-accounts.validate';
const OTHER = 'crm.servicing-request-snow-inbound-front.cash-accounts.read';

function run(script, variables) {
    const context = {
        getVariable: (name) => (name in variables ? variables[name] : null),
        setVariable: (name, value) => { variables[name] = value; }
    };
    vm.runInNewContext(script, { context });
    return variables;
}

function inputs(overrides) {
    return Object.assign({
        'tprf.input.certificate': '-----BEGIN CERTIFICATE-----\nMIIDCC\nBzCgAw==\n-----END CERTIFICATE-----\n',
        'tprf.input.clientId': CLIENT_ID,
        'tprf.input.permissions': 'CLIENT_SCOPES=' + SCOPE + ',' + OTHER + ';SIGNED_SCOPES=' + SCOPE,
        'tprf.input.methodScopes': OTHER + ', ' + SCOPE
    }, overrides);
}

function tprfResponse(body, status) {
    return {
        'tprfResponse.status.code': status || 200,
        'tprfResponse.content': JSON.stringify(body)
    };
}

const onboarded = {
    certificateFound: 'Y',
    thirdPartyId: '220',
    clientApplicationList: [{
        clientId: CLIENT_ID,
        clientApplicationScopeList: [{ scopeAbbreviationCode: SCOPE, scopeName: SCOPE }]
    }]
};

test('prepare builds the TPRF body with method scopes that were signed', () => {
    const vars = run(prepareScript, inputs());
    assert.strictEqual(vars['tprf.failed'], 'false');
    assert.deepStrictEqual(JSON.parse(vars['tprf.request.body']), {
        identifierValueBinary: 'MIIDCCBzCgAw==',
        clientId: CLIENT_ID,
        scopesAbbreviationList: [SCOPE]
    });
    assert.strictEqual(vars['tprf.client.scopes'], SCOPE + ',' + OTHER);
});

test('prepare fails when no method scope is in SIGNED_SCOPES', () => {
    const vars = run(prepareScript, inputs({ 'tprf.input.permissions': 'CLIENT_SCOPES=' + SCOPE + ';SIGNED_SCOPES=' + OTHER, 'tprf.input.methodScopes': SCOPE }));
    assert.strictEqual(vars['tprf.failed'], 'true');
});

test('prepare fails on missing clientId, certificate or KVM scopes', () => {
    assert.strictEqual(run(prepareScript, inputs({ 'tprf.input.clientId': null }))['tprf.failed'], 'true');
    assert.strictEqual(run(prepareScript, inputs({ 'tprf.input.certificate': '' }))['tprf.failed'], 'true');
    assert.strictEqual(run(prepareScript, inputs({ 'tprf.input.methodScopes': null }))['tprf.failed'], 'true');
});

function evaluate(body, extra) {
    const vars = run(prepareScript, inputs());
    Object.assign(vars, tprfResponse(body), extra);
    return run(evaluateScript, vars);
}

test('evaluate authorizes an onboarded TPP with a granted scope', () => {
    const vars = evaluate(onboarded);
    assert.strictEqual(vars['tprf.authorized'], 'true');
    assert.strictEqual(vars['tprf.granted.scopes'], SCOPE);
    assert.strictEqual(vars['tprf.thirdPartyId'], '220');
});

test('evaluate rejects certificateFound = N', () => {
    assert.strictEqual(evaluate(Object.assign({}, onboarded, { certificateFound: 'N' }))['tprf.authorized'], 'false');
});

test('evaluate rejects when the scope is not granted by TPRF', () => {
    const body = JSON.parse(JSON.stringify(onboarded));
    body.clientApplicationList[0].clientApplicationScopeList = [{ scopeAbbreviationCode: OTHER, scopeName: OTHER }];
    assert.strictEqual(evaluate(body)['tprf.authorized'], 'false');
});

test('evaluate rejects when the clientId is not in the list', () => {
    const body = JSON.parse(JSON.stringify(onboarded));
    body.clientApplicationList[0].clientId = 'another';
    assert.strictEqual(evaluate(body)['tprf.authorized'], 'false');
});

test('evaluate rejects a failed call or a non-2xx status', () => {
    assert.strictEqual(evaluate(onboarded, { 'servicecallout.SC-TPRF-Certificate-Validation.failed': true })['tprf.authorized'], 'false');
    assert.strictEqual(evaluate(onboarded, { 'tprfResponse.status.code': 500 })['tprf.authorized'], 'false');
    assert.strictEqual(evaluate(onboarded, { 'tprfResponse.content': 'not json' })['tprf.authorized'], 'false');
});
