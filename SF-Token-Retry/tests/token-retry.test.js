/*
 * Offline test for SF-Token-Retry: executes the Steps of sharedflows/default.xml
 * in order (evaluating their Conditions), runs the real JavaScript resources,
 * and simulates the ServiceCallout results.
 *
 * Run: node tests/token-retry.test.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const root = path.join(__dirname, '..');
const js = (f) => fs.readFileSync(path.join(root, 'resources/jsc', f), 'utf8');
const scripts = {
  'JS-TokenRetry-Init': js('token-retry-init.js'),
  'JS-TokenRetry-Check': js('token-retry-check.js'),
};

const flowXml = fs.readFileSync(path.join(root, 'sharedflows/default.xml'), 'utf8')
  .replace(/<!--[\s\S]*?-->/g, '');
const steps = [...flowXml.matchAll(/<Step>([\s\S]*?)<\/Step>/g)].map((m) => ({
  name: m[1].match(/<Name>(.*?)<\/Name>/)[1].trim(),
  cond: (m[1].match(/<Condition>(.*?)<\/Condition>/) || [])[1],
}));

// minimal Apigee condition evaluator: a = "x", a != "x", a != null, joined by "and"
function evalCond(cond, vars) {
  if (!cond) return true;
  return cond.split(/\s+and\s+/).every((part) => {
    let m = part.match(/^\s*([\w.]+)\s*(!=|=)\s*(null|"[^"]*")\s*$/);
    if (!m) throw new Error('unsupported condition: ' + part);
    const v = vars[m[1]] === undefined ? null : vars[m[1]];
    const rhs = m[3] === 'null' ? null : m[3].slice(1, -1);
    return m[2] === '=' ? v === rhs : v !== rhs;
  });
}

function run(config, responses) {
  const vars = Object.assign({ 'tokenRetryRequest.verb': 'POST' }, config);
  const calls = [];
  const executed = [];
  const context = {
    getVariable: (n) => (vars[n] === undefined ? null : vars[n]),
    setVariable: (n, v) => { vars[n] = v; },
    removeVariable: (n) => {
      Object.keys(vars).forEach((k) => { if (k === n || k.startsWith(n + '.')) delete vars[k]; });
    },
  };
  for (const s of steps) {
    if (!evalCond(s.cond, vars)) continue;
    executed.push(s.name);
    if (scripts[s.name]) {
      vm.runInNewContext(scripts[s.name], { context });
    } else if (s.name.startsWith('SC-')) {
      const r = responses[calls.length];
      calls.push({ policy: s.name, url: vars['servicecallout.' + s.name + '.target.url'] });
      if (r !== 'timeout') vars['tokenRetryResponse.status.code'] = String(r);
    } else if (s.name.startsWith('RF-')) {
      return { vars, calls, executed, fault: s.name };
    }
  }
  return { vars, calls, executed, fault: null };
}

const base = { 'tokenretry.url': 'https://as.example.com/token', 'tokenretry.delaysMs': '50,100' };
const tests = {
  'success on first attempt, no retry': () => {
    const r = run(base, [200]);
    assert.strictEqual(r.calls.length, 1);
    assert.strictEqual(r.vars['tokenretry.success'], 'true');
    assert.strictEqual(r.fault, null);
    assert.strictEqual(r.calls[0].url, 'https://as.example.com/token');
  },
  'timeout then success: 1 retry': () => {
    const r = run(base, ['timeout', 200]);
    assert.strictEqual(r.calls.length, 2);
    assert.strictEqual(r.vars['tokenretry.attempts'], '2');
    assert.strictEqual(r.vars['tokenretry.success'], 'true');
    assert.strictEqual(r.fault, null);
  },
  '503, 502 then success on retry 2': () => {
    const r = run(base, [503, 502, 200]);
    assert.strictEqual(r.calls.length, 3);
    assert.strictEqual(r.vars['tokenretry.success'], 'true');
    assert.strictEqual(r.fault, null);
  },
  'all 3 attempts fail -> 503 fault, max 3 calls': () => {
    const r = run(base, ['timeout', 500, 'timeout', 200]);
    assert.strictEqual(r.calls.length, 3);
    assert.strictEqual(r.vars['tokenretry.lastStatus'], 'timeout');
    assert.strictEqual(r.fault, 'RF-TokenRetry-Unavailable');
  },
  '401 is not retried': () => {
    const r = run(base, [401, 200]);
    assert.strictEqual(r.calls.length, 1);
    assert.strictEqual(r.vars['tokenretry.lastStatus'], '401');
    assert.strictEqual(r.fault, 'RF-TokenRetry-Unavailable');
  },
  '429 is retried': () => {
    assert.strictEqual(run(base, [429, 200]).calls.length, 2);
  },
  'raiseFault=false leaves the decision to the proxy': () => {
    const r = run(Object.assign({ 'tokenretry.raiseFault': 'false' }, base), [500, 500, 500]);
    assert.strictEqual(r.fault, null);
    assert.strictEqual(r.vars['tokenretry.success'], 'false');
  },
  'maxAttempts=2 -> only 1 retry': () => {
    const r = run(Object.assign({ 'tokenretry.maxAttempts': '2' }, base), [500, 500, 200]);
    assert.strictEqual(r.calls.length, 2);
    assert.strictEqual(r.fault, 'RF-TokenRetry-Unavailable');
  },
  'maxAttempts above 3 is capped to 3': () => {
    const r = run(Object.assign({}, base, { 'tokenretry.maxAttempts': '9' }), [500, 500, 500, 200]);
    assert.strictEqual(r.calls.length, 3);
  },
  'mtls=true uses the mTLS callout only': () => {
    const r = run(Object.assign({ 'tokenretry.mtls': 'true' }, base), [500, 200]);
    assert.deepStrictEqual(r.calls.map((c) => c.policy), ['SC-TokenRetry-CallMtls', 'SC-TokenRetry-CallMtls']);
  },
  'budget stops retries that would not fit': () => {
    // budget 3000 = one call timeout: no room for a retry
    const r = run(Object.assign({}, base, { 'tokenretry.budgetMs': '3000' }), [500, 200]);
    assert.strictEqual(r.calls.length, 1);
  },
  'delay is applied before a retry': () => {
    const t0 = Date.now();
    run(Object.assign({}, base, { 'tokenretry.delaysMs': '150,150' }), [500, 200]);
    assert.ok(Date.now() - t0 >= 150, 'expected at least 150 ms wait');
  },
  'delay above 2000 ms is capped': () => {
    const r = run(Object.assign({}, base, { 'tokenretry.delaysMs': '99999' }), [200]);
    assert.strictEqual(r.vars['tokenretry.delaysMs'], '2000');
  },
  'missing url -> config error, no call': () => {
    const r = run({}, [200]);
    assert.strictEqual(r.calls.length, 0);
    assert.strictEqual(r.fault, 'RF-TokenRetry-ConfigError');
  },
  'missing request message -> config error, no call': () => {
    const r = run(Object.assign({ 'tokenRetryRequest.verb': undefined }, base), [200]);
    assert.strictEqual(r.calls.length, 0);
    assert.strictEqual(r.fault, 'RF-TokenRetry-ConfigError');
  },
};

let failed = 0;
for (const [name, fn] of Object.entries(tests)) {
  try { fn(); console.log('ok   ' + name); } catch (e) { failed++; console.log('FAIL ' + name + '\n     ' + e.message); }
}
console.log(`\n${Object.keys(tests).length - failed}/${Object.keys(tests).length} passed`);
process.exit(failed ? 1 : 0);
