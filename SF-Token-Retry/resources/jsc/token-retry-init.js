/*
 * SF-Token-Retry - init
 *
 * Reads the configuration set by the calling proxy, applies defaults and
 * limits, resets the retry state and points both ServiceCallout policies at
 * tokenretry.url.
 *
 * Inputs (flow variables, set by the calling proxy before the FlowCallout):
 *   tokenRetryRequest      message  the token request (verb, headers, body)  REQUIRED
 *   tokenretry.url         string   full token endpoint URL (https://...)     REQUIRED
 *   tokenretry.mtls        "true"   use the client certificate callout        default "false"
 *   tokenretry.maxAttempts number   total attempts, 1..3                      default 3
 *   tokenretry.delaysMs    string   delays before retry 1, 2 ("500,1000")     default "500,1000"
 *   tokenretry.budgetMs    number   total time allowed for all attempts       default 10000
 *   tokenretry.raiseFault  "false"  don't raise the 503, let the proxy decide default "true"
 */

var CALL_TIMEOUT_MS = 3000;  // must match <Timeout> in the SC-TokenRetry-* policies
var MAX_ATTEMPTS_LIMIT = 3;  // the shared flow is unrolled for 3 attempts
var MAX_DELAY_MS = 2000;     // must stay below the timeLimit of JS-TokenRetry-Check

function intOr(name, dflt) {
    var v = parseInt(context.getVariable(name), 10);
    return isNaN(v) ? dflt : v;
}

function fail(message) {
    context.setVariable('tokenretry.configError', message);
}

var url = context.getVariable('tokenretry.url');
var maxAttempts = Math.min(Math.max(intOr('tokenretry.maxAttempts', 3), 1), MAX_ATTEMPTS_LIMIT);
var budgetMs = Math.max(intOr('tokenretry.budgetMs', 10000), CALL_TIMEOUT_MS);

var delaysRaw = context.getVariable('tokenretry.delaysMs') || '500,1000';
var delays = String(delaysRaw).split(',').map(function (d) {
    var n = parseInt(d, 10);
    return isNaN(n) ? 0 : Math.min(Math.max(n, 0), MAX_DELAY_MS);
});

// reset state, in case the shared flow is called more than once in the same message flow
context.removeVariable('tokenretry.configError');
context.setVariable('tokenretry.attempts', '0');
context.setVariable('tokenretry.retry', 'false');
context.setVariable('tokenretry.success', 'false');
context.setVariable('tokenretry.lastStatus', '');
context.setVariable('tokenretry.start', String(Date.now()));
context.removeVariable('tokenRetryResponse');

context.setVariable('tokenretry.maxAttempts', String(maxAttempts));
context.setVariable('tokenretry.budgetMs', String(budgetMs));
context.setVariable('tokenretry.delaysMs', delays.join(','));
context.setVariable('tokenretry.callTimeoutMs', String(CALL_TIMEOUT_MS));

if (!url || !/^https?:\/\//i.test(url)) {
    fail('tokenretry.url must be set to the full token endpoint URL (https://...).');
} else if (context.getVariable('tokenRetryRequest.verb') === null) {
    fail('tokenRetryRequest is not set. Build the token request message (e.g. AssignMessage with AssignTo createNew="true") before the FlowCallout.');
} else {
    context.setVariable('servicecallout.SC-TokenRetry-Call.target.url', url);
    context.setVariable('servicecallout.SC-TokenRetry-CallMtls.target.url', url);
}
