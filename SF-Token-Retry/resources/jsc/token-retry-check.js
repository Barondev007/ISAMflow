/*
 * SF-Token-Retry - check after each attempt
 *
 * Decides from tokenRetryResponse whether the attempt succeeded and, if not,
 * whether another attempt is allowed. Before a retry it waits the configured
 * delay.
 *
 * Retried:     no response (timeout / connection error), 408, 429, 5xx
 * Not retried: other 4xx (bad credentials, bad request...) - retrying won't help
 *
 * Outputs:
 *   tokenretry.success     "true" / "false"
 *   tokenretry.retry       "true" when another attempt must run
 *   tokenretry.attempts    number of attempts done
 *   tokenretry.lastStatus  last HTTP status, or "timeout"
 */

var attempt = parseInt(context.getVariable('tokenretry.attempts') || '0', 10) + 1;
var maxAttempts = parseInt(context.getVariable('tokenretry.maxAttempts'), 10) || 3;
var budgetMs = parseInt(context.getVariable('tokenretry.budgetMs'), 10) || 10000;
var callTimeoutMs = parseInt(context.getVariable('tokenretry.callTimeoutMs'), 10) || 3000;
var start = parseInt(context.getVariable('tokenretry.start'), 10) || Date.now();
var delays = String(context.getVariable('tokenretry.delaysMs') || '').split(',');

var status = context.getVariable('tokenRetryResponse.status.code'); // null => no response
var code = status ? parseInt(status, 10) : 0;
var ok = code >= 200 && code < 300;
var retryable = !status || code === 408 || code === 429 || code >= 500;

var delay = parseInt(delays[attempt - 1], 10) || 0;
var elapsed = Date.now() - start;
var retry = !ok && retryable && attempt < maxAttempts &&
            (elapsed + delay + callTimeoutMs) <= budgetMs;

context.setVariable('tokenretry.attempts', String(attempt));
context.setVariable('tokenretry.success', String(ok));
context.setVariable('tokenretry.retry', String(retry));
context.setVariable('tokenretry.lastStatus', status ? String(code) : 'timeout');

if (retry) {
    // drop this attempt's result so the next check can't read a stale status
    context.removeVariable('tokenRetryResponse');
    // Apigee JavaScript has no sleep(): short, bounded wait (delay is capped at 2000 ms by init)
    var end = Date.now() + delay;
    while (Date.now() < end) { /* wait */ }
}
