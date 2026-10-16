# SF-Token-Retry

Shared flow that sends a token request with **retries**: 1 call + up to
**2 retries**, a **timeout per attempt**, a **short delay before each
retry** and a **total time budget**. Any proxy can use it through a
`FlowCallout`, instead of its own `ServiceCallout` to the token endpoint.

```
attempt 1 ──fail──> wait 500 ms ──> attempt 2 ──fail──> wait 1000 ms ──> attempt 3 ──fail──> 503
    │ ok                                │ ok                                  │ ok
    └────────────────> tokenRetryResponse (left for the proxy to extract) <───┘
```

## What is retried

| Result of an attempt | Retried? |
|---|---|
| timeout / connection error (no response) | yes |
| `408`, `429`, `5xx` | yes |
| `2xx` | no, success |
| other `4xx` (`400`, `401`, `403`...) | no: bad credentials or bad request, a retry won't help |

A retry is also skipped when it would not fit in the time budget:
`elapsed + delay + per-attempt timeout > tokenretry.budgetMs`.

## Contract

The calling proxy sets these **before** the `FlowCallout`
(see `examples/consumer-proxy/apiproxy/policies/`):

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `tokenRetryRequest` | yes | – | Request **message** to send (verb, headers, body). Build it with `AssignMessage` + `<AssignTo createNew="true" type="request">tokenRetryRequest</AssignTo>` |
| `tokenretry.url` | yes | – | Full token endpoint URL, `https://host/path` |
| `tokenretry.mtls` | no | `false` | `true` = send a client certificate (`SC-TokenRetry-CallMtls`) |
| `tokenretry.maxAttempts` | no | `3` | Total attempts, `1`–`3` (`3` = 1 call + 2 retries) |
| `tokenretry.delaysMs` | no | `500,1000` | Wait before retry 1, retry 2 (each capped at 2000 ms) |
| `tokenretry.budgetMs` | no | `10000` | Total time allowed for all attempts |
| `tokenretry.raiseFault` | no | `true` | `false` = don't raise the 503, the proxy checks `tokenretry.success` itself |

After the shared flow:

| Variable | Meaning |
|---|---|
| `tokenRetryResponse` | Response message of the last attempt (extract `access_token` from it) |
| `tokenretry.success` | `true` / `false` |
| `tokenretry.attempts` | Number of attempts done |
| `tokenretry.lastStatus` | Last HTTP status, or `timeout` |

When every attempt fails (and `raiseFault` isn't `false`), the shared flow
returns **503** with `Retry-After: 5` and
`{"error":"token_unavailable","attempts":"3","lastStatus":"timeout"}`.
A missing `tokenretry.url` or `tokenRetryRequest` returns **500**
`configuration_error` without calling anything.

## Use it in a proxy

1. Add the four policies from `examples/consumer-proxy/apiproxy/policies/`
   (adapt `AM-TokenRetry-Config` / `AM-TokenRetry-BuildRequest` to your KVM
   variables and token server).
2. In the TargetEndpoint PreFlow, replace the old token `ServiceCallout` by
   `AM-TokenRetry-Config` → `AM-TokenRetry-BuildRequest` → `FC-TokenRetry`,
   all under the cache-miss condition, so the token call (and its retries)
   only happens when the cached token has expired.
   See `examples/consumer-proxy/apiproxy/targets/default-preflow-snippet.xml`.

## Timing

Default worst case: 3 × 3 s (per-attempt timeout) + 0.5 s + 1 s of delays
= 10.5 s, cut to ≤ 10 s by the default budget (the last retry is skipped
if it doesn't fit).

The **per-attempt timeout is fixed in the policies** (Apigee doesn't take a
variable there): to change it, edit `<Timeout>` and `io.timeout.millis` in
both `SC-TokenRetry-*.xml` **and** `CALL_TIMEOUT_MS` in
`resources/jsc/token-retry-init.js`.

## Notes

- **The delay is a busy-wait.** Apigee JavaScript has no `sleep()`, so
  `JS-TokenRetry-Check` loops until the delay is over. This holds a CPU
  thread, which is why each delay is capped at 2000 ms (below the policy's
  `timeLimit` of 3000 ms). Since the shared flow only runs on a token cache
  miss, this is rare. A Java Callout with `Thread.sleep()` is the
  alternative if you need longer waits.
- **TLS:** `SC-TokenRetry-Call` doesn't validate the server certificate
  until you uncomment its `TrustStore`. `SC-TokenRetry-CallMtls` needs the
  references `tokenretry-keystore-ref` / `tokenretry-truststore-ref` and the
  key alias `tokenretry-key` in every environment; rename them to match yours.
- **The URL** is applied through `servicecallout.<policy>.target.url`, which
  overrides the placeholder `<URL>` in the policies.
- A token POST (client credentials) can be retried safely: it has no side
  effect on the server.

## Test

Offline test, no Apigee needed: it runs the steps of `sharedflows/default.xml`
in order with their conditions, the real JavaScript, and simulated callout
results (success, timeout, 5xx, 401, budget, mTLS, config errors...).

```
node tests/token-retry.test.js
```

## Deploy

```
./package.sh      # builds SF-Token-Retry.zip (sharedflowbundle/ layout)
```

Import the zip as a shared flow named `SF-Token-Retry` (Apigee UI, or e.g.
`apigeecli sharedflows create bundle -n SF-Token-Retry -p SF-Token-Retry.zip`),
then deploy it to each environment **before** the proxies that call it.
