// Strips PEM armor (the BEGIN/END CERTIFICATE marker lines) and all
// whitespace from the client certificate Apigee captured during its own
// two-way TLS handshake, leaving the bare base64 body that goes into the
// request to ISAM.
//
// Only reached when tls.client.raw.cert is non-null (see this policy's
// Condition in sharedflows/default.xml), but guarded anyway in case this
// policy is ever reused or reordered elsewhere.
//
// Native message-template functions (replaceAll with a regex) were tried
// first across several variants and, on this environment (Apigee Edge
// Private Cloud 4.53.01), none of them evaluated: the combined-regex form,
// the double-backslash \\s form, and a version split across chained
// AssignVariable steps in separate policies all still left the raw,
// unevaluated expression text in the target variable. Plain JavaScript
// string methods have no such ambiguity.
var raw = context.getVariable('tls.client.raw.cert');
if (raw) {
    var stripped = raw
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
    context.setVariable('isam.client.cert.base64', stripped);
}
