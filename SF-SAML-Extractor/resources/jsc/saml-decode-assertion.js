// Reads the SAML assertion from the configured request header
// (saml.header.name, default "X-SAML-Assertion") and makes the raw XML
// text available in saml.assertion.xml — base64-decoded first if the
// header isn't already raw XML (auto-detected by whether the trimmed
// value starts with "<"). Apigee has no native base64-decode policy,
// which is the one piece this shared flow still needs JS for; actual
// element extraction is left to a native ExtractVariables policy in
// each calling proxy (<Source>saml.assertion.xml</Source> + XPath
// using local-name() so it's namespace-agnostic) — no generic runtime
// engine needed since each proxy already knows its own SAML shape.

(function decodeSamlAssertion() {
    var headerName = context.getVariable('saml.header.name');
    if (!headerName) {
        headerName = 'X-SAML-Assertion';
        context.setVariable('saml.header.name', headerName);
    }

    var raw = context.getVariable('request.header.' + headerName);
    if (!raw) {
        throw new Error('No SAML assertion found in request header "' + headerName + '".');
    }

    var trimmed = raw.replace(/^\s+|\s+$/g, '');
    var xml = trimmed.charAt(0) === '<' ? trimmed : byteStringToUtf8(base64Decode(trimmed));

    context.setVariable('saml.assertion.xml', xml);
})();
