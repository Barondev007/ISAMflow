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
//
// Some IdPs embed raw, unescaped data in claim values — e.g. a
// "user-agent" claim carrying a literal browser/bot UA string, which
// often contains a bare "&" (a URL query separator in a UA like
// "...+http://bot.example.com/info?id=1&ref=2)"). A bare "&" isn't
// valid XML and aborts parsing of the whole document, not just that
// claim, which is why an unrelated ExtractVariables step downstream
// can fail on it. sanitizeStrayAmpersands fixes only that: any "&"
// not already part of a real entity/character reference gets escaped
// to "&amp;"; a "<" or ">" is left alone since a stray one there is
// far more likely a genuine malformed-input problem than benign data,
// and isn't safe to silently paper over the same way.

function sanitizeStrayAmpersands(xml) {
    return xml.replace(/&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)/g, '&amp;');
}

(function decodeSamlAssertion() {
    var headerName = context.getVariable('saml.header.name');
    if (!headerName) {
        headerName = 'X-SAML-Assertion';
        context.setVariable('saml.header.name', headerName);
    }

    // Apigee applies HTTP's list-header convention (RFC 7230 §3.2.2) to
    // any header, not just recognized list-type ones: a comma inside a
    // single header line is treated as a value separator, same as
    // repeating the header. request.header.<name> as a plain scalar
    // then returns only the first comma-delimited segment — silently
    // truncating a raw-XML assertion at its first comma (e.g. inside a
    // free-text claim like "user-agent"). .values.string reassembles
    // the full original value; fall back to the plain scalar for the
    // ordinary case where there's nothing to reassemble.
    var raw = context.getVariable('request.header.' + headerName + '.values.string');
    if (!raw) {
        raw = context.getVariable('request.header.' + headerName);
    }
    if (!raw) {
        throw new Error('No SAML assertion found in request header "' + headerName + '".');
    }

    // Strip a leading BOM too, not just whitespace — it isn't whitespace
    // so \s+ wouldn't remove it, and it would otherwise make raw XML
    // (which some tools prepend a BOM to) fail the charAt(0) === '<'
    // check below and get wrongly treated as base64.
    var trimmed = raw.replace(/^[\s\uFEFF]+|\s+$/g, '');
    var xml = trimmed.charAt(0) === '<' ? trimmed : byteStringToUtf8(base64Decode(trimmed));

    context.setVariable('saml.assertion.xml', sanitizeStrayAmpersands(xml));
})();
