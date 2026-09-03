// Extracts values from a SAML assertion (read from a request header)
// into flow variables, per an ordered rule list loaded from KVM
// (saml.elements.template, see KVM-Get-SAML-Elements-Template).
//
// Each rule: {"variable": "<flow var to set>", "type": "element"|"attribute", "name": "<...>", "attribute": "<optional>"}
//   - type "element": first element anywhere in the assertion whose
//     local name (namespace prefix ignored) is `name`. Value is that
//     element's text content, or — if `attribute` is also given — the
//     value of that XML attribute on the element.
//   - type "attribute": the common SAML <Attribute Name="..."><AttributeValue>
//     pattern — finds the Attribute element whose Name = `name` and
//     returns its first AttributeValue child's text.
//
// Scope: reads from the current request only (request.header.*).

(function extractSamlElements() {
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

    var root = parseXml(xml);
    if (!root) {
        throw new Error('Could not parse the SAML assertion from header "' + headerName + '" as XML.');
    }

    var rulesJson = context.getVariable('saml.elements.template');
    var rules = JSON.parse(rulesJson);
    if (!(rules instanceof Array) || rules.length === 0) {
        throw new Error('SAML elements template must be a non-empty JSON array of extraction rules.');
    }

    for (var i = 0; i < rules.length; i++) {
        var rule = rules[i];
        if (!rule.variable || !rule.type || !rule.name) {
            throw new Error('SAML element rule #' + i + ' needs "variable", "type" and "name".');
        }

        var value = null;
        if (rule.type === 'element') {
            var el = findFirstByLocalName(root, rule.name);
            if (el) {
                value = rule.attribute ? el.attrs[rule.attribute] : getElementText(el);
            }
        } else if (rule.type === 'attribute') {
            var attrEl = findSamlAttributeElement(root, rule.name);
            if (attrEl) {
                var valueEl = findFirstByLocalName(attrEl, 'AttributeValue');
                value = valueEl ? getElementText(valueEl) : null;
            }
        } else {
            throw new Error('Unknown SAML element rule type "' + rule.type + '" for variable "' + rule.variable + '".');
        }

        if (value === null || value === undefined) {
            throw new Error('Could not extract "' + rule.name + '" (' + rule.type + ') from the SAML assertion for variable "' + rule.variable + '".');
        }
        context.setVariable(rule.variable, value);
    }
})();
