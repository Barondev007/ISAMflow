// Minimal single-pass XML tokenizer for Apigee's JS engine, which has
// no DOMParser/XPath. Enough to walk a SAML assertion: nested elements
// with namespace prefixes, attributes (single/double quoted), text
// content, CDATA, comments, and the XML declaration. Not a validating
// parser — it trusts the input is well-formed SAML XML.
//
// Node shape: { prefix, local, attrs: {name: value}, children: [node],
// text: string (this element's own direct text, not children's) }

function parseXml(xmlString) {
    var pos = 0;
    var len = xmlString.length;

    function skipWhitespace() {
        while (pos < len && /\s/.test(xmlString.charAt(pos))) { pos++; }
    }

    function decodeEntities(s) {
        return s
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&apos;/g, "'")
            .replace(/&amp;/g, '&');
    }

    function parseName() {
        var start = pos;
        while (pos < len && /[^\s\/>=]/.test(xmlString.charAt(pos))) { pos++; }
        return xmlString.substring(start, pos);
    }

    function parseAttributes() {
        var attrs = {};
        while (true) {
            skipWhitespace();
            var ch = xmlString.charAt(pos);
            if (pos >= len || ch === '>' || ch === '/' || ch === '?') { break; }
            var name = parseName();
            if (!name) { break; }
            skipWhitespace();
            var value = '';
            if (xmlString.charAt(pos) === '=') {
                pos++;
                skipWhitespace();
                var quote = xmlString.charAt(pos);
                if (quote === '"' || quote === "'") {
                    pos++;
                    var vstart = pos;
                    var qend = xmlString.indexOf(quote, pos);
                    if (qend === -1) { qend = len; }
                    value = xmlString.substring(vstart, qend);
                    pos = qend + 1;
                } else {
                    var vstart2 = pos;
                    while (pos < len && /[^\s\/>]/.test(xmlString.charAt(pos))) { pos++; }
                    value = xmlString.substring(vstart2, pos);
                }
            }
            attrs[name] = decodeEntities(value);
        }
        return attrs;
    }

    function splitName(qname) {
        var idx = qname.indexOf(':');
        if (idx === -1) { return { prefix: '', local: qname }; }
        return { prefix: qname.substring(0, idx), local: qname.substring(idx + 1) };
    }

    var root = null;
    var stack = [];

    while (pos < len) {
        var lt = xmlString.indexOf('<', pos);
        if (lt === -1) { break; }

        if (lt > pos && stack.length > 0) {
            stack[stack.length - 1].text += decodeEntities(xmlString.substring(pos, lt));
        }
        pos = lt;

        if (xmlString.substr(pos, 4) === '<!--') {
            var cEnd = xmlString.indexOf('-->', pos);
            pos = cEnd === -1 ? len : cEnd + 3;
            continue;
        }
        if (xmlString.substr(pos, 9) === '<![CDATA[') {
            var cdEnd = xmlString.indexOf(']]>', pos + 9);
            var cdContent = xmlString.substring(pos + 9, cdEnd === -1 ? len : cdEnd);
            if (stack.length > 0) { stack[stack.length - 1].text += cdContent; }
            pos = cdEnd === -1 ? len : cdEnd + 3;
            continue;
        }
        if (xmlString.substr(pos, 2) === '<?') {
            var piEnd = xmlString.indexOf('?>', pos);
            pos = piEnd === -1 ? len : piEnd + 2;
            continue;
        }
        if (xmlString.substr(pos, 9) === '<!DOCTYPE') {
            var dEnd = xmlString.indexOf('>', pos);
            pos = dEnd === -1 ? len : dEnd + 1;
            continue;
        }

        if (xmlString.charAt(pos + 1) === '/') {
            var gt = xmlString.indexOf('>', pos);
            pos = gt === -1 ? len : gt + 1;
            if (stack.length > 0) { stack.pop(); }
            continue;
        }

        pos++; // consume '<'
        var qname = parseName();
        var attrs = parseAttributes();
        skipWhitespace();
        var selfClosing = false;
        if (xmlString.charAt(pos) === '/') {
            selfClosing = true;
            pos++;
        }
        if (xmlString.charAt(pos) === '>') {
            pos++;
        }

        var nameParts = splitName(qname);
        var node = { prefix: nameParts.prefix, local: nameParts.local, attrs: attrs, children: [], text: '' };
        if (stack.length > 0) {
            stack[stack.length - 1].children.push(node);
        } else if (!root) {
            root = node;
        }
        if (!selfClosing) {
            stack.push(node);
        }
    }

    return root;
}

function findFirstByLocalName(node, localName) {
    if (!node) { return null; }
    if (node.local === localName) { return node; }
    for (var i = 0; i < node.children.length; i++) {
        var found = findFirstByLocalName(node.children[i], localName);
        if (found) { return found; }
    }
    return null;
}

function findSamlAttributeElement(node, attrName) {
    if (!node) { return null; }
    if (node.local === 'Attribute' && node.attrs && node.attrs.Name === attrName) {
        return node;
    }
    for (var i = 0; i < node.children.length; i++) {
        var found = findSamlAttributeElement(node.children[i], attrName);
        if (found) { return found; }
    }
    return null;
}

function getElementText(node) {
    if (!node) { return null; }
    var text = node.text;
    for (var i = 0; i < node.children.length; i++) {
        text += getElementText(node.children[i]);
    }
    return text.replace(/^\s+|\s+$/g, '');
}
