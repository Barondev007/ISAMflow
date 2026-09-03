// Exclusive XML Canonicalization 1.0 (http://www.w3.org/2001/10/xml-exc-c14n#),
// without comments, without an InclusiveNamespaces PrefixList — the common
// case needed to build the digest and SignedInfo for XML-DSig. Apigee has no
// native policy for this; verified against lxml/libxml2's canonicalize()
// (a mature reference implementation) across many edge cases before use.

function c14nParseXml(xmlString) {
    var pos = 0;
    var len = xmlString.length;

    function skipWhitespace() { while (pos < len && /\s/.test(xmlString.charAt(pos))) { pos++; } }

    function decodeEntities(s) {
        return s
            .replace(/&#x([0-9A-Fa-f]+);/g, function (m, h) { return String.fromCharCode(parseInt(h, 16)); })
            .replace(/&#([0-9]+);/g, function (m, d) { return String.fromCharCode(parseInt(d, 10)); })
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
        var attrs = [];
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
            attrs.push({ qName: name, value: decodeEntities(value) });
        }
        return attrs;
    }

    function splitQName(qname) {
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
            stack[stack.length - 1].children.push({ type: 'text', value: decodeEntities(xmlString.substring(pos, lt)) });
        }
        pos = lt;

        if (xmlString.substr(pos, 4) === '<!--') {
            var cEnd = xmlString.indexOf('-->', pos);
            var content = xmlString.substring(pos + 4, cEnd === -1 ? len : cEnd);
            if (stack.length > 0) { stack[stack.length - 1].children.push({ type: 'comment', value: content }); }
            pos = cEnd === -1 ? len : cEnd + 3;
            continue;
        }
        if (xmlString.substr(pos, 9) === '<![CDATA[') {
            var cdEnd = xmlString.indexOf(']]>', pos + 9);
            var cdContent = xmlString.substring(pos + 9, cdEnd === -1 ? len : cdEnd);
            if (stack.length > 0) { stack[stack.length - 1].children.push({ type: 'text', value: cdContent }); }
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

        pos++;
        var qname = parseName();
        var attrs = parseAttributes();
        skipWhitespace();
        var selfClosing = false;
        if (xmlString.charAt(pos) === '/') { selfClosing = true; pos++; }
        if (xmlString.charAt(pos) === '>') { pos++; }

        var nameParts = splitQName(qname);
        var node = { type: 'element', qName: qname, prefix: nameParts.prefix, local: nameParts.local, attrs: attrs, children: [] };
        if (stack.length > 0) { stack[stack.length - 1].children.push(node); }
        else if (!root) { root = node; }
        if (!selfClosing) { stack.push(node); }
    }

    return root;
}

function c14nSplitQName(qname) {
    var idx = qname.indexOf(':');
    if (idx === -1) { return { prefix: '', local: qname }; }
    return { prefix: qname.substring(0, idx), local: qname.substring(idx + 1) };
}

function c14nIsNsAttr(qName) {
    return qName === 'xmlns' || qName.indexOf('xmlns:') === 0;
}

function c14nNsAttrPrefix(qName) {
    return qName === 'xmlns' ? '' : qName.substring(6);
}

function c14nEscapeText(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
}

function c14nEscapeAttr(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/"/g, '&quot;')
        .replace(/\t/g, '&#x9;')
        .replace(/\n/g, '&#xA;')
        .replace(/\r/g, '&#xD;');
}

function c14nRenderElement(node, inScopeNs, renderedNs, out) {
    var ownDecls = {};
    var regularAttrs = [];
    for (var i = 0; i < node.attrs.length; i++) {
        var a = node.attrs[i];
        if (c14nIsNsAttr(a.qName)) {
            ownDecls[c14nNsAttrPrefix(a.qName)] = a.value;
        } else {
            regularAttrs.push(a);
        }
    }

    var newInScopeNs = {};
    for (var k in inScopeNs) { newInScopeNs[k] = inScopeNs[k]; }
    for (var k2 in ownDecls) { newInScopeNs[k2] = ownDecls[k2]; }

    var toRender = [];
    var newRenderedNs = {};
    for (var k3 in renderedNs) { newRenderedNs[k3] = renderedNs[k3]; }

    // Default namespace ('') is always relevant for an unprefixed element,
    // whether declared or not — an explicit xmlns="" must be emitted if an
    // ancestor rendered a non-empty default namespace and this element has
    // none, to correctly undeclare it.
    if (node.prefix === '') {
        var uriDefault = newInScopeNs.hasOwnProperty('') ? newInScopeNs[''] : '';
        var renderedDefault = newRenderedNs.hasOwnProperty('') ? newRenderedNs[''] : '';
        if (uriDefault !== renderedDefault) {
            toRender.push({ prefix: '', uri: uriDefault });
            newRenderedNs[''] = uriDefault;
        }
    }

    var utilizedPrefixes = {};
    if (node.prefix !== '') { utilizedPrefixes[node.prefix] = true; }
    for (var j = 0; j < regularAttrs.length; j++) {
        var attrParts = c14nSplitQName(regularAttrs[j].qName);
        if (attrParts.prefix !== '') { utilizedPrefixes[attrParts.prefix] = true; }
    }

    var nonDefaultPrefixes = [];
    for (var p in utilizedPrefixes) { nonDefaultPrefixes.push(p); }
    nonDefaultPrefixes.sort();

    for (var pi = 0; pi < nonDefaultPrefixes.length; pi++) {
        var prefix = nonDefaultPrefixes[pi];
        if (prefix === 'xml') { continue; } // implicit, never declared/rendered
        var uri = newInScopeNs.hasOwnProperty(prefix) ? newInScopeNs[prefix] : undefined;
        if (uri === undefined) { continue; } // used but never declared: malformed input, skip
        if (newRenderedNs[prefix] !== uri) {
            toRender.push({ prefix: prefix, uri: uri });
            newRenderedNs[prefix] = uri;
        }
    }

    // Sort: default namespace first, then prefixed namespaces alphabetically.
    toRender.sort(function (x, y) {
        if (x.prefix === '' && y.prefix !== '') { return -1; }
        if (x.prefix !== '' && y.prefix === '') { return 1; }
        return x.prefix < y.prefix ? -1 : (x.prefix > y.prefix ? 1 : 0);
    });

    var sortedAttrs = regularAttrs.slice().sort(function (x, y) {
        var xp = c14nSplitQName(x.qName), yp = c14nSplitQName(y.qName);
        var xUri = xp.prefix === '' ? '' : (newInScopeNs[xp.prefix] || '');
        var yUri = yp.prefix === '' ? '' : (newInScopeNs[yp.prefix] || '');
        if (xp.prefix === '' && yp.prefix !== '') { return -1; }
        if (xp.prefix !== '' && yp.prefix === '') { return 1; }
        if (xUri !== yUri) { return xUri < yUri ? -1 : 1; }
        return xp.local < yp.local ? -1 : (xp.local > yp.local ? 1 : 0);
    });

    out.push('<' + node.qName);
    for (var t = 0; t < toRender.length; t++) {
        var nsName = toRender[t].prefix === '' ? 'xmlns' : ('xmlns:' + toRender[t].prefix);
        out.push(' ' + nsName + '="' + c14nEscapeAttr(toRender[t].uri) + '"');
    }
    for (var s = 0; s < sortedAttrs.length; s++) {
        out.push(' ' + sortedAttrs[s].qName + '="' + c14nEscapeAttr(sortedAttrs[s].value) + '"');
    }
    out.push('>');

    for (var c = 0; c < node.children.length; c++) {
        var child = node.children[c];
        if (child.type === 'element') {
            c14nRenderElement(child, newInScopeNs, newRenderedNs, out);
        } else if (child.type === 'text') {
            out.push(c14nEscapeText(child.value));
        }
        // comments dropped: this is c14n *without* comments (exc-c14n#, not exc-c14n#WithComments)
    }

    out.push('</' + node.qName + '>');
}

// Canonicalizes an already-parsed element (from c14nParseXml) as the root of
// the canonicalization — i.e. with an empty outer namespace/rendered context,
// which is correct for the common case of canonicalizing the document's own
// root element or a synthetically built element like <SignedInfo>.
function canonicalizeExclusive(root) {
    var out = [];
    c14nRenderElement(root, {}, {}, out);
    return out.join('');
}
