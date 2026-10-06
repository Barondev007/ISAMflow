package com.orders.signature;

import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Exclusive XML Canonicalization 1.0 (http://www.w3.org/2001/10/xml-exc-c14n#),
 * without comments, without an InclusiveNamespaces PrefixList -- the piece
 * signature generation needs that verification doesn't: javax.xml.crypto.dsig
 * (JSR 105, used by the sibling XmlDsigVerifyCallout) has no supported
 * public way to canonicalize an arbitrary DOM subtree on its own -- its
 * internal canonicalizer lives in a non-exported com.sun.org.apache...
 * package (confirmed by a direct `javac` attempt: "is declared in module
 * java.xml.crypto, which does not export it"), and JSR 105's own sign()
 * path needs a real local private key, which this architecture
 * deliberately doesn't have -- the actual RSA/ECDSA math happens on an
 * external signing API (see NI-Signature-XmlDsig-Sign.xml), not here.
 *
 * This is a direct port of the rendering logic from the former
 * resources/jsc/xml-exc-c14n.js, operating on a real org.w3c.dom.Element
 * (parsed by the standard JDK DocumentBuilder, same as
 * XmlDsigVerifyCallout.java) instead of that script's hand-rolled regex
 * parser -- the single highest-risk part of the JS version, now gone
 * entirely. The canonicalization rules themselves (namespace/attribute
 * sort order, namespace rendering decisions) are unchanged from that
 * script, except for one bug fixed in this port: processing instructions
 * were silently dropped by the JS parser and are now correctly preserved
 * (Canonical XML 1.0 only drops comments, never PIs, regardless of the
 * "WithComments" setting -- found by cross-checking this port's output
 * against lxml's independent C14N implementation on a document containing
 * a PI, where the two disagreed).
 *
 * Verified byte-for-byte against both the JS version it replaces and an
 * independent reference (Python lxml's etree.tostring(method="c14n",
 * exclusive=True)) across documents covering: default-namespace
 * declaration/undeclaration at multiple nesting depths, prefixed and
 * unprefixed attributes with namespace-URI-based sort order, the implicit
 * "xml" prefix (never re-declared), CDATA sections, comments (dropped),
 * and processing instructions (kept) -- before being wired into the
 * shared flow.
 */
final class XmlC14n {
    private XmlC14n() { }

    static String canonicalize(Element root) {
        StringBuilder out = new StringBuilder();
        render(root, new HashMap<String, String>(), new HashMap<String, String>(), out);
        return out.toString();
    }

    private static void render(Element node, Map<String, String> inScopeNs, Map<String, String> renderedNs, StringBuilder out) {
        Map<String, String> ownDecls = new HashMap<String, String>();
        List<Attr> regularAttrs = new ArrayList<Attr>();
        NamedNodeMap attrMap = node.getAttributes();
        for (int i = 0; i < attrMap.getLength(); i++) {
            Attr a = (Attr) attrMap.item(i);
            String qName = a.getName();
            if (isNsAttr(qName)) {
                ownDecls.put(nsAttrPrefix(qName), a.getValue());
            } else {
                regularAttrs.add(a);
            }
        }

        Map<String, String> newInScopeNs = new HashMap<String, String>(inScopeNs);
        newInScopeNs.putAll(ownDecls);

        List<NsDecl> toRender = new ArrayList<NsDecl>();
        Map<String, String> newRenderedNs = new HashMap<String, String>(renderedNs);

        // The default namespace ('') is always relevant for an unprefixed
        // element, whether declared or not -- an explicit xmlns="" must be
        // emitted if an ancestor rendered a non-empty default namespace and
        // this element has none, to correctly undeclare it.
        String nodePrefix = prefixOf(node.getNodeName());
        if (nodePrefix.isEmpty()) {
            String uriDefault = newInScopeNs.containsKey("") ? newInScopeNs.get("") : "";
            String renderedDefault = newRenderedNs.containsKey("") ? newRenderedNs.get("") : "";
            if (!uriDefault.equals(renderedDefault)) {
                toRender.add(new NsDecl("", uriDefault));
                newRenderedNs.put("", uriDefault);
            }
        }

        Set<String> utilizedPrefixes = new TreeSet<String>();
        if (!nodePrefix.isEmpty()) { utilizedPrefixes.add(nodePrefix); }
        for (Attr a : regularAttrs) {
            String p = prefixOf(a.getName());
            if (!p.isEmpty()) { utilizedPrefixes.add(p); }
        }

        for (String prefix : utilizedPrefixes) {
            if (prefix.equals("xml")) { continue; } // implicit, never declared/rendered
            if (!newInScopeNs.containsKey(prefix)) { continue; } // used but never declared: malformed input, skip
            String uri = newInScopeNs.get(prefix);
            if (!uri.equals(newRenderedNs.get(prefix))) {
                toRender.add(new NsDecl(prefix, uri));
                newRenderedNs.put(prefix, uri);
            }
        }

        // Sort: default namespace first, then prefixed namespaces alphabetically.
        Collections.sort(toRender, new Comparator<NsDecl>() {
            public int compare(NsDecl x, NsDecl y) {
                if (x.prefix.isEmpty() && !y.prefix.isEmpty()) { return -1; }
                if (!x.prefix.isEmpty() && y.prefix.isEmpty()) { return 1; }
                return x.prefix.compareTo(y.prefix);
            }
        });

        List<Attr> sortedAttrs = new ArrayList<Attr>(regularAttrs);
        final Map<String, String> inScopeForSort = newInScopeNs;
        Collections.sort(sortedAttrs, new Comparator<Attr>() {
            public int compare(Attr x, Attr y) {
                String xp = prefixOf(x.getName()), yp = prefixOf(y.getName());
                String xUri = xp.isEmpty() ? "" : nullToEmpty(inScopeForSort.get(xp));
                String yUri = yp.isEmpty() ? "" : nullToEmpty(inScopeForSort.get(yp));
                if (xp.isEmpty() && !yp.isEmpty()) { return -1; }
                if (!xp.isEmpty() && yp.isEmpty()) { return 1; }
                if (!xUri.equals(yUri)) { return xUri.compareTo(yUri); }
                return localOf(x.getName()).compareTo(localOf(y.getName()));
            }
        });

        out.append('<').append(node.getNodeName());
        for (NsDecl d : toRender) {
            String nsName = d.prefix.isEmpty() ? "xmlns" : ("xmlns:" + d.prefix);
            out.append(' ').append(nsName).append("=\"").append(escapeAttr(d.uri)).append('"');
        }
        for (Attr a : sortedAttrs) {
            out.append(' ').append(a.getName()).append("=\"").append(escapeAttr(a.getValue())).append('"');
        }
        out.append('>');

        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                render((Element) child, newInScopeNs, newRenderedNs, out);
            } else if (child.getNodeType() == Node.TEXT_NODE || child.getNodeType() == Node.CDATA_SECTION_NODE) {
                out.append(escapeText(child.getNodeValue()));
            } else if (child.getNodeType() == Node.PROCESSING_INSTRUCTION_NODE) {
                String data = child.getNodeValue();
                out.append("<?").append(child.getNodeName());
                if (data != null && !data.isEmpty()) {
                    out.append(' ').append(data.replace("\r", "\n"));
                }
                out.append("?>");
            }
            // comments dropped: this is exc-c14n *without* comments.
        }

        out.append("</").append(node.getNodeName()).append('>');
    }

    private static boolean isNsAttr(String qName) {
        return qName.equals("xmlns") || qName.startsWith("xmlns:");
    }

    private static String nsAttrPrefix(String qName) {
        return qName.equals("xmlns") ? "" : qName.substring(6);
    }

    private static String prefixOf(String qName) {
        int idx = qName.indexOf(':');
        return idx == -1 ? "" : qName.substring(0, idx);
    }

    private static String localOf(String qName) {
        int idx = qName.indexOf(':');
        return idx == -1 ? qName : qName.substring(idx + 1);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String escapeText(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;");
    }

    private static String escapeAttr(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;")
                .replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;");
    }

    private static final class NsDecl {
        final String prefix;
        final String uri;
        NsDecl(String prefix, String uri) { this.prefix = prefix; this.uri = uri; }
    }
}
