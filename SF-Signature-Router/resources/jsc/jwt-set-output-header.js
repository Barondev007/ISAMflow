// Writes the assembled JWS (signature.jwt.jws, set by whichever of
// AM-JWT-Assemble-JWS-Compact / -Detached ran) into the request header
// named by this proxy's KVM config (signature.jwt.output.header, see
// KVM-Get-JWT-Output-Header) — plain header name -> JWS value, no
// "Bearer " prefix or other wrapping, since the header isn't assumed to
// be Authorization.
//
// Done in JS rather than AssignMessage's <Header name="..."> because a
// dynamic/templated header NAME (as opposed to header VALUE) is not a
// capability confirmed safe to rely on in Apigee — see the KVM
// mapIdentifier and VerifyJWS KeyStore-ref lessons elsewhere in this
// project, both cases where an identifier-like attribute turned out NOT
// to support "{variable}" substitution despite looking like it should.
// context.setVariable() with a dynamically-built variable name has no
// such ambiguity: it's a plain JS string argument.
//
// Sets the header on the REQUEST message, matching how every worked
// example in this project calls SF-Signature-Router (from a proxy's
// request PreFlow, before the signed request reaches its target). A
// proxy that calls this shared flow from a response flow instead — to
// sign an outbound response — should change 'request.header.' below to
// 'response.header.'.

(function setJwtOutputHeader() {
    var headerName = context.getVariable('signature.jwt.output.header');
    if (!headerName) {
        throw new Error('signature.jwt.output.header is not set — check KVM-Get-JWT-Output-Header ran and this proxy has a {apiproxy.name}.jwt.output KVM entry.');
    }

    var jws = context.getVariable('signature.jwt.jws');
    if (!jws) {
        throw new Error('signature.jwt.jws is not set — AM-JWT-Assemble-JWS-Compact/-Detached should have run before this step.');
    }

    context.setVariable('request.header.' + headerName, jws);
})();
