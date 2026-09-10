// Parses this proxy's JWT verification config, loaded from the shared
// KVM "signature" (entry key "{apiproxy.name}.jwt.verify") into
// signature.verify.jwt.config.json — a JSON object, e.g.:
//   {
//     "keystore": "orders-api-keystore",
//     "alias": "orders-api-signing-cert",
//     "understoodCriticalParams": ["x-txn-id"]
//   }
// keystore/alias feed VerifyJWS-Jwt-Compact/-Detached's
// <PublicKey><KeyStore ref="..."/><Alias ref="..."/></PublicKey> — the
// same ref-to-a-flow-variable pattern ServiceCallout/TargetEndpoint use
// for <SSLInfo><KeyStore ref="...">. understoodCriticalParams is this
// proxy's allow-list for JS-JWT-Verify-Check-Crit.
//
// A plain JS parse (not ExtractVariables/JSONPath) because
// understoodCriticalParams is an array — ExtractVariables' JSONPath
// extraction is built for scalar leaf values, not for pulling out a
// whole array as one variable.

(function parseJwtVerifyConfig() {
    var configJson = context.getVariable('signature.verify.jwt.config.json');
    var config = JSON.parse(configJson);

    if (!config.keystore || !config.alias) {
        throw new Error('signature.verify.jwt.config.json is missing "keystore" or "alias".');
    }

    context.setVariable('signature.verify.jwt.keystore.name', config.keystore);
    context.setVariable('signature.verify.jwt.keystore.alias', config.alias);
    context.setVariable('signature.verify.jwt.understood.crit.json', JSON.stringify(config.understoodCriticalParams || []));
})();
