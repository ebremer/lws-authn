/*
 * Copyright Erich Bremer.
 *
 * Validates a self-issued JWT as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/
 *
 * Algorithm:
 *   1. Reject alg == "none", and any critical header this provider does not implement.
 *   2. The credential is self-issued: sub == iss == client_id (the controlled identifier).
 *   3. Dereference 'sub' to a controlled identifier document whose 'id' equals 'sub'.
 *   4. Select, by the JWT 'kid', a JsonWebKey verification method controlled by the subject (from the
 *      'authentication' or 'verificationMethod' relationship), and read its publicKeyJwk.
 *   5. Validate the JWT signature against that key (RFC 7515 §5.2), with the algorithm pinned to the
 *      key type.
 *   6. Ensure the token carries iat and exp, is not expired, and is restricted to the target audience.
 *
 * RDF parsing of the (possibly arbitrary-syntax) controlled identifier document uses Apache Jena;
 * the JWK itself is JSON, so key extraction is JSON-native.
 */
package com.ebremer.lws.authn.ssicid.verify;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.jose.KeyIdFragment;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.verify.Trace;
import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.verify.ReplayCache;

/**
 * @author Erich Bremer
 */
public class SelfSignedCidVerifier {

    private static final Logger log = Logger.getLogger(SelfSignedCidVerifier.class);

    private final KeycloakSession session;
    private final ReplayCache replayCache;

    public SelfSignedCidVerifier(KeycloakSession session) {
        this(session, null);
    }

    /**
     * @param replayCache optional, and normally {@code null}. See {@link ReplayCache}: a verify
     *                    endpoint is asked about the same live credential repeatedly, so refusing a
     *                    second look is only correct for a caller that treats one verification as one
     *                    use.
     */
    public SelfSignedCidVerifier(KeycloakSession session, ReplayCache replayCache) {
        this.session = session;
        this.replayCache = replayCache;
    }

    public SsiCidVerificationResult verify(String credential) {
        return verify(credential, null);
    }

    /**
     * @param credential       the self-issued JWT
     * @param expectedAudience the authorization server this verifier speaks for. The suite says the
     *                         {@code aud} claim "MUST include the target authorization server", which
     *                         only means anything if the verifier knows which one it is; without it
     *                         only the presence of an audience can be checked.
     */
    public SsiCidVerificationResult verify(String credential, String expectedAudience) {
        SsiCidVerificationResult result = new SsiCidVerificationResult();
        result.setTraceId(Trace.newId());
        result.setTokenType(SsiCidConstants.TOKEN_TYPE_JWT);
        try {
            JWSInput jws = new JWSInput(credential);
            JWSHeader header = jws.getHeader();
            JsonWebToken token = JsonSerialization.readValue(jws.getContent(), JsonWebToken.class);

            String sub = token.getSubject();
            String iss = token.getIssuer();
            String clientId = asString(token.getOtherClaims().get("client_id"));
            result.setSubject(sub);

            // 1. alg must not be "none"
            String alg = header.getRawAlgorithm();
            boolean algOk = alg != null && !"none".equalsIgnoreCase(alg);
            result.check("signingAlgorithmNotNone", algOk);
            if (!algOk) {
                result.error("Credential MUST NOT use 'none' as the signing algorithm");
                return result.fail();
            }

            // RFC 7515 5.2, cited normatively by this suite: reject critical headers we do not implement.
            List<String> critical = JwsChecks.criticalHeaders(jws);
            result.check("noUnsupportedCriticalHeaders", critical.isEmpty());
            if (!critical.isEmpty()) {
                result.error("Credential carries unsupported critical header parameters: " + critical);
                return result.fail();
            }

            boolean typeOk = JwsChecks.typeIsJwtOrAbsent(header.getType());
            result.check("typeIsJwt", typeOk);
            if (!typeOk) {
                result.error("Credential 'typ' header is not a JWT type");
                return result.fail();
            }

            // 2. self-issued: sub == iss == client_id
            boolean selfIssued = sub != null && !sub.isBlank() && sub.equals(iss) && sub.equals(clientId);
            result.check("selfIssued", selfIssued);
            if (!selfIssued) {
                result.error("Claims 'sub', 'iss' and 'client_id' MUST all use the same URI "
                        + "(sub=" + sub + ", iss=" + iss + ", client_id=" + clientId + ")");
                return result.fail();
            }
            result.setClient(clientId);

            // "The verifier MUST use the `kid` (key id) value from the signed JWT header to identify a
            // verification method." Falling back to "the only key" when there is no kid would make the
            // selection the verifier's guess rather than the credential's assertion.
            String kid = header.getKeyId();
            boolean kidPresent = kid != null && !kid.isBlank();
            result.check("keyIdPresent", kidPresent);
            if (!kidPresent) {
                result.error("Credential header is missing the 'kid' used to select a verification method");
                return result.fail();
            }

            // 3-4. dereference the subject and select the verification method by kid
            List<VerificationMethod> methods = dereference(sub, result);
            if (methods == null) {
                return result.fail();
            }
            VerificationMethod method = selectByKid(methods, kid);
            boolean keyFound = method != null;
            result.check("verificationMethodFound", keyFound);
            if (!keyFound) {
                result.error("No JsonWebKey verification method controlled by <" + sub
                        + "> matched kid=" + kid);
                return result.fail();
            }
            JsonNode jwk = method.publicKeyJwk();

            // 5. validate the signature against the selected key
            PublicKey publicKey = toPublicKey(jwk);

            // Pin the declared algorithm to the key actually published. Without this a forged token
            // could claim a symmetric alg (HS256) and have the subject's public key treated as the HMAC
            // secret. It fails closed inside Keycloak today, but only by accident of how the provider
            // reacts to a PublicKey where it wants a SecretKey — which is not a security guarantee.
            boolean algMatchesKey = JwsChecks.algMatchesKey(alg, publicKey);
            result.check("algorithmMatchesKey", algMatchesKey);
            if (!algMatchesKey) {
                result.error("Credential 'alg' " + alg + " is not consistent with the published "
                        + publicKey.getAlgorithm() + " verification method");
                return result.fail();
            }

            // The JWK's own metadata must agree too: a key published for encryption, or declaring a
            // different algorithm, is not a key this signature may be checked against.
            String jwkUse = jwk.path("use").asText(null);
            String jwkAlg = jwk.path("alg").asText(null);
            boolean jwkUsable = (jwkUse == null || "sig".equals(jwkUse)) && (jwkAlg == null || jwkAlg.equals(alg));
            result.check("verificationMethodUsableForSigning", jwkUsable);
            if (!jwkUsable) {
                result.error("The selected verification method is not published for signing with " + alg);
                return result.fail();
            }

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
            if (signatureProvider == null) {
                result.check("signatureValid", false);
                result.error("No signature provider available for algorithm " + alg);
                return result.fail();
            }
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setKid(header.getKeyId());
            keyWrapper.setAlgorithm(alg);
            keyWrapper.setType(JwsChecks.keycloakKeyType(publicKey));
            keyWrapper.setUse(KeyUse.SIG);
            keyWrapper.setPublicKey(publicKey);

            boolean signatureValid = signatureProvider.verifier(keyWrapper).verify(
                    jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jws.getSignature());
            result.check("signatureValid", signatureValid);
            if (!signatureValid) {
                result.error("Credential signature is invalid");
                return result.fail();
            }

            // 6. expiry (and not-before) window. The credential MUST carry an 'exp': Keycloak's
            // isActive() treats a missing exp as "never expires", which would let a captured
            // self-issued JWT be replayed forever ('aud' bounds where it may be used, not for how long).
            Long exp = token.getExp();
            boolean notExpired = JwsChecks.withinValidityWindow(token);
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "Credential is missing the required 'exp' claim"
                        : "Credential is expired or not yet valid");
                return result.fail();
            }

            // "The JWT MUST include an `iat` (issued at) claim." Without it there is no lower bound on
            // the credential's age, so a stolen token's provenance cannot be reasoned about at all.
            Long iat = token.getIat();
            boolean issuedAtPresent = iat != null && iat != 0;
            result.check("issuedAtPresent", issuedAtPresent);
            if (!issuedAtPresent) {
                result.error("Credential is missing the required 'iat' claim");
                return result.fail();
            }

            // the suite REQUIRES an audience restriction, and that it name the target authorization server
            String[] aud = token.getAudience();
            boolean audiencePresent = aud != null && aud.length > 0;
            result.check("audiencePresent", audiencePresent);
            if (!audiencePresent) {
                result.error("Credential is missing the required 'aud' claim");
                return result.fail();
            }
            if (expectedAudience != null && !expectedAudience.isBlank()) {
                boolean audienceMatched = JwsChecks.audienceIncludes(aud, expectedAudience);
                result.check("audienceMatched", audienceMatched);
                if (!audienceMatched) {
                    result.error("Credential 'aud' does not include the target audience <" + expectedAudience + ">");
                    return result.fail();
                }
            }

            if (replayCache != null) {
                boolean firstSighting = replayCache.firstSighting(iss, token.getId());
                result.check("notReplayed", firstSighting);
                if (!firstSighting) {
                    result.error("Credential 'jti' has already been verified within the replay window");
                    return result.fail();
                }
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            // Never echo the exception to the caller: it can name internal hosts, ports and library
            // internals. The detail goes to the log under the result's trace id.
            log.debugf(e, "[%s] LWS self-signed CID credential verification failed", result.getTraceId());
            result.error("Credential could not be validated");
            return result.fail();
        }
        return result;
    }

    /** Dereferences the subject and returns the verification methods its CID document controls. */
    private List<VerificationMethod> dereference(String sub, SsiCidVerificationResult result) {
        try {
            // OutboundHttp applies the SSRF policy, refuses a host that has been failing, and fetches
            // through a client that follows no redirects and resolves only vetted addresses.
            SimpleHttp.Response response = OutboundHttp.get(sub, session)
                    .header("Accept", SsiCidConstants.TURTLE + ", " + SsiCidConstants.JSON_LD + ";q=0.9, "
                            + SsiCidConstants.N_TRIPLES + ";q=0.8, " + SsiCidConstants.RDF_XML + ";q=0.7")
                    .asResponse();
            if (response.getStatus() != 200) {
                log.debugf("[%s] dereferencing sub <%s> returned HTTP %d", result.getTraceId(), sub,
                        response.getStatus());
                OutboundHttp.recordFailure(sub);
                result.check("subjectDereferenced", false);
                result.error("Dereferencing 'sub' <" + sub + "> did not return a controlled identifier document");
                return null;
            }
            String contentType = response.getFirstHeader("Content-Type");
            String body = response.asString();
            // Processed as real JSON-LD where possible, so a conforming document from another
            // implementation works regardless of how it spells things; the compact reader remains for
            // a document naming a context this provider does not bundle.
            Model model = RdfParsing.parse(body, contentType, sub);
            List<VerificationMethod> methods;
            if (model != null) {
                methods = collectFromRdf(model, sub);
            } else {
                log.debugf("[%s] sub <%s> is JSON-LD this provider cannot process; reading the compact shape",
                        result.getTraceId(), sub);
                methods = collectFromJsonLd(body, sub);
            }
            OutboundHttp.recordSuccess(sub);
            result.check("subjectDereferenced", true);
            result.check("subjectIdMatches", true);
            return methods;
        } catch (RdfParsing.UnsupportedSyntaxException wrongSyntax) {
            // Distinguished from the generic failure below because it is actionable and gives nothing
            // away: the media type is one the remote server chose to advertise publicly, and naming it
            // is the difference between "your document is not RDF" and "something went wrong".
            log.debugf("[%s] sub <%s> was served as '%s', which is not an RDF syntax this verifier reads",
                    result.getTraceId(), sub, wrongSyntax.getContentType());
            OutboundHttp.recordFailure(sub);
            result.check("subjectDereferenced", false);
            result.error("The document at 'sub' <" + sub + "> was served as '" + wrongSyntax.getContentType()
                    + "', which is not an RDF syntax this verifier reads");
            return null;
        } catch (Exception e) {
            // The cause can name the address the host resolved to, so it is logged, not returned.
            log.debugf(e, "[%s] could not dereference or parse sub <%s>", result.getTraceId(), sub);
            OutboundHttp.recordFailure(sub);
            result.check("subjectDereferenced", false);
            result.error("Failed to dereference 'sub' <" + sub + "> as a controlled identifier document");
            return null;
        }
    }

    // ---- key extraction (static + side-effect free, so it is unit-testable without a session) ----

    /**
     * A {@code JsonWebKey} verification method from a controlled identifier document.
     *
     * @param id           the method's own identifier, conventionally {@code <subject>#<kid>}
     * @param publicKeyJwk its public JWK
     */
    public record VerificationMethod(String id, JsonNode publicKeyJwk) {
    }

    /**
     * Collects the subject's {@code JsonWebKey} verification methods from a compact JSON-LD document.
     *
     * <p>The document's {@code id} must equal {@code sub}: CID 1.0 requires an {@code id} in the
     * topmost map, and a document that does not claim to describe this subject is not evidence about
     * it. Each method must be a {@code JsonWebKey} controlled by the subject — a document may embed
     * methods controlled by someone else, and those are not keys this subject may authenticate with.</p>
     */
    public static List<VerificationMethod> collectFromJsonLd(String body, String sub) throws java.io.IOException {
        JsonNode doc = JsonSerialization.mapper.readTree(body);
        String id = doc.path("id").asText(doc.path("@id").asText(null));
        if (id == null || !id.equals(sub)) {
            throw new java.io.IOException("controlled identifier document 'id' does not equal the subject");
        }
        List<VerificationMethod> out = new ArrayList<>();
        collectMethods(doc.get("authentication"), sub, out);
        collectMethods(doc.get("verificationMethod"), sub, out);
        return out;
    }

    private static void collectMethods(JsonNode methods, String sub, List<VerificationMethod> out) {
        if (methods == null) {
            return;
        }
        for (JsonNode method : methods.isArray() ? methods : List.of(methods)) {
            if (!method.isObject()) {
                continue; // a bare reference to a method defined elsewhere; nothing to verify against
            }
            JsonNode jwk = method.get("publicKeyJwk");
            if (jwk == null || !jwk.isObject()) {
                continue;
            }
            if (!"JsonWebKey".equals(method.path("type").asText(null))) {
                continue;
            }
            if (!sub.equals(method.path("controller").asText(null))) {
                continue;
            }
            out.add(new VerificationMethod(method.path("id").asText(null), jwk));
        }
    }

    /**
     * Collects the subject's {@code JsonWebKey} verification methods via Jena/SPARQL. The subject is
     * bound as an IRI parameter (never concatenated) so it cannot inject SPARQL, and the query itself
     * requires the method to be a {@code JsonWebKey} the subject controls.
     */
    public static List<VerificationMethod> collectFromRdf(Model model, String sub) {
        ParameterizedSparqlString pss = new ParameterizedSparqlString();
        pss.setNsPrefix("sec", SsiCidConstants.SEC_NS);
        pss.setCommandText("SELECT ?m ?jwk WHERE { ?sub ?rel ?m . "
                + "FILTER(?rel = ?authentication || ?rel = ?verificationMethod) "
                + "?m a ?jsonWebKey ; ?controller ?sub ; ?publicKeyJwk ?jwk }");
        pss.setIri("sub", sub);
        pss.setIri("authentication", SsiCidConstants.SEC_AUTHENTICATION);
        pss.setIri("verificationMethod", SsiCidConstants.SEC_VERIFICATION_METHOD);
        pss.setIri("jsonWebKey", SsiCidConstants.JSON_WEB_KEY_TYPE);
        pss.setIri("controller", SsiCidConstants.SEC_CONTROLLER);
        pss.setIri("publicKeyJwk", SsiCidConstants.SEC_PUBLIC_KEY_JWK);
        List<VerificationMethod> out = new ArrayList<>();
        try (QueryExecution qe = QueryExecutionFactory.create(pss.asQuery(), model)) {
            ResultSet rs = qe.execSelect();
            while (rs.hasNext()) {
                var row = rs.next();
                String jwkLexical = row.getLiteral("jwk").getLexicalForm();
                try {
                    var node = row.get("m");
                    out.add(new VerificationMethod(node.isURIResource() ? node.asResource().getURI() : null,
                            JsonSerialization.mapper.readTree(jwkLexical)));
                } catch (Exception ignore) {
                    // skip non-JSON literals
                }
            }
        }
        return out;
    }

    /**
     * Picks the method the JWT's {@code kid} names — by the JWK's own {@code kid}, or by the fragment
     * of the method's {@code id}, which is where CID 1.0 conventionally puts it
     * ({@code <subject>#<kid>}). There is no fallback to "the only key": the credential says which key
     * signed it, and honouring that is the point of the check.
     *
     * <p>The fragment is compared both raw and percent-decoded: a {@code kid} is arbitrary text, so any
     * document that puts one in an IRI fragment has to encode it (this provider does — see
     * {@link KeyIdFragment}), and a comparison that only looked at the raw fragment would fail to find
     * the very method the credential names.</p>
     */
    public static VerificationMethod selectByKid(List<VerificationMethod> methods, String kid) {
        if (methods.isEmpty() || kid == null || kid.isBlank()) {
            return null;
        }
        for (VerificationMethod method : methods) {
            if (kid.equals(method.publicKeyJwk().path("kid").asText(null))) {
                return method;
            }
        }
        for (VerificationMethod method : methods) {
            String id = method.id();
            int hash = id == null ? -1 : id.lastIndexOf('#');
            if (hash < 0) {
                continue;
            }
            String fragment = id.substring(hash + 1);
            if (kid.equals(fragment) || kid.equals(KeyIdFragment.decode(fragment))) {
                return method;
            }
        }
        return null;
    }

    /** Builds a public key from a JWK JSON object. */
    public static PublicKey toPublicKey(JsonNode jwkNode) throws java.io.IOException {
        JWK jwk = JsonSerialization.readValue(jwkNode.toString(), JWK.class);
        return JWKParser.create(jwk).toPublicKey();
    }

    private static String asString(Object value) {
        return value == null ? null : value.toString();
    }
}
