/*
 * Copyright Erich Bremer.
 *
 * Validates a self-issued JWT as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/
 *
 * Algorithm:
 *   1. Reject alg == "none".
 *   2. The credential is self-issued: sub == iss == client_id (the controlled identifier).
 *   3. Dereference 'sub' to a controlled identifier document.
 *   4. Select the verification method whose key matches the JWT 'kid' (from the 'authentication'
 *      relationship), and read its publicKeyJwk.
 *   5. Validate the JWT signature against that key (RFC 7515 §5.2).
 *   6. Ensure the token is not expired.
 *
 * RDF parsing of the (possibly arbitrary-syntax) controlled identifier document uses Apache Jena;
 * the JWK itself is JSON, so key extraction is JSON-native.
 */
package com.ebremer.lws.authn.ssicid.verify;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

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

/**
 * @author Erich Bremer
 */
public class SelfSignedCidVerifier {

    private static final Logger log = Logger.getLogger(SelfSignedCidVerifier.class);

    private final KeycloakSession session;

    public SelfSignedCidVerifier(KeycloakSession session) {
        this.session = session;
    }

    public SsiCidVerificationResult verify(String credential) {
        SsiCidVerificationResult result = new SsiCidVerificationResult();
        result.setTraceId(Trace.newId());
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

            // 2. self-issued: sub == iss == client_id
            boolean selfIssued = sub != null && !sub.isBlank() && sub.equals(iss) && sub.equals(clientId);
            result.check("selfIssued", selfIssued);
            if (!selfIssued) {
                result.error("Claims 'sub', 'iss' and 'client_id' MUST all use the same URI "
                        + "(sub=" + sub + ", iss=" + iss + ", client_id=" + clientId + ")");
                return result.fail();
            }

            // 3-4. dereference the subject and select the verification method by kid
            List<JsonNode> publicKeyJwks = dereference(sub, result);
            if (publicKeyJwks == null) {
                return result.fail();
            }
            JsonNode jwk = selectByKid(publicKeyJwks, header.getKeyId());
            boolean keyFound = jwk != null;
            result.check("verificationMethodFound", keyFound);
            if (!keyFound) {
                result.error("No verification method in the controlled identifier document matched kid="
                        + header.getKeyId());
                return result.fail();
            }

            // 5. validate the signature against the selected key
            PublicKey publicKey = toPublicKey(jwk);
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
            if (signatureProvider == null) {
                result.check("signatureValid", false);
                result.error("No signature provider available for algorithm " + alg);
                return result.fail();
            }
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setKid(header.getKeyId());
            keyWrapper.setAlgorithm(alg);
            keyWrapper.setType(publicKey.getAlgorithm());
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
            boolean notExpired = exp != null && exp != 0 && token.isActive();
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "Credential is missing the required 'exp' claim"
                        : "Credential is expired or not yet valid");
                return result.fail();
            }

            // the suite REQUIRES an audience restriction
            String[] aud = token.getAudience();
            boolean audiencePresent = aud != null && aud.length > 0;
            result.check("audiencePresent", audiencePresent);
            if (!audiencePresent) {
                result.error("Credential is missing the required 'aud' claim");
                return result.fail();
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

    /** Dereferences the subject and returns the candidate public JWKs from its CID document. */
    private List<JsonNode> dereference(String sub, SsiCidVerificationResult result) {
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
            List<JsonNode> jwks = RdfParsing.isJsonLd(contentType, body)
                    ? collectFromJsonLd(body)
                    : collectFromRdf(RdfParsing.parseRdf(body, contentType, sub), sub);
            OutboundHttp.recordSuccess(sub);
            result.check("subjectDereferenced", true);
            return jwks;
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

    /** Collects every {@code publicKeyJwk} under {@code authentication}/{@code verificationMethod}. */
    public static List<JsonNode> collectFromJsonLd(String body) throws java.io.IOException {
        JsonNode doc = JsonSerialization.mapper.readTree(body);
        List<JsonNode> out = new ArrayList<>();
        collectMethods(doc.get("authentication"), out);
        collectMethods(doc.get("verificationMethod"), out);
        return out;
    }

    private static void collectMethods(JsonNode methods, List<JsonNode> out) {
        if (methods == null) {
            return;
        }
        for (JsonNode method : methods.isArray() ? methods : List.of(methods)) {
            JsonNode jwk = method.get("publicKeyJwk");
            if (jwk != null && jwk.isObject()) {
                out.add(jwk);
            }
        }
    }

    /**
     * Collects every {@code publicKeyJwk} literal reachable from the subject via Jena/SPARQL. The
     * subject is bound as an IRI parameter (never concatenated) so it cannot inject SPARQL.
     */
    public static List<JsonNode> collectFromRdf(Model model, String sub) {
        ParameterizedSparqlString pss = new ParameterizedSparqlString();
        pss.setNsPrefix("sec", SsiCidConstants.SEC_NS);
        pss.setCommandText("SELECT ?jwk WHERE { ?sub ?rel ?m . "
                + "FILTER(?rel = sec:authenticationMethod || ?rel = sec:verificationMethod) "
                + "?m sec:publicKeyJwk ?jwk }");
        pss.setIri("sub", sub);
        List<JsonNode> out = new ArrayList<>();
        try (QueryExecution qe = QueryExecutionFactory.create(pss.asQuery(), model)) {
            ResultSet rs = qe.execSelect();
            while (rs.hasNext()) {
                String jwkLexical = rs.next().getLiteral("jwk").getLexicalForm();
                try {
                    out.add(JsonSerialization.mapper.readTree(jwkLexical));
                } catch (Exception ignore) {
                    // skip non-JSON literals
                }
            }
        }
        return out;
    }

    /** Picks the JWK whose {@code kid} matches the token header (or the only key if no kid). */
    public static JsonNode selectByKid(List<JsonNode> jwks, String kid) {
        if (jwks.isEmpty()) {
            return null;
        }
        if (kid == null || kid.isBlank()) {
            return jwks.size() == 1 ? jwks.get(0) : null;
        }
        for (JsonNode jwk : jwks) {
            if (kid.equals(jwk.path("kid").asText(null))) {
                return jwk;
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
