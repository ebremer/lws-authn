package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;

/**
 * Unit tests for {@link SelfSignedCidVerifier#collectFromRdf}. It is static and side-effect free, so
 * key extraction (and its resistance to SPARQL injection via the subject) can be tested without a
 * Keycloak session or network.
 */
class SelfSignedCidVerifierTest {

    private static final String VICTIM = "https://victim.example/cid";

    /** A model in which {@code VICTIM} publishes one publicKeyJwk under an authentication method. */
    private static Model modelWithVictimKey() {
        Model model = ModelFactory.createDefaultModel();
        Resource victim = model.createResource(VICTIM);
        Resource method = model.createResource(); // blank node
        victim.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), method);
        method.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK),
                model.createLiteral("{\"kid\":\"k1\",\"kty\":\"OKP\"}"));
        return model;
    }

    @Test
    void collectsKeyForLegitimateSubject() {
        List<JsonNode> jwks = SelfSignedCidVerifier.collectFromRdf(modelWithVictimKey(), VICTIM);
        assertEquals(1, jwks.size());
        assertEquals("k1", jwks.get(0).path("kid").asText());
    }

    /**
     * The subject is attacker-controlled. With the old string-concatenated query, SPARQL
     * metacharacters in {@code sub} could break out of the {@code <...>} IRI. Now it is bound as an
     * IRI parameter, so each payload must fail closed: Jena either rejects the injection-risk IRI
     * (throws) or treats it as one opaque, non-matching IRI (empty result). It must never leak
     * another subject's key. Both safe outcomes are caught and fail the verification in production,
     * where these calls run inside the verifier's try/catch.
     */
    @Test
    void subjectCannotInjectSparql() {
        Model model = modelWithVictimKey();
        String[] injections = {
            VICTIM + "> ?p ?o #",
            "https://attacker.example/x> ?r ?m . ?m2 <" + SsiCidConstants.SEC_PUBLIC_KEY_JWK + "> ?jwk #",
            "urn:x> ?p ?o } UNION { ?s ?rel ?m . ?m <" + SsiCidConstants.SEC_PUBLIC_KEY_JWK + "> ?jwk } #",
            "x\"}{ ?s ?p ?o",
        };
        for (String inject : injections) {
            List<JsonNode> jwks;
            try {
                jwks = SelfSignedCidVerifier.collectFromRdf(model, inject);
            } catch (RuntimeException failsClosed) {
                continue; // Jena rejected the injection-risk IRI outright — safe
            }
            assertTrue(jwks.isEmpty(),
                    "SPARQL injection via 'sub' must not leak another subject's key: " + inject);
        }
    }
}
