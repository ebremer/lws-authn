package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier.VerificationMethod;

/**
 * Key extraction is static and side-effect free, so it can be driven without a Keycloak session or
 * network — which is where the interesting rules live: which methods in a controlled identifier
 * document a subject may authenticate with, and which it may not.
 */
class SelfSignedCidVerifierTest {

    private static final String VICTIM = "https://victim.example/cid";
    private static final String ATTACKER = "https://attacker.example/cid";

    /** A CID-conformant model: a JsonWebKey method, controlled by the subject, under authentication. */
    private static Model modelWithVictimKey() {
        Model model = ModelFactory.createDefaultModel();
        addMethod(model, VICTIM, VICTIM, VICTIM + "#k1", "{\"kid\":\"k1\",\"kty\":\"OKP\"}");
        return model;
    }

    private static void addMethod(Model model, String subject, String controller, String methodId, String jwk) {
        Resource subjectResource = model.createResource(subject);
        Resource method = model.createResource(methodId);
        method.addProperty(RDF.type, model.createResource(SsiCidConstants.JSON_WEB_KEY_TYPE));
        method.addProperty(model.createProperty(SsiCidConstants.SEC_CONTROLLER), model.createResource(controller));
        method.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK), model.createLiteral(jwk));
        subjectResource.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), method);
    }

    @Test
    void collectsKeyForLegitimateSubject() {
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromRdf(modelWithVictimKey(), VICTIM);
        assertEquals(1, methods.size());
        assertEquals("k1", methods.get(0).publicKeyJwk().path("kid").asText());
        assertEquals(VICTIM + "#k1", methods.get(0).id());
    }

    /**
     * P1-C5. A document may list a method controlled by somebody else — CID 1.0 makes {@code
     * controller} a required property precisely so a verifier can tell. Authenticating a subject with
     * a key it does not control would let anyone who can get a method into that document sign as it.
     */
    @Test
    void ignoresAMethodControlledBySomeoneElse() {
        Model model = ModelFactory.createDefaultModel();
        addMethod(model, VICTIM, ATTACKER, ATTACKER + "#evil", "{\"kid\":\"evil\",\"kty\":\"OKP\"}");
        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, VICTIM).isEmpty(),
                "a method the subject does not control must not be usable to authenticate as the subject");
    }

    /** P1-C5. Only a JsonWebKey carries a publicKeyJwk; anything else typed is not one. */
    @Test
    void ignoresAMethodOfAnotherType() {
        Model model = ModelFactory.createDefaultModel();
        Resource subject = model.createResource(VICTIM);
        Resource method = model.createResource(VICTIM + "#k1");
        method.addProperty(RDF.type, model.createResource(SsiCidConstants.SEC_NS + "Multikey"));
        method.addProperty(model.createProperty(SsiCidConstants.SEC_CONTROLLER), subject);
        method.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK),
                model.createLiteral("{\"kid\":\"k1\",\"kty\":\"OKP\"}"));
        subject.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), method);

        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, VICTIM).isEmpty());
    }

    /**
     * The subject is attacker-controlled. With a string-concatenated query, SPARQL metacharacters in
     * {@code sub} could break out of the {@code <...>} IRI. Bound as an IRI parameter, each payload
     * must fail closed: Jena either rejects the injection-risk IRI (throws) or treats it as one opaque,
     * non-matching IRI (empty result). It must never leak another subject's key.
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
            List<VerificationMethod> methods;
            try {
                methods = SelfSignedCidVerifier.collectFromRdf(model, inject);
            } catch (RuntimeException failsClosed) {
                continue; // Jena rejected the injection-risk IRI outright — safe
            }
            assertTrue(methods.isEmpty(),
                    "SPARQL injection via 'sub' must not leak another subject's key: " + inject);
        }
    }

    // ------------------------------------------------------------------------------- JSON-LD path

    private static String jsonLd(String id, String controller) {
        return "{\"@context\":[\"https://www.w3.org/ns/cid/v1\"],\"id\":\"" + id + "\","
                + "\"authentication\":[{\"id\":\"" + id + "#k1\",\"type\":\"JsonWebKey\","
                + "\"controller\":\"" + controller + "\","
                + "\"publicKeyJwk\":{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"X\",\"y\":\"Y\"}}]}";
    }

    @Test
    void readsAConformantJsonLdDocument() throws Exception {
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromJsonLd(jsonLd(VICTIM, VICTIM), VICTIM);
        assertEquals(1, methods.size());
        assertEquals("k1", methods.get(0).publicKeyJwk().path("kid").asText());
    }

    /**
     * P1-C4. The RDF path enforces {@code id == sub} implicitly by binding the subject; the JSON-LD
     * path used to enforce nothing at all, so the two disagreed about what counted as evidence.
     */
    @Test
    void rejectsAJsonLdDocumentAboutADifferentSubject() {
        assertThrows(java.io.IOException.class,
                () -> SelfSignedCidVerifier.collectFromJsonLd(jsonLd(ATTACKER, ATTACKER), VICTIM),
                "a document whose id is not the subject is not evidence about that subject");
    }

    @Test
    void rejectsAJsonLdDocumentWithNoId() {
        String noId = "{\"@context\":[\"https://www.w3.org/ns/cid/v1\"],\"authentication\":[]}";
        assertThrows(java.io.IOException.class,
                () -> SelfSignedCidVerifier.collectFromJsonLd(noId, VICTIM),
                "CID 1.0 requires an id in the topmost map");
    }

    /** P1-C5, on the JSON-LD path too. */
    @Test
    void ignoresAJsonLdMethodControlledBySomeoneElse() throws Exception {
        assertTrue(SelfSignedCidVerifier.collectFromJsonLd(jsonLd(VICTIM, ATTACKER), VICTIM).isEmpty());
    }

    // ------------------------------------------------------------------------------ key selection

    /**
     * P1-C3. The suite says the verifier MUST use the {@code kid} from the header to identify the
     * method. The old "if there is only one key, use it" fallback made the choice the verifier's
     * guess instead of the credential's assertion.
     */
    @Test
    void selectionRequiresAKid() {
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromRdf(modelWithVictimKey(), VICTIM);
        assertNull(SelfSignedCidVerifier.selectByKid(methods, null));
        assertNull(SelfSignedCidVerifier.selectByKid(methods, "  "));
        assertNull(SelfSignedCidVerifier.selectByKid(methods, "not-a-known-kid"));
        assertNotNull(SelfSignedCidVerifier.selectByKid(methods, "k1"));
    }

    /** CID 1.0 puts the key id in the method's own id fragment, so that is honoured as well. */
    @Test
    void selectsByTheMethodIdFragmentWhenTheJwkHasNoKid() {
        Model model = ModelFactory.createDefaultModel();
        addMethod(model, VICTIM, VICTIM, VICTIM + "#k2", "{\"kty\":\"OKP\"}");
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromRdf(model, VICTIM);
        assertNotNull(SelfSignedCidVerifier.selectByKid(methods, "k2"));
        assertNull(SelfSignedCidVerifier.selectByKid(methods, "k1"));
    }
}
