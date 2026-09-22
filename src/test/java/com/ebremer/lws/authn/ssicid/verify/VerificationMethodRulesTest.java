/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;

import org.apache.jena.datatypes.xsd.XSDDatatype;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier.VerificationMethod;

/**
 * Which verification methods in a controlled identifier document a subject may authenticate with —
 * CID 1.0 §2.2, §2.3 and §3.3, which the self-signed CID suite cites normatively — on both the compact
 * JSON path and the RDF path.
 */
class VerificationMethodRulesTest {

    private static final String SUB = "https://controller.example/123";
    private static final String ED25519_MULTIKEY = "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu";
    private static final String P256_JWK = "{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";

    private static List<VerificationMethod> json(String document) throws Exception {
        return SelfSignedCidVerifier.collectFromJsonLd(document, SUB);
    }

    private static String multikey(String id, String controller, String extra) {
        return "{\"id\":\"" + id + "\",\"type\":\"Multikey\",\"controller\":\"" + controller + "\","
                + "\"publicKeyMultibase\":\"" + ED25519_MULTIKEY + "\"" + extra + "}";
    }

    /** CID 1.0 §3.3 Example 20, the "minimum conformant controlled identifier document", verbatim. */
    private static final String MINIMUM_CONFORMANT = "{\"@context\":\"https://www.w3.org/ns/cid/v1\","
            + "\"id\":\"" + SUB + "\",\"verificationMethod\":[" + multikey(SUB + "#key-456", SUB, "") + "],"
            + "\"authentication\":[\"" + SUB + "#key-456\"]}";

    // --------------------------------------------------------------------------- relationships

    /** "Each verification method MAY be embedded or referenced" (CID 1.0 §2.3.1). */
    @Test
    void aMethodReferencedFromAuthenticationIsUsable() throws Exception {
        List<VerificationMethod> methods = json(MINIMUM_CONFORMANT);
        assertEquals(1, methods.size());
        VerificationMethod method = methods.get(0);
        assertEquals(SUB + "#key-456", method.id());
        assertEquals("Multikey", method.type());
        assertEquals("OKP", method.publicKeyJwk().path("kty").asText());
        assertEquals("EdDSA", method.publicKeyJwk().path("alg").asText());
        assertNotNull(method.publicKey());
    }

    /**
     * CID 1.0 §2.3: "Verification methods that are not associated with a particular verification
     * relationship cannot be used for that verification relationship." A key published only for
     * assertions is not one the subject authenticates with — the verifier used to accept any method
     * defined under {@code verificationMethod}.
     */
    @Test
    void aMethodNotAssociatedWithAuthenticationIsNotUsable() throws Exception {
        String assertionOnly = "{\"id\":\"" + SUB + "\",\"verificationMethod\":["
                + multikey(SUB + "#key-456", SUB, "") + "],\"assertionMethod\":[\"" + SUB + "#key-456\"]}";
        assertTrue(json(assertionOnly).isEmpty());

        String definedOnly = "{\"id\":\"" + SUB + "\",\"verificationMethod\":["
                + multikey(SUB + "#key-456", SUB, "") + "]}";
        assertTrue(json(definedOnly).isEmpty());
    }

    @Test
    void aRelativeReferenceResolvesAgainstTheDocument() throws Exception {
        String relative = "{\"id\":\"" + SUB + "\",\"verificationMethod\":[" + multikey("#k1", SUB, "")
                + "],\"authentication\":[\"#k1\"]}";
        List<VerificationMethod> methods = json(relative);
        assertEquals(1, methods.size());
        assertEquals(SUB + "#k1", methods.get(0).id());
    }

    /** DID 1.1 §3.2.1: a relative DID URL is a fragment of the DID. */
    @Test
    void aDidDocumentsRelativeMethodIdResolvesAgainstTheDid() throws Exception {
        String did = "did:web:example.com";
        String doc = "{\"id\":\"" + did + "\",\"verificationMethod\":[" + multikey("#key-1", did, "")
                + "],\"authentication\":[\"#key-1\"]}";
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromJsonLd(doc, did);
        assertEquals(1, methods.size());
        assertEquals(did + "#key-1", methods.get(0).id());
    }

    /** A reference is resolved within the subject's document; it is not followed anywhere else. */
    @Test
    void aReferenceToAnotherDocumentIsNotFollowed() throws Exception {
        String external = "{\"id\":\"" + SUB + "\",\"authentication\":[\"https://other.example/doc#k1\"]}";
        assertTrue(json(external).isEmpty());
    }

    /**
     * CID 1.0 §3.3 takes a method's document from its identifier and requires that document's id and
     * the method's controller to be that URL — so a method whose id names another document is not one
     * this document can vouch for.
     */
    @Test
    void aMethodWhoseIdBelongsToAnotherDocumentIsNotUsable() throws Exception {
        String foreignId = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + multikey("https://other.example/doc#k1", SUB, "") + "]}";
        assertTrue(json(foreignId).isEmpty());
    }

    /**
     * A subject may itself carry a fragment (a Solid-style WebID); its keys are fragments of the same
     * document, so they are in the subject's document even though their ids do not start with the
     * subject as written.
     */
    @Test
    void aSubjectWithAFragmentStillOwnsTheKeysInItsDocument() throws Exception {
        String webId = "https://alice.example/profile/card#me";
        String doc = "{\"id\":\"" + webId + "\",\"authentication\":["
                + multikey("https://alice.example/profile/card#key-1", webId, "") + "]}";
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromJsonLd(doc, webId);
        assertEquals(1, methods.size());
        assertSame(methods.get(0), SelfSignedCidVerifier.selectByKid(methods, "key-1"));

        String foreign = "{\"id\":\"" + webId + "\",\"authentication\":["
                + multikey("https://alice.example/other#key-1", webId, "") + "]}";
        assertTrue(SelfSignedCidVerifier.collectFromJsonLd(foreign, webId).isEmpty());
    }

    // ------------------------------------------------------------------------------ key material

    /** CID 1.0 §2.2.3: publicKeyJwk "MUST NOT include any members of the private information class". */
    @Test
    void aJsonWebKeyPublishingAPrivateKeyIsNotUsable() throws Exception {
        String leaked = "{\"id\":\"" + SUB + "\",\"authentication\":[{\"id\":\"" + SUB + "#k1\","
                + "\"type\":\"JsonWebKey\",\"controller\":\"" + SUB + "\",\"publicKeyJwk\":"
                + P256_JWK.replace("}", ",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}") + "}]}";
        assertTrue(json(leaked).isEmpty());
    }

    @Test
    void aMultikeyThatIsNotACanonicalSupportedPublicKeyIsNotUsable() throws Exception {
        for (String bad : new String[]{"z1" + ED25519_MULTIKEY.substring(1),                   // non-canonical
                                       "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",   // secp256k1
                                       "not-multibase"}) {
            String doc = "{\"id\":\"" + SUB + "\",\"authentication\":[{\"id\":\"" + SUB + "#k1\","
                    + "\"type\":\"Multikey\",\"controller\":\"" + SUB + "\",\"publicKeyMultibase\":\"" + bad + "\"}]}";
            assertTrue(json(doc).isEmpty(), bad);
        }
    }

    // ---------------------------------------------------------------------- revocation and expiry

    @Test
    void readsRevocationAndExpiry() throws Exception {
        String doc = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + multikey(SUB + "#revoked", SUB, ",\"revoked\":\"2020-01-01T00:00:00Z\"") + ","
                + multikey(SUB + "#expired", SUB, ",\"expires\":\"2021-06-01T12:00:00+02:00\"") + ","
                + multikey(SUB + "#current", SUB, ",\"expires\":\"2999-01-01T00:00:00Z\"") + "]}";
        List<VerificationMethod> methods = json(doc);
        assertEquals(3, methods.size());
        Instant now = Instant.now();

        VerificationMethod revoked = SelfSignedCidVerifier.selectByKid(methods, "revoked");
        assertEquals(Instant.parse("2020-01-01T00:00:00Z"), revoked.revoked());
        assertTrue(revoked.inactiveReason(now).startsWith("was revoked at"), revoked.inactiveReason(now));

        VerificationMethod expired = SelfSignedCidVerifier.selectByKid(methods, "expired");
        assertEquals(Instant.parse("2021-06-01T10:00:00Z"), expired.expires());
        assertTrue(expired.inactiveReason(now).startsWith("expired at"), expired.inactiveReason(now));

        assertNull(SelfSignedCidVerifier.selectByKid(methods, "current").inactiveReason(now));
    }

    /** An unreadable revocation date is not evidence that a key was never revoked. */
    @Test
    void aMethodWithAnUnreadableDateIsNotUsable() throws Exception {
        for (String bad : new String[]{"yesterday", "2020-01-01T00:00:00", "2020-01-01"}) {
            String doc = "{\"id\":\"" + SUB + "\",\"authentication\":["
                    + multikey(SUB + "#k1", SUB, ",\"revoked\":\"" + bad + "\"") + "]}";
            assertTrue(json(doc).isEmpty(), bad);
        }
    }

    // ---------------------------------------------------------------------------------- the RDF path

    private static Resource method(Model model, String id, String type) {
        Resource method = model.createResource(id);
        method.addProperty(RDF.type, model.createResource(type));
        method.addProperty(model.createProperty(SsiCidConstants.SEC_CONTROLLER), model.createResource(SUB));
        return method;
    }

    /** In RDF the rule is one triple: the subject's sec:authenticationMethod must name the method. */
    @Test
    void rdfOnlyAMethodNamedByAuthenticationCounts() {
        Model model = ModelFactory.createDefaultModel();
        Resource subject = model.createResource(SUB);
        Resource defined = method(model, SUB + "#k1", SsiCidConstants.JSON_WEB_KEY_TYPE);
        defined.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK), model.createLiteral(P256_JWK));
        subject.addProperty(model.createProperty(SsiCidConstants.SEC_VERIFICATION_METHOD), defined);
        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty());

        subject.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), defined);
        assertEquals(1, SelfSignedCidVerifier.collectFromRdf(model, SUB).size());
    }

    @Test
    void rdfReadsAMultikeyAndItsRevocation() {
        Model model = ModelFactory.createDefaultModel();
        Resource subject = model.createResource(SUB);
        Resource multikey = method(model, SUB + "#k1", SsiCidConstants.MULTIKEY_TYPE);
        multikey.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE),
                model.createTypedLiteral(ED25519_MULTIKEY, SsiCidConstants.SEC_NS + "multibase"));
        multikey.addProperty(model.createProperty(SsiCidConstants.SEC_REVOKED),
                model.createTypedLiteral("2020-01-01T00:00:00Z", XSDDatatype.XSDdateTime));
        subject.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), multikey);

        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromRdf(model, SUB);
        assertEquals(1, methods.size());
        assertEquals("Multikey", methods.get(0).type());
        assertNotNull(methods.get(0).publicKey());
        assertEquals(Instant.parse("2020-01-01T00:00:00Z"), methods.get(0).revoked());
    }

    /**
     * The real JSON-LD path, through the bundled CID context — whose Multikey and JsonWebKey terms are
     * type-scoped, so this also checks that publicKeyMultibase and revoked expand as the RDF reader
     * expects.
     */
    @Test
    void jsonLdProcessingOfAMultikeyDocumentFindsTheMethod() {
        String doc = MINIMUM_CONFORMANT.replace(multikey(SUB + "#key-456", SUB, ""),
                multikey(SUB + "#key-456", SUB, ",\"revoked\":\"2020-01-01T00:00:00Z\""));
        Model model = RdfParsing.parseJsonLd(doc, SUB);
        List<VerificationMethod> methods = SelfSignedCidVerifier.collectFromRdf(model, SUB);
        assertEquals(1, methods.size());
        assertEquals(SUB + "#key-456", methods.get(0).id());
        assertEquals("Multikey", methods.get(0).type());
        assertEquals(Instant.parse("2020-01-01T00:00:00Z"), methods.get(0).revoked());
    }

    // ---------------------------------------------------------------------------------- selection

    @Test
    void aKidThatIsTheFullMethodIdSelectsIt() throws Exception {
        List<VerificationMethod> methods = json(MINIMUM_CONFORMANT);
        assertSame(methods.get(0), SelfSignedCidVerifier.selectByKid(methods, SUB + "#key-456"));
        assertSame(methods.get(0), SelfSignedCidVerifier.selectByKid(methods, "key-456"));
        assertSame(methods.get(0), SelfSignedCidVerifier.selectByKid(methods, "#key-456"));
    }

    /** Matching the fragment alone must not let a kid naming another document select this one's key. */
    @Test
    void aKidNamingAMethodInAnotherDocumentSelectsNothing() throws Exception {
        List<VerificationMethod> methods = json(MINIMUM_CONFORMANT);
        assertNull(SelfSignedCidVerifier.selectByKid(methods, "https://attacker.example/doc#key-456"));
        assertNull(SelfSignedCidVerifier.selectByKid(methods, "did:key:" + ED25519_MULTIKEY + "#key-456"));
    }
}
