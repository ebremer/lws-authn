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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
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

    /**
     * R-06. A {@code revoked} or {@code expires} that is not a string used to read as "never": the key
     * stayed usable. Whatever its shape, a value that is there is either read as one date or makes the
     * method unusable.
     */
    @Test
    void aRevocationThatIsNotAStringIsNotIgnored() throws Exception {
        for (String property : new String[]{"revoked", "expires"}) {
            for (String value : new String[]{
                    "[\"2000-01-01T00:00:00Z\",\"2999-01-01T00:00:00Z\"]",
                    "[\"2999-01-01T00:00:00Z\",\"2000-01-01T00:00:00Z\"]",
                    "[]", "946684800", "true", "{}", "{\"@id\":\"#when\"}", "{\"@value\":946684800}"}) {
                String doc = "{\"id\":\"" + SUB + "\",\"authentication\":["
                        + multikey(SUB + "#k1", SUB, ",\"" + property + "\":" + value) + "]}";
                assertTrue(json(doc).isEmpty(), property + ": " + value);
            }
        }
    }

    /** R-06. The shapes JSON-LD gives one date — a value object, an array of one — are read as that date. */
    @Test
    void aRevocationInAnotherShapeOfOneDateIsRead() throws Exception {
        for (String value : new String[]{
                "{\"@value\":\"2000-01-01T00:00:00Z\",\"@type\":\"xsd:dateTime\"}",
                "[\"2000-01-01T00:00:00Z\"]",
                "[{\"@value\":\"2000-01-01T00:00:00Z\"}]"}) {
            String doc = "{\"id\":\"" + SUB + "\",\"authentication\":["
                    + multikey(SUB + "#k1", SUB, ",\"revoked\":" + value) + "]}";
            List<VerificationMethod> methods = json(doc);
            assertEquals(1, methods.size(), value);
            assertEquals(Instant.parse("2000-01-01T00:00:00Z"), methods.get(0).revoked(), value);
            assertNotNull(methods.get(0).inactiveReason(Instant.now()), value);
        }
        String unset = "{\"id\":\"" + SUB + "\",\"authentication\":["
                + multikey(SUB + "#k1", SUB, ",\"revoked\":null") + "]}";
        assertNull(json(unset).get(0).revoked(), "null is no value, as it is to a JSON-LD processor");
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

    // ------------------------------------------------------------------- bounded work (R-03)

    /**
     * R-03. One method with one bad key and hundreds of revoked and expiration values used to come back
     * from the query as their cross product, with the bad key decoded again on every row: a 36 KiB
     * document took 271 seconds. Now each method is read once — and two values for one property make
     * it unusable, so the bad method is not even decoded.
     */
    @Test
    void rdfReadsEachMethodOnceWhateverItsValues() {
        Model model = ModelFactory.createDefaultModel();
        Resource subject = model.createResource(SUB);
        Resource noisy = method(model, SUB + "#noisy", SsiCidConstants.MULTIKEY_TYPE);
        noisy.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE), "z" + "2".repeat(200));
        for (int i = 0; i < 300; i++) {
            noisy.addProperty(model.createProperty(SsiCidConstants.SEC_REVOKED),
                    model.createTypedLiteral("2999-01-01T00:00:" + String.format("%02d", i % 60) + "." + i + "Z",
                            XSDDatatype.XSDdateTime));
            noisy.addProperty(model.createProperty(SsiCidConstants.SEC_EXPIRATION),
                    model.createTypedLiteral("2999-02-01T00:00:" + String.format("%02d", i % 60) + "." + i + "Z",
                            XSDDatatype.XSDdateTime));
        }
        subject.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), noisy);
        Resource good = method(model, SUB + "#good", SsiCidConstants.JSON_WEB_KEY_TYPE);
        good.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK), model.createLiteral(P256_JWK));
        subject.addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), good);

        List<VerificationMethod> methods = assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> SelfSignedCidVerifier.collectFromRdf(model, SUB));
        assertEquals(1, methods.size());
        assertEquals(SUB + "#good", methods.get(0).id());
    }

    /**
     * Two expiration dates leave it undecided whether the key has expired. The reader used to take
     * whichever the query returned first — so a key could stay usable past an expiry it published.
     */
    @Test
    void rdfAMethodWithTwoValuesForOnePropertyIsNotUsable() {
        for (String property : new String[]{SsiCidConstants.SEC_EXPIRATION, SsiCidConstants.SEC_REVOKED}) {
            Model model = ModelFactory.createDefaultModel();
            Resource multikey = method(model, SUB + "#k1", SsiCidConstants.MULTIKEY_TYPE);
            multikey.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE), ED25519_MULTIKEY);
            multikey.addProperty(model.createProperty(property),
                    model.createTypedLiteral("2000-01-01T00:00:00Z", XSDDatatype.XSDdateTime));
            multikey.addProperty(model.createProperty(property),
                    model.createTypedLiteral("2999-01-01T00:00:00Z", XSDDatatype.XSDdateTime));
            model.createResource(SUB).addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), multikey);
            assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty(), property);
        }

        Model model = ModelFactory.createDefaultModel();
        Resource jwk = method(model, SUB + "#k1", SsiCidConstants.JSON_WEB_KEY_TYPE);
        jwk.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK), model.createLiteral(P256_JWK));
        jwk.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK),
                model.createLiteral(P256_JWK.replace("}", ",\"kid\":\"other\"}")));
        model.createResource(SUB).addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), jwk);
        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty(), "two keys on one method");
    }

    /** A revocation that is not a literal is not "no revocation". */
    @Test
    void rdfANonLiteralRevocationIsNotUsable() {
        Model model = ModelFactory.createDefaultModel();
        Resource multikey = method(model, SUB + "#k1", SsiCidConstants.MULTIKEY_TYPE);
        multikey.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE), ED25519_MULTIKEY);
        multikey.addProperty(model.createProperty(SsiCidConstants.SEC_REVOKED), model.createResource(SUB + "#when"));
        model.createResource(SUB).addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), multikey);
        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty());
    }

    /**
     * R-03. Each reference in {@code authentication} used to search the whole document again; 8 000
     * that resolve to nothing, in a 163 KiB document, took 30 seconds. They are now looked up in an index
     * built once.
     */
    @Test
    void manyUnresolvableReferencesAreCheap() throws Exception {
        StringBuilder doc = new StringBuilder("{\"id\":\"" + SUB + "\",\"verificationMethod\":[")
                .append(multikey(SUB + "#key-456", SUB, "")).append("],\"authentication\":[");
        for (int i = 0; i < 8_000; i++) {
            doc.append("\"#missing-").append(i).append("\",");
        }
        doc.append("\"#key-456\"],\"padding\":[");
        for (int i = 0; i < 2_000; i++) {
            doc.append(i == 0 ? "" : ",").append("{\"id\":\"#pad-").append(i).append("\",\"x\":[[[1]]]}");
        }
        doc.append("]}");
        List<VerificationMethod> methods = assertTimeoutPreemptively(Duration.ofSeconds(2), () -> json(doc.toString()));
        assertEquals(1, methods.size());
        assertEquals(SUB + "#key-456", methods.get(0).id());
    }

    /** A reference resolves to the first map in document order with that id, as a search from the top did. */
    @Test
    void aReferenceResolvesToTheFirstMapWithThatId() throws Exception {
        String usable = multikey(SUB + "#k", SUB, "");
        String foreign = multikey(SUB + "#k", "https://someone-else.example/", "");
        String first = "{\"id\":\"" + SUB + "\",\"verificationMethod\":[" + usable + "," + foreign + "],"
                + "\"authentication\":[\"#k\"]}";
        String second = "{\"id\":\"" + SUB + "\",\"verificationMethod\":[" + foreign + "," + usable + "],"
                + "\"authentication\":[\"#k\"]}";
        assertEquals(1, json(first).size());
        assertTrue(json(second).isEmpty(), "the first map with the id is the method; a later one is not consulted");
    }

    // ------------------------------------------------------------------ CID 1.0 §2.2 shape (R-23)

    private static String jsonWebKey(String id, String jwkKid) {
        String jwk = P256_JWK.replace("{", "{\"kid\":\"" + jwkKid + "\",");
        return "{" + (id == null ? "" : "\"id\":\"" + id + "\",") + "\"type\":\"JsonWebKey\",\"controller\":\""
                + SUB + "\",\"publicKeyJwk\":" + jwk + "}";
    }

    private static String document(String... methods) {
        return "{\"id\":\"" + SUB + "\",\"authentication\":[" + String.join(",", methods) + "]}";
    }

    /**
     * R-23. CID 1.0 §2.2: a verification method "MUST include id, type, controller". One without an id
     * was accepted and selectable by its JWK's kid, though §3.3 retrieves a method by its identifier.
     */
    @Test
    void aMethodWithoutAnIdIsNotUsable() throws Exception {
        assertTrue(json(document(jsonWebKey(null, "k1"))).isEmpty());
        assertEquals(1, json(document(jsonWebKey(SUB + "#k1", "k1"))).size(), "the same method with an id");

        Model model = ModelFactory.createDefaultModel();
        Resource blank = model.createResource();
        blank.addProperty(RDF.type, model.createResource(SsiCidConstants.MULTIKEY_TYPE));
        blank.addProperty(model.createProperty(SsiCidConstants.SEC_CONTROLLER), model.createResource(SUB));
        blank.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE), ED25519_MULTIKEY);
        model.createResource(SUB).addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), blank);
        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty());
    }

    /**
     * R-23. CID 1.0 §2.2: type "MUST be a string that references exactly one verification method type",
     * controller a string. A second type or controller leaves the reader to choose which applies. An
     * array of one is the same single value to a JSON-LD processor.
     */
    @Test
    void aMethodWithTwoTypesOrTwoControllersIsNotUsable() throws Exception {
        String twoTypes = multikey(SUB + "#k1", SUB, "").replace("\"type\":\"Multikey\"",
                "\"type\":[\"Multikey\",\"https://example.org/Other\"]");
        assertTrue(json(document(twoTypes)).isEmpty());

        String oneOfEach = multikey(SUB + "#k1", SUB, "").replace("\"type\":\"Multikey\"", "\"type\":[\"Multikey\"]")
                .replace("\"controller\":\"" + SUB + "\"", "\"controller\":[\"" + SUB + "\"]");
        assertEquals(1, json(document(oneOfEach)).size());

        for (String second : new String[]{"type", "controller"}) {
            Model model = ModelFactory.createDefaultModel();
            Resource multikey = method(model, SUB + "#k1", SsiCidConstants.MULTIKEY_TYPE);
            multikey.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE), ED25519_MULTIKEY);
            model.createResource(SUB).addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), multikey);
            assertEquals(1, SelfSignedCidVerifier.collectFromRdf(model, SUB).size(), "control");
            if (second.equals("type")) {
                multikey.addProperty(RDF.type, model.createResource(SsiCidConstants.JSON_WEB_KEY_TYPE));
            } else {
                multikey.addProperty(model.createProperty(SsiCidConstants.SEC_CONTROLLER),
                        model.createResource("https://someone-else.example/"));
            }
            assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty(), second);
        }
    }

    /** R-23. CID 1.0 §2.2: a method "MUST NOT contain multiple verification material properties". */
    @Test
    void aMethodWithTwoKindsOfKeyMaterialIsNotUsable() throws Exception {
        String both = multikey(SUB + "#k1", SUB, ",\"publicKeyJwk\":" + P256_JWK);
        assertTrue(json(document(both)).isEmpty());

        Model model = ModelFactory.createDefaultModel();
        Resource multikey = method(model, SUB + "#k1", SsiCidConstants.MULTIKEY_TYPE);
        multikey.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE), ED25519_MULTIKEY);
        multikey.addProperty(model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK), model.createLiteral(P256_JWK));
        model.createResource(SUB).addProperty(model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), multikey);
        assertTrue(SelfSignedCidVerifier.collectFromRdf(model, SUB).isEmpty());
    }

    /**
     * R-23. A kid is matched against the method ids — whole, then fragment, the method {@code #kid}
     * resolves to under CID 1.0 §3.4 — before any JWK's own kid. One method's JWK kid "b" used to win over
     * the method whose id is {@code #b}.
     */
    @Test
    void theMethodIdIsMatchedBeforeTheJwksOwnKid() throws Exception {
        List<VerificationMethod> methods = json(document(jsonWebKey(SUB + "#a", "b"), jsonWebKey(SUB + "#b", "c")));
        assertEquals(2, methods.size());
        assertSame(methods.get(1), SelfSignedCidVerifier.selectByKid(methods, "b"));
        assertSame(methods.get(1), SelfSignedCidVerifier.selectByKid(methods, "#b"));
        assertSame(methods.get(1), SelfSignedCidVerifier.selectByKid(methods, "c"), "the JWK's kid still selects");
        assertSame(methods.get(0), SelfSignedCidVerifier.selectByKid(methods, "a"));
    }
}
