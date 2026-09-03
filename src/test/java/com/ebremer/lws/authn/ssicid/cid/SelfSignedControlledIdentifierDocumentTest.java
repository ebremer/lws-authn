package com.ebremer.lws.authn.ssicid.cid;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.jena.riot.RDFFormat;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

/**
 * P0-1, at the last line of defence. The resource provider filters and logs, but the document builder
 * is what actually serializes, so it filters too: no caller can make a served controlled identifier
 * document contain private key material, whatever it passes in.
 */
class SelfSignedControlledIdentifierDocumentTest {

    private static final String ID = "https://kc.example/realms/r/lws-ssi-cid/cid/u1";

    private static JsonNode json(String s) throws Exception {
        return JsonSerialization.mapper.readTree(s);
    }

    @Test
    void privateKeyMaterialNeverReachesTheServedDocument() throws Exception {
        JsonNode keyPair = json("{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"PUBX\",\"y\":\"PUBY\",\"d\":\"PRIVATESCALAR\"}");
        SelfSignedControlledIdentifierDocument document =
                new SelfSignedControlledIdentifierDocument(ID, List.of(keyPair));

        String jsonLd = document.toJsonLd();
        String turtle = document.toRdf(RDFFormat.TURTLE);
        assertFalse(jsonLd.contains("PRIVATESCALAR"), "JSON-LD leaked the private scalar: " + jsonLd);
        assertFalse(turtle.contains("PRIVATESCALAR"), "Turtle leaked the private scalar: " + turtle);
        assertFalse(jsonLd.contains("authentication"),
                "a key pair is rejected outright, so no verification method should be published");
    }

    @Test
    void aPublicKeyIsStillPublished() throws Exception {
        JsonNode jwk = json("{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"PUBX\",\"y\":\"PUBY\"}");
        String jsonLd = new SelfSignedControlledIdentifierDocument(ID, List.of(jwk)).toJsonLd();
        assertTrue(jsonLd.contains("\"authentication\""), jsonLd);
        assertTrue(jsonLd.contains("JsonWebKey"), jsonLd);
        assertTrue(jsonLd.contains("PUBX"), jsonLd);
        assertTrue(jsonLd.contains(ID + "#k1"), jsonLd);
    }

    /**
     * P3-3. A kid is arbitrary text; concatenated into the fragment unescaped it produced an IRI Jena
     * refuses to write, so one badly-named key used to 500 the whole document — including the other,
     * perfectly good keys on the same user.
     */
    @Test
    void anAwkwardKeyIdStillSerializesInEverySyntax() throws Exception {
        JsonNode awkward = json("{\"kid\":\"my key #2/v1\",\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"PUBX\",\"y\":\"PUBY\"}");
        SelfSignedControlledIdentifierDocument document =
                new SelfSignedControlledIdentifierDocument(ID, List.of(awkward));

        String jsonLd = document.toJsonLd();
        assertTrue(jsonLd.contains(ID + "#my%20key%20%232%2Fv1"), jsonLd);
        // Would previously throw: Jena rejects <...#my key #2/v1> when writing.
        assertTrue(document.toRdf(RDFFormat.TURTLE).contains("my%20key"), "Turtle should carry the encoded id");
        assertTrue(document.toRdf(RDFFormat.NTRIPLES).contains("my%20key"), "N-Triples too");
        assertTrue(document.toRdf(RDFFormat.RDFXML).contains("my%20key"), "RDF/XML too");
    }

    /**
     * P1-C6. CID 1.0 requires every verification method to have an {@code id} "conforming to URL
     * syntax", so a JWK whose {@code kid} cannot supply the fragment gets a synthesized one rather
     * than the blank node the RDF serialization used to fall back to.
     */
    @Test
    void aKeyWithNoUsableKidStillGetsAConformingIdentifier() throws Exception {
        JsonNode unnamed = json("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"PUBX\",\"y\":\"PUBY\"}");
        JsonNode named = json("{\"kid\":\"k2\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"PUBQ\",\"y\":\"PUBR\"}");
        SelfSignedControlledIdentifierDocument document =
                new SelfSignedControlledIdentifierDocument(ID, List.of(unnamed, named));

        String jsonLd = document.toJsonLd();
        assertTrue(jsonLd.contains("PUBX"), jsonLd);
        assertTrue(jsonLd.contains(ID + "#key-1"), "the kid-less key needs an id of its own: " + jsonLd);
        assertTrue(jsonLd.contains(ID + "#k2"), "and a usable kid still supplies the fragment: " + jsonLd);

        String turtle = document.toRdf(RDFFormat.TURTLE);
        assertTrue(turtle.contains("key-1"), turtle);
        assertFalse(turtle.contains("[ a"), "no blank-node verification method should remain: " + turtle);
    }
}
