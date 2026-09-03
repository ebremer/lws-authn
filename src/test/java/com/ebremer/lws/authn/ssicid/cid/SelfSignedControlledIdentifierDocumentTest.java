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
}
