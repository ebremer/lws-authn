/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.ssicid.cid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.riot.RDFParser;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;

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

    // ---------------------------------------------------------------------------------- R-33

    private static JsonNode ec(String kid, String x) throws Exception {
        return json("{" + (kid == null ? "" : "\"kid\":\"" + kid + "\",")
                + "\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"PUBY\"}");
    }

    /** Each verification method, read back from the Turtle as a verifier reads it, with its keys. */
    private static java.util.Map<String, List<String>> methodsInTurtle(SelfSignedControlledIdentifierDocument document) {
        Model model = ModelFactory.createDefaultModel();
        RDFParser.fromString(document.toRdf(RDFFormat.TURTLE), Lang.TURTLE).parse(model);
        Property authentication = model.createProperty(SsiCidConstants.SEC_AUTHENTICATION);
        Property publicKeyJwk = model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK);
        java.util.Map<String, List<String>> methods = new java.util.TreeMap<>();
        model.listObjectsOfProperty(model.createResource(ID), authentication).forEachRemaining(method ->
                methods.put(method.asResource().getURI(), model.listObjectsOfProperty(method.asResource(), publicKeyJwk)
                        .mapWith(RDFNode::toString).toList()));
        return methods;
    }

    /**
     * A key registered as {@code kid: "key-2"} followed by one with no {@code kid} were both {@code #key-2}:
     * one node in RDF with two keys, and read back, one key — tokens signed with the other failed.
     */
    @Test
    void aPositionalIdNeverTakesOneAKidAlreadyHas() throws Exception {
        SelfSignedControlledIdentifierDocument document =
                new SelfSignedControlledIdentifierDocument(ID, List.of(ec("key-2", "PUBA"), ec(null, "PUBB")));

        java.util.Map<String, List<String>> methods = methodsInTurtle(document);
        assertEquals(java.util.Set.of(ID + "#key-2", ID + "#key-3"), methods.keySet(), methods.toString());
        methods.values().forEach(keys -> assertEquals(1, keys.size(), methods.toString()));
        assertTrue(document.refusedMethodIds().isEmpty());
    }

    /** Two different keys under one {@code kid}: a credential naming it could mean either, so neither. */
    @Test
    void differentKeysSharingAKidAreNotPublished() throws Exception {
        SelfSignedControlledIdentifierDocument document = new SelfSignedControlledIdentifierDocument(ID,
                List.of(ec("k1", "PUBA"), ec("k2", "PUBB"), ec("k1", "PUBC")));

        assertEquals(java.util.Set.of(ID + "#k2"), methodsInTurtle(document).keySet());
        assertEquals(List.of(ID + "#k1"), document.refusedMethodIds());
        assertFalse(document.toJsonLd().contains("PUBA"));
        assertFalse(document.toJsonLd().contains("PUBC"));
    }

    /** The same key registered twice is one method. */
    @Test
    void theSameKeyRegisteredTwiceIsPublishedOnce() throws Exception {
        SelfSignedControlledIdentifierDocument document =
                new SelfSignedControlledIdentifierDocument(ID, List.of(ec("k1", "PUBA"), ec("k1", "PUBA")));

        java.util.Map<String, List<String>> methods = methodsInTurtle(document);
        assertEquals(java.util.Set.of(ID + "#k1"), methods.keySet());
        assertEquals(1, methods.get(ID + "#k1").size());
        assertTrue(document.refusedMethodIds().isEmpty());
    }
}
