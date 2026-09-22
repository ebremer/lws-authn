/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.did;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.did.Dids.InvalidDidException;

/**
 * DID syntax, did:key expansion and the did:web URL mapping — the parts of DID resolution that need no
 * network, checked against the examples the method specifications themselves give.
 */
class DidsTest {

    // ------------------------------------------------------------------------------------ syntax

    @Test
    void readsTheMethodOfAValidDid() {
        assertEquals("web", Dids.methodOf("did:web:example.com"));
        assertEquals("key", Dids.methodOf("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
        assertEquals("example", Dids.methodOf("did:example:123456789abcdefghi"));
        assertEquals("web", Dids.methodOf("did:web:example.com%3A3000:user:alice"));
    }

    /** DID 1.1 §3.1: a DID has no path, query or fragment, a lower-case method, and no empty tail. */
    @Test
    void refusesWhatIsNotADid() {
        for (String bad : new String[]{
                "did:", "did:web", "did:web:", "did:web:example.com:", "did:WEB:example.com",
                "did:web:example.com#key-1", "did:web:example.com/path", "did:web:example.com?x=1",
                "did:web:exa mple.com", "did:web:example.com%ZZ", "https://example.com", "", }) {
            assertThrows(InvalidDidException.class, () -> Dids.methodOf(bad), bad);
        }
        assertThrows(InvalidDidException.class, () -> Dids.methodOf(null));
        assertFalse(Dids.isDid("https://id.example/agent"));
        assertTrue(Dids.isDid("did:web:example.com"));
    }

    @Test
    void namesTheSupportedMethodsWhenRefusingAnother() {
        String message = new Dids.UnsupportedDidMethodException("example").getMessage();
        assertTrue(message.contains("did:example"), message);
        assertTrue(message.contains("did:key") && message.contains("did:web"), message);
    }

    // ----------------------------------------------------------------------------------- did:web

    /** The three examples the did:web Method Specification's Read operation gives. */
    @Test
    void mapsADidWebToItsDocumentUrl() {
        assertEquals("https://w3c-ccg.github.io/.well-known/did.json",
                Dids.didWebUrl("did:web:w3c-ccg.github.io"));
        assertEquals("https://w3c-ccg.github.io/user/alice/did.json",
                Dids.didWebUrl("did:web:w3c-ccg.github.io:user:alice"));
        assertEquals("https://example.com:3000/user/alice/did.json",
                Dids.didWebUrl("did:web:example.com%3A3000:user:alice"));
        assertEquals("https://example.com:3000/.well-known/did.json",
                Dids.didWebUrl("did:web:example.com%3a3000"));
    }

    /** "The method specific identifier ... MUST NOT include IP addresses." */
    @Test
    void refusesAnIpAddress() {
        for (String bad : new String[]{"did:web:192.168.1.10", "did:web:10.0.0.1%3A443", "did:web:127.0.0.1:x"}) {
            assertThrows(InvalidDidException.class, () -> Dids.didWebUrl(bad), bad);
        }
    }

    @Test
    void refusesAPortThatIsNotOne() {
        for (String bad : new String[]{"did:web:example.com%3A0", "did:web:example.com%3A70000",
                "did:web:example.com%3Ahttp", "did:web:example.com%3A"}) {
            assertThrows(InvalidDidException.class, () -> Dids.didWebUrl(bad), bad);
        }
    }

    @Test
    void refusesAHostThatIsNotADomainName() {
        for (String bad : new String[]{"did:web:exa_mple.com", "did:web:-example.com", "did:web:example%2Ecom",
                "did:web:example..com", "did:web:" + "a".repeat(64) + ".com"}) {
            assertThrows(InvalidDidException.class, () -> Dids.didWebUrl(bad), bad);
        }
    }

    @Test
    void refusesAnEmptyPathSegment() {
        assertThrows(InvalidDidException.class, () -> Dids.didWebUrl("did:web:example.com::alice"));
    }

    @Test
    void refusesAnotherMethod() {
        assertThrows(InvalidDidException.class,
                () -> Dids.didWebUrl("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
    }

    // ----------------------------------------------------------------------------------- did:key

    /** The did:key Method's own worked example, field for field. */
    @Test
    void expandsADidKeyToItsDocument() {
        String did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        String methodId = did + "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        JsonNode doc = Dids.didKeyDocument(did);

        assertEquals(did, doc.path("id").asText());
        assertEquals(1, doc.path("verificationMethod").size());
        JsonNode method = doc.path("verificationMethod").get(0);
        assertEquals(methodId, method.path("id").asText());
        assertEquals("Multikey", method.path("type").asText());
        assertEquals(did, method.path("controller").asText());
        assertEquals("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", method.path("publicKeyMultibase").asText());
        for (String relationship : new String[]{"authentication", "assertionMethod",
                "capabilityInvocation", "capabilityDelegation"}) {
            assertEquals(methodId, doc.path(relationship).get(0).asText(), relationship);
        }
        assertNull(doc.get("keyAgreement"), "key agreement derivation is off by default");
    }

    /** secp256k1 and BLS12-381 are did:key types this provider cannot verify a JWS with. */
    @Test
    void refusesADidKeyOfAnUnsupportedType() {
        for (String bad : new String[]{
                "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                "did:key:zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb"}) {
            assertThrows(InvalidDidException.class, () -> Dids.didKeyDocument(bad), bad);
        }
    }

    @Test
    void refusesANonCanonicalDidKey() {
        assertThrows(InvalidDidException.class,
                () -> Dids.didKeyDocument("did:key:z16MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
    }

    // ------------------------------------------------------------------------------ media types

    @Test
    void acceptsTheMediaTypesADidDocumentIsServedWith() {
        for (String ok : new String[]{"application/did+json", "application/did+ld+json", "application/did",
                "application/ld+json", "application/json", "application/json; charset=utf-8", null, " "}) {
            assertTrue(Dids.isDidDocumentMediaType(ok), String.valueOf(ok));
        }
        for (String bad : new String[]{"text/html", "text/turtle", "application/octet-stream"}) {
            assertFalse(Dids.isDidDocumentMediaType(bad), bad);
        }
    }
}
