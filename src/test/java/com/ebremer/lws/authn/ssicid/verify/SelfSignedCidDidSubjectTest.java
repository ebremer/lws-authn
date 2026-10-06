/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.did.DidKey;
import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;

/**
 * DID subjects under the self-signed CID suite, verified end to end.
 *
 * <p>The suite "is designed to work with subject identifiers that use HTTPS URIs as well as DID URIs",
 * and the discontinued did:key suite was folded into it as the "generalization" of its mechanism. A
 * did:key needs no network, so the whole algorithm runs here without a Keycloak session: the subject
 * is resolved to its DID document, the {@code kid} selects the Multikey method that document's
 * {@code authentication} names, and the signature is checked against it.</p>
 */
class SelfSignedCidDidSubjectTest {

    private static SsiCidVerificationResult verify(String jwt) {
        return new SelfSignedCidVerifier(null).verify(jwt, SelfIssuedJwts.AUDIENCE);
    }

    private static String didFor(KeyPair pair, String keyType) {
        return switch (keyType) {
            case "Ed25519" -> DidKey.encodeEd25519(pair.getPublic());
            case "P-256" -> DidKey.encodeP256((ECPublicKey) pair.getPublic());
            case "P-384" -> DidKey.encodeP384((ECPublicKey) pair.getPublic());
            default -> DidKey.encodeP521((ECPublicKey) pair.getPublic());
        };
    }

    private static KeyPair pairFor(String keyType) throws Exception {
        return switch (keyType) {
            case "Ed25519" -> SelfIssuedJwts.ed25519();
            case "P-256" -> SelfIssuedJwts.ec("secp256r1");
            case "P-384" -> SelfIssuedJwts.ec("secp384r1");
            default -> SelfIssuedJwts.ec("secp521r1");
        };
    }

    /** The did:key Method's verification method id: the DID, '#', and its multibase value. */
    private static String methodId(String did) {
        return did + "#" + DidKey.multibaseValue(did);
    }

    @Test
    void aDidKeyCredentialVerifiesForEverySupportedKeyType() throws Exception {
        String[][] types = {{"Ed25519", "EdDSA"}, {"P-256", "ES256"}, {"P-384", "ES384"}, {"P-521", "ES512"}};
        for (String[] type : types) {
            KeyPair pair = pairFor(type[0]);
            String did = didFor(pair, type[0]);
            String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), type[1], methodId(did),
                    pair.getPrivate(), SelfIssuedJwts.jcaFor(type[1]));

            SsiCidVerificationResult result = verify(jwt);

            assertTrue(result.isValid(), () -> type[0] + ": " + result.getErrors());
            assertEquals(did, result.getSubject());
            assertEquals(did, result.getClient());
            assertEquals(SsiCidConstants.TOKEN_TYPE_JWT, result.getTokenType());
            for (String check : new String[]{"selfIssued", "keyIdPresent", "subjectDereferenced", "subjectIdMatches",
                    "verificationMethodFound", "verificationMethodActive", "algorithmMatchesKey", "signatureValid",
                    "notExpired", "issuedAtPresent", "audiencePresent", "audienceMatched"}) {
                assertEquals(Boolean.TRUE, result.getChecks().get(check), type[0] + " " + check);
            }
        }
    }

    /** CID 1.0 conventionally puts the key id in the method id's fragment; that spelling works too. */
    @Test
    void theKidMayBeTheFragmentAlone() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", DidKey.multibaseValue(did),
                pair.getPrivate(), "Ed25519");
        assertTrue(verify(jwt).isValid());
    }

    /**
     * The one behavioural difference from the discontinued did:key suite, which read the key from the
     * identifier and ignored {@code kid}: this suite says the verifier "MUST use the kid".
     */
    @Test
    void aDidKeyCredentialWithoutAKidIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ec("secp256r1");
        String did = DidKey.encodeP256((ECPublicKey) pair.getPublic());
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "ES256", null, pair.getPrivate(),
                "SHA256withECDSAinP1363Format");
        assertRejected(verify(jwt), "keyIdPresent");
    }

    @Test
    void aKidNamingNoMethodOfTheSubjectIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        String other = DidKey.encodeEd25519(SelfIssuedJwts.ed25519().getPublic());
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", methodId(other),
                pair.getPrivate(), "Ed25519");
        assertRejected(verify(jwt), "verificationMethodFound");
    }

    @Test
    void aCredentialSignedByAnotherKeyIsRejected() throws Exception {
        KeyPair subject = SelfIssuedJwts.ed25519();
        KeyPair impostor = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(subject.getPublic());
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", methodId(did),
                impostor.getPrivate(), "Ed25519");
        assertRejected(verify(jwt), "signatureValid");
    }

    @Test
    void anAlgorithmThatIsNotTheKeysIsRejected() throws Exception {
        KeyPair ed = SelfIssuedJwts.ed25519();
        String edDid = DidKey.encodeEd25519(ed.getPublic());
        String claimsEs256 = SelfIssuedJwts.sign(SelfIssuedJwts.claims(edDid), "ES256", methodId(edDid),
                ed.getPrivate(), "Ed25519");
        assertRejected(verify(claimsEs256), "algorithmMatchesKey");

        // RFC 7518 §3.4: ES384 is P-384. A P-256 key signing SHA-384 is valid ECDSA, and still not ES384.
        KeyPair p256 = SelfIssuedJwts.ec("secp256r1");
        String p256Did = DidKey.encodeP256((ECPublicKey) p256.getPublic());
        String es384 = SelfIssuedJwts.sign(SelfIssuedJwts.claims(p256Did), "ES384", methodId(p256Did),
                p256.getPrivate(), "SHA384withECDSAinP1363Format");
        assertRejected(verify(es384), "algorithmMatchesKey");
    }

    /** A did:key is its key: a second spelling of the same key must not be a second identity. */
    @Test
    void aNonCanonicalDidKeyIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ec("secp256r1");
        String did = DidKey.encodeP256((ECPublicKey) pair.getPublic()).replace("did:key:z", "did:key:z1");
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "ES256", did + "#x", pair.getPrivate(),
                "SHA256withECDSAinP1363Format");
        assertRejected(verify(jwt), "subjectDereferenced");
    }

    /** The suite mandates no DID method; the ones this provider cannot resolve are refused by name. */
    @Test
    void anUnsupportedDidMethodIsRefusedByName() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = "did:example:123456789abcdefghi";
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", did + "#key-1", pair.getPrivate(),
                "Ed25519");
        SsiCidVerificationResult result = verify(jwt);
        assertRejected(result, "subjectDereferenced");
        assertTrue(String.join(" ", result.getErrors()).contains("did:key, did:web"), result.getErrors()::toString);
    }

    @Test
    void anInvalidDidIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = "did:key:z6Mk%ZZ";
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", did + "#k", pair.getPrivate(),
                "Ed25519");
        assertRejected(verify(jwt), "subjectDereferenced");
    }

    /** did:web "MUST NOT include IP addresses" — refused before anything is fetched. */
    @Test
    void aDidWebNamingAnIpAddressIsRefusedWithoutAFetch() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = "did:web:127.0.0.1";
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", did + "#key-1", pair.getPrivate(),
                "Ed25519");
        assertRejected(verify(jwt), "subjectDereferenced");
    }

    @Test
    void theRestOfTheSuiteStillApplies() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());

        Map<String, Object> expired = SelfIssuedJwts.claims(did);
        long past = Instant.now().getEpochSecond() - 3600;
        expired.put("iat", past - 300);
        expired.put("exp", past);
        assertRejected(verify(SelfIssuedJwts.sign(expired, "EdDSA", methodId(did), pair.getPrivate(), "Ed25519")),
                "notExpired");

        Map<String, Object> elsewhere = SelfIssuedJwts.claims(did);
        elsewhere.put("aud", java.util.List.of("https://another-as.example"));
        assertRejected(verify(SelfIssuedJwts.sign(elsewhere, "EdDSA", methodId(did), pair.getPrivate(), "Ed25519")),
                "audienceMatched");

        Map<String, Object> notSelfIssued = SelfIssuedJwts.claims(did);
        notSelfIssued.put("client_id", "https://app.example");
        assertRejected(verify(SelfIssuedJwts.sign(notSelfIssued, "EdDSA", methodId(did), pair.getPrivate(),
                "Ed25519")), "selfIssued");
    }

    private static void assertRejected(SsiCidVerificationResult result, String failedCheck) {
        assertFalse(result.isValid(), "expected a rejection at " + failedCheck);
        assertEquals(Boolean.FALSE, result.getChecks().get(failedCheck),
                () -> failedCheck + " should have failed; checks=" + result.getChecks() + " errors=" + result.getErrors());
    }

    /**
     * R-05. {@code at+jwt} is RFC 9068's marker for an OAuth access token. A credential that says it is
     * one is not a self-issued authentication credential, however good its signature.
     */
    @Test
    void aCredentialTypedAsAnAccessTokenIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        for (String typ : new String[]{"at+jwt", "application/at+jwt"}) {
            String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "EdDSA", methodId(did),
                    pair.getPrivate(), "Ed25519", typ);
            SsiCidVerificationResult result = verify(jwt);
            assertFalse(result.isValid(), typ);
            assertEquals(Boolean.FALSE, result.getChecks().get("typeIsJwt"), typ);
        }
    }

    private static String edDsaCredential(KeyPair pair, String did, Map<String, Object> claims) throws Exception {
        return SelfIssuedJwts.sign(claims, "EdDSA", methodId(did), pair.getPrivate(), "Ed25519");
    }

    /**
     * R-16. "The {@code aud} claim MUST include the target authorization server." With no target to
     * compare against, a credential minted for any authorization server used to verify; it now does not.
     */
    @Test
    void withoutATargetAuthorizationServerNothingIsValid() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        String jwt = edDsaCredential(pair, did, SelfIssuedJwts.claims(did));
        for (String target : new String[]{null, "", " "}) {
            assertRejected(new SelfSignedCidVerifier(null).verify(jwt, target), "audienceMatched");
        }
        assertRejected(new SelfSignedCidVerifier(null).verify(jwt, "https://another-as.example"), "audienceMatched");
        assertTrue(verify(jwt).isValid(), "the control: the right target verifies");
    }

    /** R-16. A blank audience names nothing, and used to count as "present" on its own. */
    @Test
    void aBlankAudienceIsNotAnAudience() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        for (java.util.List<String> aud : java.util.List.of(java.util.List.of(""), java.util.List.of(" "),
                java.util.List.of(SelfIssuedJwts.AUDIENCE, ""))) {
            Map<String, Object> claims = SelfIssuedJwts.claims(did);
            claims.put("aud", aud);
            assertRejected(verify(edDsaCredential(pair, did, claims)), "audiencePresent");
        }
    }

    /** R-28, with R-17. A credential issued in the future, or after it expires, was not issued by a clock. */
    @Test
    void anIssuedAtInTheFutureOrAfterExpiryIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        long now = Instant.now().getEpochSecond();

        Map<String, Object> future = SelfIssuedJwts.claims(did);
        future.put("iat", now + 10 * 365 * 86_400L);
        future.put("exp", now + 11 * 365 * 86_400L);
        assertRejected(verify(edDsaCredential(pair, did, future)), "issuedAtConsistent");

        Map<String, Object> afterExpiry = SelfIssuedJwts.claims(did);
        afterExpiry.put("iat", now + 50);   // within the clock skew, so not "in the future"
        afterExpiry.put("exp", now + 30);
        assertRejected(verify(edDsaCredential(pair, did, afterExpiry)), "issuedAtConsistent");

        Map<String, Object> slightlyAhead = SelfIssuedJwts.claims(did);
        slightlyAhead.put("iat", now + 30);  // a clock a little fast is still a clock
        assertTrue(verify(edDsaCredential(pair, did, slightlyAhead)).isValid());
    }

    /**
     * R-28. A deployment may bound a credential's lifetime, {@code exp − iat}; by default nothing does, and
     * a self-issued credential valid until 9999 verified.
     */
    @Test
    void aConfiguredMaximumLifetimeIsEnforced() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        Map<String, Object> forever = SelfIssuedJwts.claims(did);
        forever.put("exp", 253_402_300_799L); // 9999-12-31T23:59:59Z
        String longLived = edDsaCredential(pair, did, forever);
        assertTrue(verify(longLived).isValid(), "no limit unless one is configured");
        assertEquals(null, verify(longLived).getChecks().get("lifetimeWithinLimit"));

        System.setProperty("lws.authn.maxCredentialLifetimeSeconds", "3600");
        try {
            com.ebremer.lws.authn.config.ServerSettings.contribute("test", null);
            assertRejected(verify(longLived), "lifetimeWithinLimit");
            SsiCidVerificationResult shortLived = verify(edDsaCredential(pair, did, SelfIssuedJwts.claims(did)));
            assertTrue(shortLived.isValid(), () -> String.valueOf(shortLived.getErrors()));
            assertEquals(Boolean.TRUE, shortLived.getChecks().get("lifetimeWithinLimit"));
        } finally {
            System.clearProperty("lws.authn.maxCredentialLifetimeSeconds");
            com.ebremer.lws.authn.config.ServerSettings.reset();
        }
    }

    /**
     * R-27. The identity point as a did:key: {@code (R = identity, S = 0)} is a valid Ed25519 signature on
     * any message under it, which the JDK verifier accepts — so anyone could sign as this subject.
     */
    @Test
    void aSmallOrderKeyCannotSignForAnyone() throws Exception {
        byte[] multicodec = new byte[34];
        multicodec[0] = (byte) 0xed;
        multicodec[1] = 0x01;
        multicodec[2] = 0x01; // y = 1: the identity
        String did = "did:key:z" + DidKey.base58Encode(multicodec);
        java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
        com.fasterxml.jackson.databind.ObjectMapper json = new com.fasterxml.jackson.databind.ObjectMapper();
        String input = b64.encodeToString(json.writeValueAsBytes(Map.of("alg", "EdDSA", "typ", "JWT",
                "kid", did + "#" + DidKey.multibaseValue(did))))
                + "." + b64.encodeToString(json.writeValueAsBytes(SelfIssuedJwts.claims(did)));
        byte[] signature = new byte[64];
        signature[0] = 0x01; // R = identity, S = 0
        SsiCidVerificationResult result = verify(input + "." + b64.encodeToString(signature));

        assertFalse(result.isValid(), "a credential nobody signed verified");
        assertEquals(Boolean.FALSE, result.getChecks().get("subjectDereferenced"));
    }
}
