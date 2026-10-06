/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

import com.ebremer.lws.authn.http.ThisRealm;
import com.ebremer.lws.authn.openid.resource.LWSResourceProvider;
import com.ebremer.lws.authn.openid.verify.LWSCredentialVerifier;
import com.ebremer.lws.authn.openid.verify.VerificationResult;
import com.ebremer.lws.authn.ssicid.resource.SsiCidResourceProvider;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier;
import com.ebremer.lws.authn.ssicid.verify.SsiCidVerificationResult;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * R-26. A credential this realm issued, or about a subject whose document it hosts, is verified from
 * the realm itself — its key store and the renderer its endpoint uses — not by fetching from itself.
 * The realm here is at a host that does not resolve, so any fetch would fail: these pass only if
 * nothing is fetched.
 */
class ThisRealmVerificationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final String ISSUER = "https://keycloak.invalid/realms/demo";
    private static final String USER_ID = "2b8a5c1e-0f4d-4c7e-9a3b-6d1f0e2c4b7a";

    /** A user whose only attribute is {@code lws_jwk}, holding {@code jwks}. */
    private static UserModel user(List<String> jwks) {
        return (UserModel) Proxy.newProxyInstance(ThisRealmVerificationTest.class.getClassLoader(),
                new Class<?>[]{UserModel.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getId" -> USER_ID;
                    case "getAttributeStream" -> "lws_jwk".equals(args[0]) ? jwks.stream() : Stream.empty();
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static ThisRealm realm(String issuer, UserModel user, KeyWrapper... keys) {
        return new ThisRealm(issuer, id -> user != null && USER_ID.equals(id) ? user : null, () -> Stream.of(keys));
    }

    // ------------------------------------------------------------------------------ self-signed

    /**
     * The registered key, as {@code lws_jwk} holds it. RSA, because outside a running server Keycloak's
     * JWK parser has no crypto provider for EC keys; the document's handling is the same for both.
     */
    private static String rsaJwk(KeyPair pair) {
        java.security.interfaces.RSAPublicKey key = (java.security.interfaces.RSAPublicKey) pair.getPublic();
        return "{\"kid\":\"agent-key-1\",\"kty\":\"RSA\",\"n\":\"" + B64.encodeToString(unsigned(key.getModulus()))
                + "\",\"e\":\"" + B64.encodeToString(unsigned(key.getPublicExponent())) + "\"}";
    }

    private static byte[] unsigned(java.math.BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes[0] == 0 ? java.util.Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static SsiCidVerificationResult selfSigned(String issuer, UserModel user, KeyPair pair) throws Exception {
        String sub = issuer + "/lws-ssi-cid/cid/" + USER_ID;
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(sub), "RS256", "agent-key-1", pair.getPrivate(),
                "SHA256withRSA");
        return new SelfSignedCidVerifier(null).localTo(realm(issuer, user), SsiCidResourceProvider.DOCUMENTS)
                .verify(jwt, SelfIssuedJwts.AUDIENCE);
    }

    @Test
    void aSelfSignedCredentialForOneOfThisRealmsDocumentsNeedsNoFetch() throws Exception {
        KeyPair pair = rsa();
        SsiCidVerificationResult result = selfSigned(ISSUER, user(List.of(rsaJwk(pair))), pair);
        assertTrue(result.isValid(), () -> result.getErrors() + " " + result.getChecks());
    }

    /** What the endpoint would answer is what the verifier reads: no such user is a 404. */
    @Test
    void anUnknownUserIsAsMissingLocallyAsOverHttp() throws Exception {
        KeyPair pair = rsa();
        SsiCidVerificationResult result = selfSigned(ISSUER, null, pair);
        assertFalse(result.isValid());
        assertEquals(Boolean.FALSE, result.getChecks().get("subjectDereferenced"));
    }

    /** R-07 still holds: a plain-http identifier is refused, not quietly read from the realm. */
    @Test
    void aPlainHttpIdentifierIsStillRefused() throws Exception {
        KeyPair pair = rsa();
        SsiCidVerificationResult result = selfSigned("http://keycloak.invalid/realms/demo",
                user(List.of(rsaJwk(pair))), pair);
        assertFalse(result.isValid());
        assertTrue(result.getErrors().toString().contains("neither an https URL nor a DID"), result.getErrors().toString());
    }

    // ----------------------------------------------------------------------------------- OpenID

    private static KeyWrapper rsaKey(String kid, PublicKey key) {
        KeyWrapper wrapper = new KeyWrapper();
        wrapper.setKid(kid);
        wrapper.setAlgorithm("RS256");
        wrapper.setType(KeyType.RSA);
        wrapper.setUse(KeyUse.SIG);
        wrapper.setStatus(KeyStatus.ACTIVE);
        wrapper.setPublicKey(key);
        return wrapper;
    }

    private static String idToken(String kid, KeyPair pair) throws Exception {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("sub", ISSUER + "/lws/cid/" + USER_ID);
        claims.put("azp", "lws-app");
        claims.put("aud", List.of("lws-app"));
        claims.put("typ", "ID");
        claims.put("iat", now);
        claims.put("exp", now + 300);
        String input = B64.encodeToString(JSON.writeValueAsBytes(Map.of("alg", "RS256", "typ", "JWT", "kid", kid)))
                + "." + B64.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(pair.getPrivate());
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + B64.encodeToString(signature.sign());
    }

    /** A session whose RS256 signature provider is the JDK's; nothing else is offered, or needed. */
    private static KeycloakSession rs256Session() {
        Object provider = Proxy.newProxyInstance(ThisRealmVerificationTest.class.getClassLoader(),
                new Class<?>[]{SignatureProvider.class}, (proxy, method, args) -> {
                    if ("verifier".equals(method.getName()) && args != null && args[0] instanceof KeyWrapper key) {
                        return new SignatureVerifierContext() {
                            @Override
                            public String getKid() {
                                return key.getKid();
                            }

                            @Override
                            public String getAlgorithm() {
                                return "RS256";
                            }

                            @Override
                            public boolean verify(byte[] data, byte[] signature) {
                                try {
                                    Signature verifier = Signature.getInstance("SHA256withRSA");
                                    verifier.initVerify((PublicKey) key.getPublicKey());
                                    verifier.update(data);
                                    return verifier.verify(signature);
                                } catch (Exception e) {
                                    return false;
                                }
                            }
                        };
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return (KeycloakSession) Proxy.newProxyInstance(ThisRealmVerificationTest.class.getClassLoader(),
                new Class<?>[]{KeycloakSession.class}, (proxy, method, args) -> {
                    if ("getProvider".equals(method.getName()) && args != null && args.length == 2) {
                        return provider;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    /**
     * One of this realm's own ID Tokens, about one of its own users: the document, the discovery and the
     * JWK set used to be three loopback requests. Now none, and the keys are the realm's own.
     */
    @Test
    void thisRealmsOwnIdTokenNeedsNoFetch() throws Exception {
        KeyPair pair = rsa();
        ThisRealm realm = realm(ISSUER, user(List.of()), rsaKey("realm-key", pair.getPublic()));

        VerificationResult result = new LWSCredentialVerifier(rs256Session())
                .localTo(realm, LWSResourceProvider.DOCUMENTS).verify(idToken("realm-key", pair));

        assertTrue(result.isValid(), () -> result.getErrors() + " " + result.getChecks());
        for (String check : new String[]{"subjectDereferenced", "subjectIdMatches", "openIdProviderServiceLocated",
                "issuerDiscoveryMatches", "jwksResolved", "signatureValid"}) {
            assertEquals(Boolean.TRUE, result.getChecks().get(check), check);
        }

        VerificationResult unknownKid = new LWSCredentialVerifier(rs256Session())
                .localTo(realm, LWSResourceProvider.DOCUMENTS).verify(idToken("another-key", pair));
        assertFalse(unknownKid.isValid());
        assertEquals(Boolean.FALSE, unknownKid.getChecks().get("jwksResolved"));
    }
}
