/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.did;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;

/**
 * The multibase codec, now also the reader for CID 1.0 {@code Multikey} verification methods.
 */
class DidKeyTest {

    /**
     * The did:key Method's test vectors — which are also the keys CID 1.0 Appendix B.1 uses for its
     * Multikey examples.
     */
    @Test
    void decodesTheSpecificationVectors() {
        assertKey("z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP", "Ed25519", "EdDSA");
        assertKey("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "Ed25519", "EdDSA");
        assertKey("zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv", "P-256", "ES256");
        assertKey("z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54", "P-384", "ES384");
        // CID 1.0 §3.3 Example 20
        assertKey("z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu", "Ed25519", "EdDSA");
    }

    private static void assertKey(String multibase, String keyType, String alg) {
        DidKey.DecodedKey key = DidKey.decodeMultibase(multibase);
        assertEquals(keyType, key.keyType(), multibase);
        assertEquals(alg, key.jwsAlgorithm(), multibase);
        assertEquals(multibase, DidKey.multibaseOf(key), "canonical round trip");
        assertEquals(key.keyType(), DidKey.decode("did:key:" + multibase).keyType());
    }

    /** secp256k1, BLS12-381 G2 and SM2 are Multikey types this provider cannot verify a JWS with. */
    @Test
    void refusesKeyTypesItCannotVerifyWith() {
        for (String unsupported : new String[]{
                "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                "zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb",
                "zEPJc1vCfbG2aoZn8f3U8ggYRL4ZFfF63ZA3qFSk81WJxnCQr"}) {
            assertThrows(IllegalArgumentException.class, () -> DidKey.decodeMultibase(unsupported), unsupported);
        }
        assertThrows(IllegalArgumentException.class, () -> DidKey.decodeMultibase("uABC"), "base64url multibase");
        assertThrows(IllegalArgumentException.class, () -> DidKey.decodeMultibase(null));
    }

    /**
     * CID 1.0 §2.2.2: an implementation must raise an error on a value "expected to be a public key"
     * that does not start with a public key header. A secret-key header is named as such, because it
     * means somebody published a private key.
     */
    @Test
    void refusesASecretKeyByName() {
        for (int[] header : new int[][]{{0x80, 0x26}, {0x86, 0x26}, {0x87, 0x26}, {0x88, 0x26}}) {
            byte[] bytes = new byte[34];
            new SecureRandom().nextBytes(bytes);
            bytes[0] = (byte) header[0];
            bytes[1] = (byte) header[1];
            String multibase = "z" + DidKey.base58Encode(bytes);
            IllegalArgumentException refused =
                    assertThrows(IllegalArgumentException.class, () -> DidKey.decodeMultibase(multibase));
            assertTrue(refused.getMessage().contains("secret"), refused.getMessage());
        }
    }

    /** The JWK a Multikey becomes must be exactly the same key, and carry nothing private. */
    @Test
    void expressesEveryKeyTypeAsTheSameJwk() throws Exception {
        String[][] curves = {{"secp256r1", "P-256", "ES256", "32"}, {"secp384r1", "P-384", "ES384", "48"},
                             {"secp521r1", "P-521", "ES512", "66"}};
        for (String[] curve : curves) {
            KeyPair pair = SelfIssuedJwts.ec(curve[0]);
            ECPublicKey original = (ECPublicKey) pair.getPublic();
            String did = switch (curve[1]) {
                case "P-256" -> DidKey.encodeP256(original);
                case "P-384" -> DidKey.encodeP384(original);
                default -> DidKey.encodeP521(original);
            };
            Map<String, String> jwk = DidKey.toJwk(DidKey.decodeMultibase(DidKey.multibaseValue(did)));

            assertEquals("EC", jwk.get("kty"));
            assertEquals(curve[1], jwk.get("crv"));
            assertEquals(curve[2], jwk.get("alg"));
            assertFalse(jwk.containsKey("d"));
            byte[] x = Base64.getUrlDecoder().decode(jwk.get("x"));
            byte[] y = Base64.getUrlDecoder().decode(jwk.get("y"));
            assertEquals(Integer.parseInt(curve[3]), x.length, "fixed-length x");
            assertEquals(Integer.parseInt(curve[3]), y.length, "fixed-length y");
            PublicKey rebuilt = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                    new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), original.getParams()));
            assertArrayEquals(original.getEncoded(), rebuilt.getEncoded(), curve[1]);
        }

        KeyPair ed = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(ed.getPublic());
        Map<String, String> jwk = DidKey.toJwk(DidKey.decode(did));
        byte[] spki = ed.getPublic().getEncoded();
        assertEquals("OKP", jwk.get("kty"));
        assertEquals("Ed25519", jwk.get("crv"));
        assertEquals("EdDSA", jwk.get("alg"));
        assertArrayEquals(Arrays.copyOfRange(spki, spki.length - 32, spki.length),
                Base64.getUrlDecoder().decode(jwk.get("x")));
        assertFalse(jwk.containsKey("d"));
    }

    @Test
    void readsTheMultibaseValueOfADidKey() {
        assertEquals("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                DidKey.multibaseValue("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
        assertEquals("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                DidKey.multibaseValue("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6Mkha"));
        assertThrows(IllegalArgumentException.class, () -> DidKey.multibaseValue("did:web:example.com"));
    }
}
