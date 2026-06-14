/*
 * Copyright Erich Bremer.
 *
 * Decoding (and encoding) of did:key identifiers per "The did:key Method" — multibase base58btc plus
 * a multicodec key-type prefix. Supports Ed25519 (0xed01) and P-256 (0x1200). Pure JDK: no
 * BouncyCastle, so it works under both the default and FIPS Keycloak crypto providers.
 */
package com.ebremer.lws.authn.ssididkey;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * @author Erich Bremer
 */
public final class DidKey {

    private DidKey() {
    }

    public static final String DID_KEY_PREFIX = "did:key:";

    private static final String BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // multicodec varint prefixes
    private static final byte[] MC_ED25519 = {(byte) 0xed, (byte) 0x01}; // 0xed
    private static final byte[] MC_P256 = {(byte) 0x80, (byte) 0x24};    // 0x1200

    // P-256 (secp256r1) domain parameters, for point decompression
    private static final BigInteger P = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    private static final BigInteger B = new BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);

    // SubjectPublicKeyInfo header preceding the 32 raw bytes of an Ed25519 public key
    private static final byte[] ED25519_SPKI_PREFIX = hex("302a300506032b6570032100");

    /** A public key decoded from a did:key, with its key type and the JWS algorithm it signs with. */
    public record DecodedKey(PublicKey publicKey, String keyType, String jwsAlgorithm) {
    }

    /** Decodes the public key embedded in a {@code did:key} identifier (Ed25519 or P-256). */
    public static DecodedKey decode(String did) {
        if (did == null || !did.startsWith(DID_KEY_PREFIX)) {
            throw new IllegalArgumentException("Not a did:key identifier: " + did);
        }
        String multibase = did.substring(DID_KEY_PREFIX.length());
        int fragment = multibase.indexOf('#');
        if (fragment >= 0) {
            multibase = multibase.substring(0, fragment);
        }
        if (multibase.isEmpty() || multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException("did:key must use base58btc multibase (leading 'z')");
        }
        byte[] bytes = base58Decode(multibase.substring(1));
        if (startsWith(bytes, MC_ED25519)) {
            return new DecodedKey(ed25519PublicKey(Arrays.copyOfRange(bytes, 2, bytes.length)), "Ed25519", "EdDSA");
        }
        if (startsWith(bytes, MC_P256)) {
            return new DecodedKey(p256PublicKey(Arrays.copyOfRange(bytes, 2, bytes.length)), "P-256", "ES256");
        }
        throw new IllegalArgumentException("Unsupported did:key key type (only Ed25519 and P-256 are supported)");
    }

    public static PublicKey toPublicKey(String did) {
        return decode(did).publicKey();
    }

    // ---- did:key encoding (for minting / tests) ----

    public static String encodeP256(ECPublicKey key) {
        ECPoint w = key.getW();
        byte[] compressed = new byte[33];
        compressed[0] = w.getAffineY().testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(toFixed(w.getAffineX(), 32), 0, compressed, 1, 32);
        return DID_KEY_PREFIX + "z" + base58Encode(concat(MC_P256, compressed));
    }

    public static String encodeEd25519(PublicKey key) {
        byte[] spki = key.getEncoded();
        byte[] raw = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        return DID_KEY_PREFIX + "z" + base58Encode(concat(MC_ED25519, raw));
    }

    // ---- key building ----

    private static PublicKey ed25519PublicKey(byte[] raw32) {
        try {
            if (raw32.length != 32) {
                throw new IllegalArgumentException("Ed25519 key must be 32 bytes");
            }
            return KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(concat(ED25519_SPKI_PREFIX, raw32)));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not build Ed25519 key: " + e.getMessage(), e);
        }
    }

    private static PublicKey p256PublicKey(byte[] compressed) {
        try {
            if (compressed.length != 33 || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
                throw new IllegalArgumentException("Invalid P-256 compressed point");
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, 33));
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), P).add(A.multiply(x)).add(B).mod(P);
            BigInteger y = rhs.modPow(P.add(BigInteger.ONE).shiftRight(2), P); // p ≡ 3 (mod 4)
            if (!y.multiply(y).mod(P).equals(rhs)) {
                throw new IllegalArgumentException("Point is not on the P-256 curve");
            }
            if (y.testBit(0) != (compressed[0] == 0x03)) {
                y = P.subtract(y);
            }
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecSpec));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not build P-256 key: " + e.getMessage(), e);
        }
    }

    // ---- base58btc ----

    public static byte[] base58Decode(String input) {
        BigInteger value = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);
        for (int i = 0; i < input.length(); i++) {
            int digit = BASE58.indexOf(input.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58 character: " + input.charAt(i));
            }
            value = value.multiply(base).add(BigInteger.valueOf(digit));
        }
        byte[] full = value.toByteArray();
        int from = (full.length > 1 && full[0] == 0) ? 1 : 0; // drop BigInteger sign byte
        int leadingZeros = 0;
        while (leadingZeros < input.length() && input.charAt(leadingZeros) == '1') {
            leadingZeros++;
        }
        byte[] out = new byte[leadingZeros + full.length - from];
        System.arraycopy(full, from, out, leadingZeros, full.length - from);
        return out;
    }

    public static String base58Encode(byte[] input) {
        BigInteger value = new BigInteger(1, input);
        BigInteger base = BigInteger.valueOf(58);
        StringBuilder sb = new StringBuilder();
        while (value.signum() > 0) {
            BigInteger[] qr = value.divideAndRemainder(base);
            sb.append(BASE58.charAt(qr[1].intValue()));
            value = qr[0];
        }
        for (byte b : input) {
            if (b == 0) {
                sb.append('1');
            } else {
                break;
            }
        }
        return sb.reverse().toString();
    }

    // ---- helpers ----

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        byte[] out = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, out, 0, length); // strip leading sign byte
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length); // left-pad
        }
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
