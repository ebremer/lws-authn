/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Decoding (and encoding) of did:key identifiers per "The did:key Method" — multibase base58btc plus
 * a multicodec key-type prefix. Supports Ed25519 (0xed01) and the NIST curves P-256 (0x1200),
 * P-384 (0x1201) and P-521 (0x1202). Pure JDK: no BouncyCastle, so it works under both the default
 * and FIPS Keycloak crypto providers.
 */
package com.ebremer.lws.authn.ssididkey;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
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
    private static final byte[] MC_P384 = {(byte) 0x81, (byte) 0x24};    // 0x1201
    private static final byte[] MC_P521 = {(byte) 0x82, (byte) 0x24};    // 0x1202

    // SubjectPublicKeyInfo header preceding the 32 raw bytes of an Ed25519 public key
    private static final byte[] ED25519_SPKI_PREFIX = hex("302a300506032b6570032100");

    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    /**
     * The elliptic curves this method supports, each with its multicodec prefix, its JDK curve name,
     * its coordinate size in bytes and the JWS algorithm it signs with.
     *
     * <p>Domain parameters are read from the JDK rather than written out here: p, a and b for each
     * curve come from {@link AlgorithmParameters}, so a new curve is one row of this table and there
     * are no hand-transcribed constants to get subtly wrong.</p>
     */
    private enum Curve {
        P256(MC_P256, "secp256r1", "P-256", 32, "ES256"),
        P384(MC_P384, "secp384r1", "P-384", 48, "ES384"),
        P521(MC_P521, "secp521r1", "P-521", 66, "ES512");

        private final byte[] multicodec;
        private final String jdkName;
        private final String keyType;
        private final int coordinateBytes;
        private final String jwsAlgorithm;

        Curve(byte[] multicodec, String jdkName, String keyType, int coordinateBytes, String jwsAlgorithm) {
            this.multicodec = multicodec;
            this.jdkName = jdkName;
            this.keyType = keyType;
            this.coordinateBytes = coordinateBytes;
            this.jwsAlgorithm = jwsAlgorithm;
        }

        static Curve byKeyType(String keyType) {
            for (Curve curve : values()) {
                if (curve.keyType.equals(keyType)) {
                    return curve;
                }
            }
            return null;
        }
    }

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

        DecodedKey decoded = null;
        if (startsWith(bytes, MC_ED25519)) {
            decoded = new DecodedKey(ed25519PublicKey(Arrays.copyOfRange(bytes, 2, bytes.length)), "Ed25519", "EdDSA");
        } else {
            for (Curve curve : Curve.values()) {
                if (startsWith(bytes, curve.multicodec)) {
                    decoded = new DecodedKey(ecPublicKey(curve, Arrays.copyOfRange(bytes, 2, bytes.length)),
                            curve.keyType, curve.jwsAlgorithm);
                    break;
                }
            }
        }
        if (decoded == null) {
            throw new IllegalArgumentException(
                    "Unsupported did:key key type (supported: Ed25519, P-256, P-384, P-521)");
        }

        // A did:key IS its key, so the mapping must be one-to-one. Re-encoding the decoded key and
        // requiring the exact input back rejects any non-canonical spelling — a base58 string with
        // extra leading '1's, or an uncompressed point — that would otherwise give one key two
        // identifiers, and so let one agent present itself as two subjects.
        String canonical = encode(decoded);
        if (!canonical.equals(DID_KEY_PREFIX + multibase)) {
            throw new IllegalArgumentException("did:key is not canonically encoded");
        }
        return decoded;
    }

    /** Re-encodes a decoded key as its canonical {@code did:key} identifier. */
    public static String encode(DecodedKey decoded) {
        if ("Ed25519".equals(decoded.keyType())) {
            return encodeEd25519(decoded.publicKey());
        }
        Curve curve = Curve.byKeyType(decoded.keyType());
        if (curve == null) {
            throw new IllegalArgumentException("Cannot encode key type " + decoded.keyType());
        }
        return encodeEc(curve, (ECPublicKey) decoded.publicKey());
    }

    public static PublicKey toPublicKey(String did) {
        return decode(did).publicKey();
    }

    // ---- did:key encoding (for minting / tests) ----

    public static String encodeP256(ECPublicKey key) {
        return encodeEc(Curve.P256, key);
    }

    public static String encodeP384(ECPublicKey key) {
        return encodeEc(Curve.P384, key);
    }

    public static String encodeP521(ECPublicKey key) {
        return encodeEc(Curve.P521, key);
    }

    private static String encodeEc(Curve curve, ECPublicKey key) {
        ECPoint w = key.getW();
        byte[] compressed = new byte[curve.coordinateBytes + 1];
        compressed[0] = w.getAffineY().testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(toFixed(w.getAffineX(), curve.coordinateBytes), 0, compressed, 1, curve.coordinateBytes);
        return DID_KEY_PREFIX + "z" + base58Encode(concat(curve.multicodec, compressed));
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

    /**
     * Decompresses a SEC1 compressed point onto {@code curve}. All three NIST primes are congruent to
     * 3 mod 4, so the square root is a single modular exponentiation; that congruence is asserted
     * rather than assumed, since it is the one property this shortcut depends on.
     */
    private static PublicKey ecPublicKey(Curve curve, byte[] compressed) {
        try {
            if (compressed.length != curve.coordinateBytes + 1
                    || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
                throw new IllegalArgumentException("Invalid " + curve.keyType + " compressed point");
            }
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec(curve.jdkName));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
            EllipticCurve ec = ecSpec.getCurve();
            ECField field = ec.getField();
            if (!(field instanceof ECFieldFp fp)) {
                throw new IllegalArgumentException(curve.keyType + " is not a prime-field curve");
            }
            BigInteger p = fp.getP();
            if (!p.mod(FOUR).equals(THREE)) {
                throw new IllegalStateException("Square root shortcut needs p = 3 (mod 4) for " + curve.keyType);
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, compressed.length));
            if (x.compareTo(p) >= 0) {
                throw new IllegalArgumentException("Point x coordinate is out of range for " + curve.keyType);
            }
            BigInteger rhs = x.modPow(THREE, p).add(ec.getA().multiply(x)).add(ec.getB()).mod(p);
            BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p); // p = 3 (mod 4)
            if (!y.multiply(y).mod(p).equals(rhs)) {
                throw new IllegalArgumentException("Point is not on the " + curve.keyType + " curve");
            }
            if (y.testBit(0) != (compressed[0] == 0x03)) {
                y = p.subtract(y);
            }
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecSpec));
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not build " + curve.keyType + " key: " + e.getMessage(), e);
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
