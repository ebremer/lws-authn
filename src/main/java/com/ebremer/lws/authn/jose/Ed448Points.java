/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validation of an Ed448 public key's encoding, which the JDK does not perform when it builds a key.
 */
package com.ebremer.lws.authn.jose;

import java.math.BigInteger;

/**
 * Decides whether 57 bytes are an Ed448 public key a verifier should accept: the Ed448 counterpart of
 * the Ed25519 check R-27 added (R-38).
 *
 * <p>Keycloak's EdDSA verifier accepts Ed448 keys as well as Ed25519 ones, and like the JDK underneath it
 * checks nothing about the point until a signature is verified. A point of small order — the identity,
 * or one of the three others whose order divides the cofactor, 4 — is a key for which forged signatures
 * verify; a non-canonical encoding gives one point two spellings. Both are refused.</p>
 *
 * <p>Decoding follows RFC 8032 §5.2.3; the order test multiplies the point by the cofactor with the
 * complete Edwards addition law of §5.2.4 and compares the result with the identity. All of it is
 * arithmetic on public values.</p>
 *
 * @author Erich Bremer
 */
final class Ed448Points {

    private Ed448Points() {
    }

    /** p = 2^448 − 2^224 − 1. */
    private static final BigInteger P = BigInteger.TWO.pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE);

    /** d = −39081 mod p. */
    private static final BigInteger D = BigInteger.valueOf(-39081).mod(P);

    /**
     * Why {@code encoded} is not an acceptable Ed448 public key, or {@code null} if it is.
     *
     * @param encoded the 57-byte encoding of RFC 8032 §5.2.2
     */
    static String problem(byte[] encoded) {
        if (encoded == null || encoded.length != 57) {
            return "an Ed448 key is 57 bytes";
        }
        // §5.2.3 step 1: little-endian; bit 455 is x's least significant bit, and y is what is left.
        byte[] bigEndian = new byte[57];
        for (int i = 0; i < 57; i++) {
            bigEndian[i] = encoded[56 - i];
        }
        boolean sign = (bigEndian[0] & 0x80) != 0;
        bigEndian[0] &= 0x7f;
        BigInteger y = new BigInteger(1, bigEndian);
        if (y.compareTo(P) >= 0) {
            return "the Ed448 key is not canonically encoded (y is not reduced mod p)";
        }
        // Steps 2 and 3: x² = (y² − 1) / (d·y² − 1), x = u³v (u⁵v³)^((p−3)/4), and v·x² must be u.
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(y2).subtract(BigInteger.ONE).mod(P);
        BigInteger u3v = u.pow(3).multiply(v).mod(P);
        BigInteger u5v3 = u.pow(5).multiply(v.pow(3)).mod(P);
        BigInteger x = u3v.multiply(u5v3.modPow(P.subtract(BigInteger.valueOf(3)).shiftRight(2), P)).mod(P);
        if (!v.multiply(x).multiply(x).mod(P).equals(u)) {
            return "the Ed448 key is not a point on the curve";
        }
        // Step 4.
        if (x.signum() == 0 && sign) {
            return "the Ed448 key is not canonically encoded (x is zero with the sign bit set)";
        }
        if (x.testBit(0) != sign) {
            x = P.subtract(x);
        }
        BigInteger[] point = {x, y};
        for (int i = 0; i < 2; i++) {
            point = add(point, point);
        }
        if (point[0].signum() == 0 && point[1].equals(BigInteger.ONE)) {
            return "the Ed448 key is a point of small order, for which forged signatures verify";
        }
        return null;
    }

    /** The Edwards sum of RFC 8032 §5.2.4 (a = 1), which is complete on Ed448: it also doubles. */
    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        BigInteger x1y2 = a[0].multiply(b[1]);
        BigInteger x2y1 = b[0].multiply(a[1]);
        BigInteger y1y2 = a[1].multiply(b[1]);
        BigInteger x1x2 = a[0].multiply(b[0]);
        BigInteger dxxyy = D.multiply(x1x2).mod(P).multiply(y1y2).mod(P);
        BigInteger x3 = x1y2.add(x2y1).multiply(BigInteger.ONE.add(dxxyy).modInverse(P)).mod(P);
        BigInteger y3 = y1y2.subtract(x1x2).multiply(BigInteger.ONE.subtract(dxxyy).mod(P).modInverse(P)).mod(P);
        return new BigInteger[]{x3, y3};
    }
}
