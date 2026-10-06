/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validation of an Ed25519 public key's encoding, which the JDK does not perform when it builds a key.
 */
package com.ebremer.lws.authn.did;

import java.math.BigInteger;

/**
 * Decides whether 32 bytes are an Ed25519 public key a verifier should accept.
 *
 * <p>The JDK builds an Ed25519 key from any 32 bytes and decides nothing until a signature is checked,
 * and then accepts two kinds of key this provider must not (R-27):</p>
 * <ul>
 *   <li><strong>A point of small order</strong> — the identity, or one of the seven others whose order
 *       divides 8. With the identity as the key, the signature {@code (R = identity, S = 0)} verifies
 *       <em>any</em> message, so a {@code did:key} built from it is one anybody can sign for.</li>
 *   <li><strong>A non-canonical encoding</strong>, with {@code y ≥ p}. RFC 8032 §5.1.3: "If the resulting
 *       value is &gt;= p, decoding fails." The JDK keeps the bytes as given, so re-encoding the key — the
 *       check that makes a {@code did:key} one-to-one with its key — gave them back unchanged, and one
 *       point had two identifiers.</li>
 * </ul>
 *
 * <p>Decoding follows RFC 8032 §5.1.3; the order test multiplies the point by the cofactor, 8, with the
 * complete twisted Edwards addition law, and compares the result with the identity. All of it is
 * arithmetic on public values.</p>
 *
 * @author Erich Bremer
 */
final class Ed25519Points {

    private Ed25519Points() {
    }

    /** p = 2^255 − 19. */
    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

    /** d = −121665 / 121666 mod p. */
    private static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);

    /** A square root of −1 mod p: 2^((p−1)/4). */
    private static final BigInteger SQRT_M1 = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);

    /**
     * Why {@code encoded} is not an acceptable Ed25519 public key, or {@code null} if it is.
     *
     * @param encoded the 32-byte encoding of RFC 8032 §5.1.2
     */
    static String problem(byte[] encoded) {
        if (encoded == null || encoded.length != 32) {
            return "an Ed25519 key is 32 bytes";
        }
        byte[] bigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            bigEndian[i] = encoded[31 - i];
        }
        boolean sign = (bigEndian[0] & 0x80) != 0;
        bigEndian[0] &= 0x7f;
        BigInteger y = new BigInteger(1, bigEndian);
        if (y.compareTo(P) >= 0) {
            return "the Ed25519 key is not canonically encoded (y is not reduced mod p)";
        }
        // x² = (y² − 1) / (d·y² + 1)
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger v3 = v.pow(3).mod(P);
        BigInteger x = u.multiply(v3).multiply(u.multiply(v3).multiply(v3).multiply(v).mod(P)
                .modPow(P.subtract(BigInteger.valueOf(5)).shiftRight(3), P)).mod(P);
        BigInteger vx2 = v.multiply(x).multiply(x).mod(P);
        if (!vx2.equals(u)) {
            if (vx2.equals(u.negate().mod(P))) {
                x = x.multiply(SQRT_M1).mod(P);
            } else {
                return "the Ed25519 key is not a point on the curve";
            }
        }
        if (x.signum() == 0 && sign) {
            return "the Ed25519 key is not canonically encoded (x is zero with the sign bit set)";
        }
        if (x.testBit(0) != sign) {
            x = P.subtract(x);
        }
        BigInteger[] point = {x, y};
        for (int i = 0; i < 3; i++) {
            point = add(point, point);
        }
        if (point[0].signum() == 0 && point[1].equals(BigInteger.ONE)) {
            return "the Ed25519 key is a point of small order, for which any message has a valid signature";
        }
        return null;
    }

    /** The twisted Edwards sum (a = −1), which is complete on Ed25519: it also doubles. */
    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        BigInteger x1y2 = a[0].multiply(b[1]);
        BigInteger y1x2 = a[1].multiply(b[0]);
        BigInteger y1y2 = a[1].multiply(b[1]);
        BigInteger x1x2 = a[0].multiply(b[0]);
        BigInteger dxxyy = D.multiply(x1x2).mod(P).multiply(y1y2).mod(P);
        BigInteger x3 = x1y2.add(y1x2).multiply(BigInteger.ONE.add(dxxyy).modInverse(P)).mod(P);
        BigInteger y3 = y1y2.add(x1x2).multiply(BigInteger.ONE.subtract(dxxyy).mod(P).modInverse(P)).mod(P);
        return new BigInteger[]{x3, y3};
    }
}
