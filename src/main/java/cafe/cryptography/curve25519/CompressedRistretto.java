/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import java.util.Arrays;

import cafe.cryptography.subtle.ConstantTime;

/**
 * A Ristretto point in compressed wire format.
 * <p>
 * The Ristretto encoding is canonical, so two points are equal if and only if
 * their encodings are equal.
 */
public class CompressedRistretto {
    /**
     * The encoded point.
     */
    private final byte[] data;

    public CompressedRistretto(byte[] data) {
        if (data.length != 32) {
            throw new IllegalArgumentException("Invalid CompressedRistretto encoding");
        }
        this.data = data;
    }

    /**
     * Attempts to decompress to a RistrettoElement.
     * <p>
     * This is the ristretto255 DECODE function.
     *
     * @return a RistrettoElement, if this is the canonical encoding of an element
     *         of the ristretto255 group.
     */
    public RistrettoElement decompress() {
        // 1. First, interpret the string as an integer s in little-endian
        // representation. If the resulting value is >= p, decoding fails.
        // 2. If IS_NEGATIVE(s) returns TRUE, decoding fails.
        final FieldElement s = FieldElement.fromByteArray(this.data);
        final byte[] sBytes = s.toByteArray();
        final int sIsCanonical = ConstantTime.equal(this.data, sBytes);
        if (sIsCanonical == 0 || s.isNegative() == 1) {
            throw new IllegalArgumentException("Invalid ristretto255 encoding");
        }

        // 3. Process s as follows:
        final FieldElement ss = s.square();
        final FieldElement u1 = FieldElement.ONE.subtract(ss);
        final FieldElement u2 = FieldElement.ONE.add(ss);
        final FieldElement u2Sqr = u2.square();

        final FieldElement v = Constants.NEG_EDWARDS_D.multiply(u1.square()).subtract(u2Sqr);

        final FieldElement.SqrtRatioM1Result invsqrt = FieldElement.sqrtRatioM1(FieldElement.ONE, v.multiply(u2Sqr));

        final FieldElement denX = invsqrt.result.multiply(u2);
        final FieldElement denY = invsqrt.result.multiply(denX).multiply(v);

        final FieldElement x = s.add(s).multiply(denX).ctAbs();
        final FieldElement y = u1.multiply(denY);
        final FieldElement t = x.multiply(y);

        // 4. If was_square is FALSE, or IS_NEGATIVE(t) returns TRUE, or y = 0, decoding
        // fails. Otherwise, return the internal representation in extended coordinates
        // (x, y, 1, t).
        if (invsqrt.wasSquare == 0 || t.isNegative() == 1 || y.isZero() == 1) {
            throw new IllegalArgumentException("Invalid ristretto255 encoding");
        } else {
            return new RistrettoElement(new EdwardsPoint(x, y, FieldElement.ONE, t));
        }
    }

    /**
     * Encode the element to its compressed 32-byte form.
     *
     * @return the encoded element.
     */
    public byte[] toByteArray() {
        return data;
    }

    /**
     * Constant-time equality check.
     *
     * @return 1 if this and other are equal, 0 otherwise.
     */
    public int ctEquals(CompressedRistretto other) {
        return ConstantTime.equal(data, other.data);
    }

    /**
     * Equality check overridden to be constant-time.
     * <p>
     * Fails fast if the objects are of different types.
     *
     * @return true if this and other are equal, false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CompressedRistretto)) {
            return false;
        }

        CompressedRistretto other = (CompressedRistretto) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
