/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

/**
 * A pre-computed table of multiples of a basepoint, for accelerating fixed-base
 * scalar multiplication.
 */
public class EdwardsBasepointTable {
    final AffineNielsPoint.LookupTable[] tables;

    /**
     * Create a table of pre-computed multiples of basepoint.
     */
    public EdwardsBasepointTable(final EdwardsPoint basepoint) {
        this.tables = new AffineNielsPoint.LookupTable[32];
        EdwardsPoint Bi = basepoint;
        for (int i = 0; i < 32; i++) {
            this.tables[i] = AffineNielsPoint.buildLookupTable(Bi);
            // Only every second summand is precomputed (16^2 = 256)
            Bi = Bi.multiplyByPow2(8);
        }
    }

    /**
     * Constant-time fixed-base scalar multiplication.
     *
     * @param s the Scalar to multiply by.
     * @return $[s]B$
     */
    public EdwardsPoint multiply(final Scalar s) {
        int i;

        final byte[] e = s.toRadix16();

        EdwardsPoint h = EdwardsPoint.IDENTITY;
        for (i = 1; i < 64; i += 2) {
            h = h.add(this.tables[i / 2].select(e[i])).toExtended();
        }

        h = h.multiplyByPow2(4);

        for (i = 0; i < 64; i += 2) {
            h = h.add(this.tables[i / 2].select(e[i])).toExtended();
        }

        return h;
    }
}
