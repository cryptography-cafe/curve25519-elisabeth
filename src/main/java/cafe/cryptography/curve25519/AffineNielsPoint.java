/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import cafe.cryptography.subtle.ConstantTime;

/**
 * A pre-computed point on the affine model of the curve, represented as $(y+x,
 * y-x, 2dxy)$ in "Niels coordinates".
 */
class AffineNielsPoint {
    static final AffineNielsPoint IDENTITY = new AffineNielsPoint(FieldElement.ONE, FieldElement.ONE,
            FieldElement.ZERO);

    final FieldElement yPlusx;
    final FieldElement yMinusx;
    final FieldElement xy2D;

    AffineNielsPoint(FieldElement yPlusx, FieldElement yMinusx, FieldElement xy2D) {
        this.yPlusx = yPlusx;
        this.yMinusx = yMinusx;
        this.xy2D = xy2D;
    }

    /**
     * Constant-time selection between two AffineNielsPoints.
     *
     * @param that the other point.
     * @param b    must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of that if $b == 1$.
     */
    public AffineNielsPoint ctSelect(AffineNielsPoint that, int b) {
        return new AffineNielsPoint(this.yPlusx.ctSelect(that.yPlusx, b), this.yMinusx.ctSelect(that.yMinusx, b),
                this.xy2D.ctSelect(that.xy2D, b));
    }

    /**
     * Point negation.
     *
     * @return $-P$
     */
    public AffineNielsPoint negate() {
        return new AffineNielsPoint(this.yMinusx, this.yPlusx, this.xy2D.negate());
    }

    /**
     * Construct a lookup table of $[P, [2]P, [3]P, [4]P, [5]P, [6]P, [7]P, [8]P]$.
     *
     * @param P the point to calculate multiples for.
     * @return the lookup table.
     */
    static LookupTable buildLookupTable(EdwardsPoint P) {
        AffineNielsPoint[] points = new AffineNielsPoint[8];
        points[0] = P.toAffineNiels();
        for (int i = 0; i < 7; i++) {
            points[i + 1] = P.add(points[i]).toExtended().toAffineNiels();
        }
        return new AffineNielsPoint.LookupTable(points);
    }

    static class LookupTable {
        private final AffineNielsPoint[] table;

        LookupTable(AffineNielsPoint[] table) {
            this.table = table;
        }

        /**
         * Given $-8 \leq x \leq 8$, return $[x]P$ in constant time.
         *
         * @param x the index.
         * @return the pre-computed point.
         */
        AffineNielsPoint select(final int x) {
            if (x < -8 || x > 8) {
                throw new IllegalArgumentException("x is not in range -8 <= x <= 8");
            }

            // Is x negative?
            final int xNegative = ConstantTime.isNegative(x);
            // |x|
            final int xabs = x - (((-xNegative) & x) << 1);

            // |x| P
            AffineNielsPoint t = AffineNielsPoint.IDENTITY;
            for (int i = 1; i < 9; i++) {
                t = t.ctSelect(this.table[i - 1], ConstantTime.equal(xabs, i));
            }

            // -|x| P
            final AffineNielsPoint tminus = t.negate();
            // [x]P
            return t.ctSelect(tminus, xNegative);
        }
    }

    /**
     * Construct a lookup table of $[P, [3]P, [5]P, [7]P, [9]P, [11]P, [13]P,
     * [15]P]$.
     *
     * @param P the point to calculate multiples for.
     * @return the lookup table.
     */
    static NafLookupTable buildNafLookupTable(EdwardsPoint P) {
        AffineNielsPoint[] points = new AffineNielsPoint[8];
        points[0] = P.toAffineNiels();
        EdwardsPoint P2 = P.dbl();
        for (int i = 0; i < 7; i++) {
            points[i + 1] = P2.add(points[i]).toExtended().toAffineNiels();
        }
        return new AffineNielsPoint.NafLookupTable(points);
    }

    static class NafLookupTable {
        private final AffineNielsPoint[] table;

        NafLookupTable(AffineNielsPoint[] table) {
            this.table = table;
        }

        /**
         * Given public, odd $x$ with $0 \lt x \lt 2^4$, return $[x]A$.
         *
         * @param x the index.
         * @return the pre-computed point.
         */
        AffineNielsPoint select(final int x) {
            if ((x % 2 == 0) || x >= 16) {
                throw new IllegalArgumentException("invalid x");
            }

            return this.table[x / 2];
        }
    }
}
