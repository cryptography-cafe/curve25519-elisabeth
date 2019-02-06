package cafe.cryptography.curve25519;

import cafe.cryptography.subtle.ConstantTime;

/**
 * A pre-computed point on the $\mathbb P^3$ model of the curve, represented as
 * $(Y+X, Y-X, Z, 2dXY)$ in "Niels coordinates".
 */
class ProjectiveNielsPoint {
    static final ProjectiveNielsPoint IDENTITY = new ProjectiveNielsPoint(FieldElement.ONE, FieldElement.ONE,
            FieldElement.ONE, FieldElement.ZERO);

    final FieldElement YPlusX;
    final FieldElement YMinusX;
    final FieldElement Z;
    final FieldElement T2D;

    ProjectiveNielsPoint(FieldElement YPlusX, FieldElement YMinusX, FieldElement Z, FieldElement T2D) {
        this.YPlusX = YPlusX;
        this.YMinusX = YMinusX;
        this.Z = Z;
        this.T2D = T2D;
    }

    /**
     * Constant-time selection between two ProjectiveNielsPoints.
     *
     * @param that the other point.
     * @param b    must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of that if $b == 1$.
     */
    public ProjectiveNielsPoint ctSelect(ProjectiveNielsPoint that, int b) {
        return new ProjectiveNielsPoint(this.YPlusX.ctSelect(that.YPlusX, b), this.YMinusX.ctSelect(that.YMinusX, b),
                this.Z.ctSelect(that.Z, b), this.T2D.ctSelect(that.T2D, b));
    }

    /**
     * Point negation.
     *
     * @return $-P$
     */
    public ProjectiveNielsPoint negate() {
        return new ProjectiveNielsPoint(this.YMinusX, this.YPlusX, this.Z, this.T2D.negate());
    }

    /**
     * Construct a lookup table of $[P, [2]P, [3]P, [4]P, [5]P, [6]P, [7]P, [8]P]$.
     *
     * @param P the point to calculate multiples for.
     * @return the lookup table.
     */
    static LookupTable buildLookupTable(EdwardsPoint P) {
        final ProjectiveNielsPoint[] points = new ProjectiveNielsPoint[8];
        points[0] = P.toProjectiveNiels();
        for (int i = 0; i < 7; i++) {
            points[i + 1] = P.add(points[i]).toExtended().toProjectiveNiels();
        }
        return new ProjectiveNielsPoint.LookupTable(points);
    }

    static class LookupTable {
        private final ProjectiveNielsPoint[] table;

        LookupTable(ProjectiveNielsPoint[] table) {
            this.table = table;
        }

        /**
         * Given $-8 \leq x \leq 8$, return $[x]P$ in constant time.
         *
         * @param x the index.
         * @return the pre-computed point.
         */
        ProjectiveNielsPoint select(final int x) {
            if (x < -8 || x > 8) {
                throw new IllegalArgumentException("x is not in range -8 <= x <= 8");
            }

            // Is x negative?
            final int xNegative = ConstantTime.isNegative(x);
            // |x|
            final int xabs = x - (((-xNegative) & x) << 1);

            // |x| P
            ProjectiveNielsPoint t = ProjectiveNielsPoint.IDENTITY;
            for (int i = 1; i < 9; i++) {
                t = t.ctSelect(this.table[i - 1], ConstantTime.equal(xabs, i));
            }

            // -|x| P
            final ProjectiveNielsPoint tminus = t.negate();
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
        ProjectiveNielsPoint[] points = new ProjectiveNielsPoint[8];
        points[0] = P.toProjectiveNiels();
        EdwardsPoint P2 = P.dbl();
        for (int i = 0; i < 7; i++) {
            points[i + 1] = P2.add(points[i]).toExtended().toProjectiveNiels();
        }
        return new ProjectiveNielsPoint.NafLookupTable(points);
    }

    static class NafLookupTable {
        private final ProjectiveNielsPoint[] table;

        NafLookupTable(ProjectiveNielsPoint[] table) {
            this.table = table;
        }

        /**
         * Given public, odd $x$ with $0 < x < 2^4$, return $[x]A$.
         *
         * @param x the index.
         * @return the pre-computed point.
         */
        ProjectiveNielsPoint select(final int x) {
            if ((x % 2 == 0) || x >= 16) {
                throw new IllegalArgumentException("invalid x");
            }

            return this.table[x / 2];
        }
    }
}
