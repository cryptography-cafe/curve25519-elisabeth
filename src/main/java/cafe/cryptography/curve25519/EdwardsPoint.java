package cafe.cryptography.curve25519;

/**
 * An EdwardsPoint represents a point on the Edwards form of Curve25519.
 */
public class EdwardsPoint {
    public static final EdwardsPoint IDENTITY = new EdwardsPoint(FieldElement.ZERO, FieldElement.ONE, FieldElement.ONE,
            FieldElement.ZERO);

    final FieldElement X;
    final FieldElement Y;
    final FieldElement Z;
    final FieldElement T;

    /**
     * Only for internal use.
     */
    EdwardsPoint(FieldElement X, FieldElement Y, FieldElement Z, FieldElement T) {
        this.X = X;
        this.Y = Y;
        this.Z = Z;
        this.T = T;
    }

    /**
     * Compress this point to CompressedEdwardsY format.
     *
     * @return the encoded point.
     */
    public CompressedEdwardsY compress() {
        FieldElement recip = this.Z.invert();
        FieldElement x = this.X.multiply(recip);
        FieldElement y = this.Y.multiply(recip);
        byte[] s = y.toByteArray();
        s[31] |= (x.isNegative() << 7);
        return new CompressedEdwardsY(s);
    }

    /**
     * Constant-time equality check.
     * <p>
     * Compares the encodings of the two EdwardsPoints.
     *
     * @return 1 if this and other are equal, 0 otherwise.
     */
    public int ctEquals(EdwardsPoint other) {
        return compress().ctEquals(other.compress());
    }

    /**
     * Constant-time selection between two EdwardsPoints.
     *
     * @param that the other point.
     * @param b    must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of that if $b == 1$.
     */
    public EdwardsPoint ctSelect(EdwardsPoint that, int b) {
        throw new UnsupportedOperationException();
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
        if (!(obj instanceof EdwardsPoint)) {
            return false;
        }

        EdwardsPoint other = (EdwardsPoint) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        // The general contract for the hashCode method states that equal objects must
        // have equal hash codes. Object equality is based on the encodings of the
        // points, not their internal representations (which may not be canonical).
        return compress().hashCode();
    }

    /**
     * Convert the representation of this point from extended coordinates to
     * projective coordinates.
     * <p>
     * Free.
     */
    ProjectivePoint toProjective() {
        return new ProjectivePoint(this.X, this.Y, this.Z);
    }

    /**
     * Convert to a ProjectiveNielsPoint.
     */
    ProjectiveNielsPoint toProjectiveNiels() {
        return new ProjectiveNielsPoint(this.Y.add(this.X), this.Y.subtract(this.X), this.Z,
                this.T.multiply(Constants.EDWARDS_2D));
    }

    /**
     * Dehomogenize to an AffineNielsPoint.
     */
    AffineNielsPoint toAffineNiels() {
        FieldElement recip = this.Z.invert();
        FieldElement x = this.X.multiply(recip);
        FieldElement y = this.Y.multiply(recip);
        FieldElement xy2D = x.multiply(y).multiply(Constants.EDWARDS_2D);
        return new AffineNielsPoint(y.add(x), y.subtract(x), xy2D);
    }

    /**
     * Point addition.
     *
     * @param Q the point to add to this one.
     * @return $P + Q$
     */
    public EdwardsPoint add(EdwardsPoint Q) {
        return this.add(Q.toProjectiveNiels()).toExtended();
    }

    /**
     * Point addition.
     *
     * @param Q the point to add to this one, in projective "Niels coordinates".
     * @return $P + Q$
     */
    CompletedPoint add(ProjectiveNielsPoint Q) {
        FieldElement YPlusX = this.Y.add(this.X);
        FieldElement YMinusX = this.Y.subtract(this.X);
        FieldElement PP = YPlusX.multiply(Q.YPlusX);
        FieldElement MM = YMinusX.multiply(Q.YMinusX);
        FieldElement TT2D = this.T.multiply(Q.T2D);
        FieldElement ZZ = this.Z.multiply(Q.Z);
        FieldElement ZZ2 = ZZ.add(ZZ);
        return new CompletedPoint(PP.subtract(MM), PP.add(MM), ZZ2.add(TT2D), ZZ2.subtract(TT2D));
    }

    /**
     * Point addition.
     *
     * @param Q the point to add to this one, in affine "Niels coordinates".
     * @return $P + Q$
     */
    CompletedPoint add(AffineNielsPoint q) {
        FieldElement YPlusX = this.Y.add(this.X);
        FieldElement YMinusX = this.Y.subtract(this.X);
        FieldElement PP = YPlusX.multiply(q.yPlusx);
        FieldElement MM = YMinusX.multiply(q.yMinusx);
        FieldElement Txy2D = this.T.multiply(q.xy2D);
        FieldElement Z2 = this.Z.add(this.Z);
        return new CompletedPoint(PP.subtract(MM), PP.add(MM), Z2.add(Txy2D), Z2.subtract(Txy2D));
    }

    /**
     * Point subtraction.
     *
     * @param Q the point to subtract from this one.
     * @return $P - Q$
     */
    public EdwardsPoint subtract(EdwardsPoint Q) {
        return this.subtract(Q.toProjectiveNiels()).toExtended();
    }

    /**
     * Point subtraction.
     *
     * @param Q the point to subtract from this one, in projective "Niels
     *          coordinates".
     * @return $P - Q$
     */
    CompletedPoint subtract(ProjectiveNielsPoint Q) {
        FieldElement YPlusX = this.Y.add(this.X);
        FieldElement YMinusX = this.Y.subtract(this.X);
        FieldElement PM = YPlusX.multiply(Q.YMinusX);
        FieldElement MP = YMinusX.multiply(Q.YPlusX);
        FieldElement TT2D = this.T.multiply(Q.T2D);
        FieldElement ZZ = Z.multiply(Q.Z);
        FieldElement ZZ2 = ZZ.add(ZZ);
        return new CompletedPoint(PM.subtract(MP), PM.add(MP), ZZ2.subtract(TT2D), ZZ2.add(TT2D));
    }

    /**
     * Point subtraction.
     *
     * @param Q the point to subtract from this one, in affine "Niels coordinates".
     * @return $P - Q$
     */
    CompletedPoint subtract(AffineNielsPoint q) {
        FieldElement YPlusX = this.Y.add(this.X);
        FieldElement YMinusX = this.Y.subtract(this.X);
        FieldElement PM = YPlusX.multiply(q.yMinusx);
        FieldElement MP = YMinusX.multiply(q.yPlusx);
        FieldElement Txy2D = this.T.multiply(q.xy2D);
        FieldElement Z2 = this.Z.add(this.Z);
        return new CompletedPoint(PM.subtract(MP), PM.add(MP), Z2.subtract(Txy2D), Z2.add(Txy2D));
    }

    /**
     * Point negation.
     *
     * @return $-P$
     */
    public EdwardsPoint negate() {
        return new EdwardsPoint(this.X.negate(), this.Y, this.Z, this.T.negate());
    }

    /**
     * Point doubling.
     *
     * @return $[2]P$
     */
    public EdwardsPoint dbl() {
        return this.toProjective().dbl().toExtended();
    }

    /**
     * Constant-time variable-base scalar multiplication.
     *
     * @param s the Scalar to multiply by.
     * @return $[s]P$
     */
    public EdwardsPoint multiply(final Scalar s) {
        throw new UnsupportedOperationException();
    }

    /**
     * Compute $r = [a]A + [b]B$ in variable time, where $B$ is the Ed25519
     * basepoint.
     *
     * @param a a Scalar.
     * @param A an EdwardsPoint.
     * @param b a Scalar.
     * @return $[a]A + [b]B$
     */
    public static EdwardsPoint vartimeDoubleScalarMultiplyBasepoint(final Scalar a, final EdwardsPoint A,
            final Scalar b) {
        throw new UnsupportedOperationException();
    }

    /**
     * Multiply by the cofactor.
     *
     * @return $[8]P$
     */
    public EdwardsPoint multiplyByCofactor() {
        return this.multiplyByPow2(3);
    }

    /**
     * Compute $[2^k]P$ by successive doublings.
     *
     * @param k the exponent of 2. Must be positive and non-zero.
     * @return $[2^k]P$
     */
    EdwardsPoint multiplyByPow2(int k) {
        if (!(k > 0)) {
            throw new IllegalArgumentException("Exponent must be positive and non-zero");
        }
        ProjectivePoint s = this.toProjective();
        for (int i = 0; i < k - 1; i++) {
            s = s.dbl().toProjective();
        }
        // Unroll last doubling so we can go directly to extended coordinates.
        return s.dbl().toExtended();
    }

    /**
     * Determine if this point is in the 8-torsion subgroup $(\mathcal E[8])$, and
     * therefore of small order.
     *
     * @return true if this point is of small order, false otherwise.
     */
    public boolean isSmallOrder() {
        throw new UnsupportedOperationException();
    }

    /**
     * Determine if this point is contained in the prime-order subgroup $(\mathcal
     * E[\ell])$, and has no torsion component.
     *
     * @return true if this point has zero torsion component and is in the
     *         prime-order subgroup, false otherwise.
     */
    public boolean isTorsionFree() {
        throw new UnsupportedOperationException();
    }
}
