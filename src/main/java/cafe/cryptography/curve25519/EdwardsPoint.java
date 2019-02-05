package cafe.cryptography.curve25519;

/**
 * An EdwardsPoint represents a point on the Edwards form of Curve25519.
 */
public class EdwardsPoint {
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
        throw new UnsupportedOperationException();
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
     * Point addition.
     *
     * @param Q the point to add to this one.
     * @return $P + Q$
     */
    public EdwardsPoint add(EdwardsPoint Q) {
        throw new UnsupportedOperationException();
    }

    /**
     * Point subtraction.
     *
     * @param Q the point to subtract from this one.
     * @return $P - Q$
     */
    public EdwardsPoint subtract(EdwardsPoint Q) {
        throw new UnsupportedOperationException();
    }

    /**
     * Point negation.
     *
     * @return $-P$
     */
    public EdwardsPoint negate() {
        throw new UnsupportedOperationException();
    }

    /**
     * Point doubling.
     *
     * @return $[2]P$
     */
    public EdwardsPoint dbl() {
        throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
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
