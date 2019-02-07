package cafe.cryptography.curve25519;

/**
 * An element of the prime-order ristretto255 group.
 */
public class RistrettoElement {
    /**
     * The internal representation. Not canonical.
     */
    final EdwardsPoint repr;

    /**
     * Only for internal use.
     */
    RistrettoElement(EdwardsPoint repr) {
        this.repr = repr;
    }

    /**
     * Construct a ristretto255 element from a uniformly-distributed 64-byte string.
     *
     * @return the resulting element.
     */
    public static RistrettoElement fromUniformBytes(final byte[] b) {
        throw new UnsupportedOperationException();
    }

    /**
     * Compress this element using the Ristretto encoding.
     *
     * @return the encoded element.
     */
    public CompressedRistretto compress() {
        throw new UnsupportedOperationException();
    }

    /**
     * Constant-time equality check.
     *
     * @return 1 if this and other are equal, 0 otherwise.
     */
    public int ctEquals(final RistrettoElement other) {
        throw new UnsupportedOperationException();
    }

    /**
     * Constant-time selection between two RistrettoElements.
     *
     * @param that the other element.
     * @param b    must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of that if $b == 1$.
     */
    public RistrettoElement ctSelect(final RistrettoElement that, final int b) {
        return new RistrettoElement(this.repr.ctSelect(that.repr, b));
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
        if (!(obj instanceof RistrettoElement)) {
            return false;
        }

        RistrettoElement other = (RistrettoElement) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        // The general contract for the hashCode method states that equal objects must
        // have equal hash codes. Object equality is based on the encodings of the
        // elements, not their internal representations (are not canonical). Note that
        // equality is actually implemented using the ristretto255 EQUALS function, but
        // it is simpler to derive a hashCode from the element's encoding.
        return compress().hashCode();
    }

    /**
     * Group addition.
     *
     * @param Q the element to add to this one.
     * @return $P + Q$
     */
    public RistrettoElement add(final RistrettoElement Q) {
        return new RistrettoElement(this.repr.add(Q.repr));
    }

    /**
     * Group subtraction.
     *
     * @param Q the element to subtract from this one.
     * @return $P - Q$
     */
    public RistrettoElement subtract(final RistrettoElement Q) {
        return new RistrettoElement(this.repr.subtract(Q.repr));
    }

    /**
     * Element negation.
     *
     * @return $-P$
     */
    public RistrettoElement negate() {
        return new RistrettoElement(this.repr.negate());
    }

    /**
     * Element doubling.
     *
     * @return $[2]P$
     */
    public RistrettoElement dbl() {
        return new RistrettoElement(this.repr.dbl());
    }

    /**
     * Constant-time variable-base scalar multiplication.
     *
     * @param s the Scalar to multiply by.
     * @return $[s]P$
     */
    public RistrettoElement multiply(final Scalar s) {
        return new RistrettoElement(this.repr.multiply(s));
    }

    /**
     * For debugging.
     */
    String printInternalRepresentation() {
        return "RistrettoElement(" + this.repr.printInternalRepresentation() + ")";
    }
}
