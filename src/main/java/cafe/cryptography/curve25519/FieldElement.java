package cafe.cryptography.curve25519;

import java.util.Arrays;

import cafe.cryptography.subtle.ConstantTime;

/**
 * A field element of the field $\mathbb{Z} / (2^{255} - 19)$.
 */
class FieldElement {
    public static final FieldElement ZERO = new FieldElement(new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    public static final FieldElement ONE = new FieldElement(new int[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

    /**
     * An element $t$, entries $t[0] \dots t[9]$, represents the integer $t[0] +
     * 2^{26} t[1] + 2^{51} t[2] + 2^{77} t[3] + 2^{102} t[4] + \dots + 2^{230}
     * t[9]$. Bounds on each $t[i]$ vary depending on context.
     */
    private final int[] t;

    /**
     * Create a field element.
     *
     * @param t The $2^{25.5}$ bit representation of the field element.
     */
    public FieldElement(int[] t) {
        if (t.length != 10)
            throw new IllegalArgumentException("Invalid radix-2^25.5 representation");
        this.t = t;
    }

    /**
     * Load a FieldElement from the low 255 bits of a 256-bit input.
     *
     * @param in The 32-byte representation.
     * @return The field element in its $2^{25.5}$ bit representation.
     */
    public static FieldElement fromByteArray(byte[] in) {
        throw new UnsupportedOperationException();
    }

    /**
     * Encode a FieldElement in its 32-byte representation.
     *
     * @return the 32-byte encoding of this FieldElement.
     */
    byte[] toByteArray() {
        throw new UnsupportedOperationException();
    }

    /**
     * Constant-time equality check.
     * <p>
     * Compares the encodings of the two FieldElements.
     *
     * @return 1 if self and other are equal, 0 otherwise.
     */
    public int ctEquals(FieldElement other) {
        return ConstantTime.equal(toByteArray(), other.toByteArray());
    }

    /**
     * Constant-time selection between two FieldElements.
     *
     * @param that the other field element.
     * @param b    must be 0 or 1, otherwise results are undefined.
     * @return this if $b == 0$, or val if $b == 1$.
     */
    public FieldElement ctSelect(FieldElement that, int b) {
        throw new UnsupportedOperationException();
    }

    /**
     * Equality check overridden to be constant-time.
     * <p>
     * Fails fast if the objects are of different types.
     *
     * @return true if self and other are equal, false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FieldElement)) {
            return false;
        }

        FieldElement other = (FieldElement) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        // The general contract for the hashCode method states that equal objects must
        // have equal hash codes. Object equality is based on the encodings of the
        // field elements, not their internal representations (which may not be
        // canonical).
        final byte[] s = toByteArray();
        return Arrays.hashCode(s);
    }

    private static final byte[] ZERO_BYTES = new byte[32];

    /**
     * Determine whether this FieldElement is zero.
     *
     * @return 1 if this FieldElement is zero, 0 otherwise.
     */
    int isZero() {
        final byte[] s = toByteArray();
        return ConstantTime.equal(s, ZERO_BYTES);
    }

    /**
     * Determine whether this FieldElement is negative.
     * <p>
     * As in RFC 8032, a FieldElement is negative if the least significant bit of
     * the encoding is 1.
     *
     * @return 1 if this FieldElement is negative, 0 otherwise.
     * @see <a href="https://tools.ietf.org/html/rfc8032" target="_top">RFC 8032</a>
     */
    int isNegative() {
        final byte[] s = toByteArray();
        return s[0] & 1;
    }

    /**
     * $h = f + g$
     *
     * @param val The field element to add.
     * @return The field element this + val.
     */
    public FieldElement add(FieldElement val) {
        throw new UnsupportedOperationException();
    }

    /**
     * $h = f - g$
     *
     * @param val The field element to subtract.
     * @return The field element this - val.
     **/
    public FieldElement subtract(FieldElement val) {
        throw new UnsupportedOperationException();
    }

    /**
     * $h = -f$
     *
     * @return The field element (-1) * this.
     */
    public FieldElement negate() {
        throw new UnsupportedOperationException();
    }

    /**
     * $h = f * g$
     *
     * @param val The field element to multiply.
     * @return The (reasonably reduced) field element this * val.
     */
    public FieldElement multiply(FieldElement val) {
        throw new UnsupportedOperationException();
    }

    /**
     * $h = f * f$
     *
     * @return The (reasonably reduced) square of this field element.
     */
    public FieldElement square() {
        throw new UnsupportedOperationException();
    }

    /**
     * $h = 2 * f * f$
     *
     * @return The (reasonably reduced) square of this field element times 2.
     */
    public FieldElement squareAndDouble() {
        throw new UnsupportedOperationException();
    }

    /**
     * Invert this field element.
     *
     * @return The inverse of this field element.
     */
    public FieldElement invert() {
        throw new UnsupportedOperationException();
    }
}
