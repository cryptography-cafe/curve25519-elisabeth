package cafe.cryptography.curve25519;

import java.util.Arrays;

import cafe.cryptography.subtle.ConstantTime;

/**
 * An integer $s < 2^{255}$ which represents an element of the field $\mathbb{Z}
 * / \ell$.
 */
public class Scalar {
    public static final Scalar ZERO = new Scalar(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    public static final Scalar ONE = new Scalar(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

    /**
     * The 32-byte little-endian encoding of an integer representing a scalar modulo
     * the group order.
     * <p>
     * Invariant: the highest bit must be zero ($s[31] \le 127$).
     */
    private final byte[] s;

    Scalar(byte[] s) {
        this.s = s;
    }

    /**
     * Construct a Scalar by reducing a 512-bit little-endian integer modulo the
     * group order $\ell$.
     */
    public static Scalar fromBytesModOrderWide(byte[] input) {
        throw new UnsupportedOperationException();
    }

    /**
     * Convert this Scalar to its underlying sequence of bytes.
     *
     * @return the 32-byte little-endian encoding of this Scalar.
     */
    public byte[] toByteArray() {
        return s;
    }

    /**
     * Constant-time equality check.
     * <p>
     * Compares the encodings of the two Scalars.
     *
     * @return 1 if self and other are equal, 0 otherwise.
     */
    public int ctEquals(Scalar other) {
        return ConstantTime.equal(s, other.s);
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
        if (!(obj instanceof Scalar)) {
            return false;
        }

        Scalar other = (Scalar) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(s);
    }

    /**
     * Compute $a * b + c \bmod \ell$.
     *
     * @param b the Scalar to multiply this by.
     * @param c the Scalar to add to the product.
     * @return $a * b + c \bmod \ell$
     */
    public Scalar multiplyAndAdd(Scalar b, Scalar c) {
        throw new UnsupportedOperationException();
    }

    /**
     * Writes this Scalar in radix 16, with coefficients in range $[-8, 8)$.
     *
     * @return 64 bytes, each between -8 and 7
     */
    byte[] toRadix16() {
        throw new UnsupportedOperationException();
    }
}
