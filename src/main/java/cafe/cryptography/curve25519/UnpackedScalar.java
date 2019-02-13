package cafe.cryptography.curve25519;

/**
 * Represents an element in ℤ/lℤ as 9 29-bit limbs.
 */
class UnpackedScalar {
    static final UnpackedScalar ZERO = new UnpackedScalar(new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0 });

    final int[] s;

    UnpackedScalar(final int[] s) {
        if (s.length != 9) {
            throw new IllegalArgumentException("Invalid radix-2^29 representation");
        }
        this.s = s;
    }

    /**
     * Compute $a + b \bmod \ell$.
     *
     * @param b the Scalar to add to this.
     * @return $a + b \bmod \ell$
     */
    UnpackedScalar add(final UnpackedScalar b) {
        throw new UnsupportedOperationException();
    }

    /**
     * Compute $a - b \bmod \ell$.
     *
     * @param b the Scalar to subtract from this.
     * @return $a - b \bmod \ell$
     */
    UnpackedScalar subtract(final UnpackedScalar b) {
        throw new UnsupportedOperationException();
    }

    /**
     * Compute $a * b \bmod \ell$.
     *
     * @param b the Scalar to multiply with this.
     * @return $a * b \bmod \ell$
     */
    UnpackedScalar multiply(final UnpackedScalar b) {
        throw new UnsupportedOperationException();
    }
}
