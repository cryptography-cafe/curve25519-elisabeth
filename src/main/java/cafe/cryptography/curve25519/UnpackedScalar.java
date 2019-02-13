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

    static final int MASK_29_BITS = (1 << 29) - 1;
    static final int MASK_24_BITS = (1 << 24) - 1;

    /**
     * Unpack a 32 byte / 256 bit scalar into 9 29-bit limbs.
     */
    static UnpackedScalar fromByteArray(final byte[] input) {
        if (input.length != 32) {
            throw new IllegalArgumentException("Input must by 32 bytes");
        }

        int[] words = new int[8];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 4; j++) {
                words[i] |= ((input[(i * 4) + j]) & 0xff) << (j * 8);
            }
        }

        int[] s = new int[9];

        s[0] = (words[0] & MASK_29_BITS);
        s[1] = (((words[0] >>> 29) | (words[1] << 3)) & MASK_29_BITS);
        s[2] = (((words[1] >>> 26) | (words[2] << 6)) & MASK_29_BITS);
        s[3] = (((words[2] >>> 23) | (words[3] << 9)) & MASK_29_BITS);
        s[4] = (((words[3] >>> 20) | (words[4] << 12)) & MASK_29_BITS);
        s[5] = (((words[4] >>> 17) | (words[5] << 15)) & MASK_29_BITS);
        s[6] = (((words[5] >>> 14) | (words[6] << 18)) & MASK_29_BITS);
        s[7] = (((words[6] >>> 11) | (words[7] << 21)) & MASK_29_BITS);
        s[8] = ((words[7] >>> 8) & MASK_24_BITS);

        return new UnpackedScalar(s);
    }

    /**
     * Pack the limbs of this UnpackedScalar into 32 bytes.
     */
    byte[] toByteArray() {
        byte[] result = new byte[32];

        // All limbs are 29 bits, but let's use the unsigned right shift anyway.
        result[0] = (byte) (this.s[0] >>> 0);
        result[1] = (byte) (this.s[0] >>> 8);
        result[2] = (byte) (this.s[0] >>> 16);
        result[3] = (byte) ((this.s[0] >>> 24) | (this.s[1] << 5));
        result[4] = (byte) (this.s[1] >>> 3);
        result[5] = (byte) (this.s[1] >>> 11);
        result[6] = (byte) (this.s[1] >>> 19);
        result[7] = (byte) ((this.s[1] >>> 27) | (this.s[2] << 2));
        result[8] = (byte) (this.s[2] >>> 6);
        result[9] = (byte) (this.s[2] >>> 14);
        result[10] = (byte) ((this.s[2] >>> 22) | (this.s[3] << 7));
        result[11] = (byte) (this.s[3] >>> 1);
        result[12] = (byte) (this.s[3] >>> 9);
        result[13] = (byte) (this.s[3] >>> 17);
        result[14] = (byte) ((this.s[3] >>> 25) | (this.s[4] << 4));
        result[15] = (byte) (this.s[4] >>> 4);
        result[16] = (byte) (this.s[4] >>> 12);
        result[17] = (byte) (this.s[4] >>> 20);
        result[18] = (byte) ((this.s[4] >>> 28) | (this.s[5] << 1));
        result[19] = (byte) (this.s[5] >>> 7);
        result[20] = (byte) (this.s[5] >>> 15);
        result[21] = (byte) ((this.s[5] >>> 23) | (this.s[6] << 6));
        result[22] = (byte) (this.s[6] >>> 2);
        result[23] = (byte) (this.s[6] >>> 10);
        result[24] = (byte) (this.s[6] >>> 18);
        result[25] = (byte) ((this.s[6] >>> 26) | (this.s[7] << 3));
        result[26] = (byte) (this.s[7] >>> 5);
        result[27] = (byte) (this.s[7] >>> 13);
        result[28] = (byte) (this.s[7] >>> 21);
        result[29] = (byte) (this.s[8] >>> 0);
        result[30] = (byte) (this.s[8] >>> 8);
        result[31] = (byte) (this.s[8] >>> 16);

        return result;
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
