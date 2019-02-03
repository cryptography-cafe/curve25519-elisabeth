package cafe.cryptography.subtle;

/**
 * Constant-time functions.
 */
public final class ConstantTime {
    /**
     * Constant-time byte comparison.
     *
     * @param b a byte, represented as an int
     * @param c a byte, represented as an int
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(int b, int c) {
        int result = 0;
        int xor = b ^ c;
        for (int i = 0; i < 8; i++) {
            result |= xor >> i;
        }
        return (result ^ 0x01) & 0x01;
    }

    /**
     * Constant-time byte[] comparison.
     * <p>
     * Fails fast if the lengths differ.
     *
     * @param b a byte[]
     * @param c a byte[]
     * @return 1 if b and c are equal, 0 otherwise.
     */
    public static int equal(byte[] b, byte[] c) {
        // Fail-fast if the lengths differ
        if (b.length != c.length) {
            return 0;
        }

        // Now use a constant-time comparison
        int result = 0;
        for (int i = 0; i < b.length; i++) {
            result |= b[i] ^ c[i];
        }

        return equal(result, 0);
    }

    /**
     * Constant-time determine if byte is negative.
     *
     * @param b the byte to check, represented as an int.
     * @return 1 if the byte is negative, 0 otherwise.
     */
    public static int isNegative(int b) {
        return (b >> 8) & 1;
    }

    /**
     * Get the i'th bit of a byte array.
     *
     * @param h the byte array.
     * @param i the bit index.
     * @return 0 or 1, the value of the i'th bit in h
     */
    public static int bit(byte[] h, int i) {
        return (h[i >> 3] >> (i & 7)) & 1;
    }
}
