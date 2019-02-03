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

    static int load_3(byte[] in, int offset) {
        int result = in[offset++] & 0xff;
        result |= (in[offset++] & 0xff) << 8;
        result |= (in[offset] & 0xff) << 16;
        return result;
    }

    static long load_4(byte[] in, int offset) {
        int result = in[offset++] & 0xff;
        result |= (in[offset++] & 0xff) << 8;
        result |= (in[offset++] & 0xff) << 16;
        result |= in[offset] << 24;
        return ((long) result) & 0xffffffffL;
    }

    /**
     * Load a FieldElement from the low 255 bits of a 256-bit input.
     *
     * @param in The 32-byte representation.
     * @return The field element in its $2^{25.5}$ bit representation.
     */
    public static FieldElement fromByteArray(byte[] in) {
        long h0 = load_4(in, 0);
        long h1 = load_3(in, 4) << 6;
        long h2 = load_3(in, 7) << 5;
        long h3 = load_3(in, 10) << 3;
        long h4 = load_3(in, 13) << 2;
        long h5 = load_4(in, 16);
        long h6 = load_3(in, 20) << 7;
        long h7 = load_3(in, 23) << 5;
        long h8 = load_3(in, 26) << 4;
        long h9 = (load_3(in, 29) & 0x7FFFFF) << 2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        // Remember: 2^255 congruent 19 modulo p
        // @formatter:off
        carry9 = (h9 + (long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
        carry1 = (h1 + (long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry3 = (h3 + (long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry5 = (h5 + (long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
        carry7 = (h7 + (long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry2 = (h2 + (long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry6 = (h6 + (long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
        carry8 = (h8 + (long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
        // @formatter:on

        int[] h = new int[10];
        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        return new FieldElement(h);
    }

    /**
     * Encode a FieldElement in its 32-byte representation.
     * <p>
     * This is done in two steps:
     * <ol>
     * <li>Reduce the value of the field element modulo $p$.
     * <li>Convert the field element to the 32 byte representation.
     * <p>
     * The idea for the modulo $p$ reduction algorithm is as follows:
     * <h2>Assumption:</h2>
     * <ul>
     * <li>$p = 2^{255} - 19$
     * <li>$h = h_0 + 2^{25} * h_1 + 2^{(26+25)} * h_2 + \dots + 2^{230} * h_9$
     * where $0 \le |h_i| \lt 2^{27}$ for all $i=0,\dots,9$.
     * <li>$h \cong r \mod p$, i.e. $h = r + q * p$ for some suitable $0 \le r \lt
     * p$ and an integer $q$.
     * <p>
     * Then $q = [2^{-255} * (h + 19 * 2^{-25} * h_9 + 1/2)]$ where $[x] =
     * floor(x)$.
     * <h2>Proof:</h2>
     * <p>
     * We begin with some very raw estimation for the bounds of some expressions:
     * <p>
     * $$ \begin{equation} |h| \lt 2^{230} * 2^{30} = 2^{260} \Rightarrow |r + q *
     * p| \lt 2^{260} \Rightarrow |q| \lt 2^{10}. \\ \Rightarrow -1/4 \le a := 19^2
     * * 2^{-255} * q \lt 1/4. \\ |h - 2^{230} * h_9| = |h_0 + \dots + 2^{204} *
     * h_8| \lt 2^{204} * 2^{30} = 2^{234}. \\ \Rightarrow -1/4 \le b := 19 *
     * 2^{-255} * (h - 2^{230} * h_9) \lt 1/4 \end{equation} $$
     * <p>
     * Therefore $0 \lt 1/2 - a - b \lt 1$.
     * <p>
     * Set $x := r + 19 * 2^{-255} * r + 1/2 - a - b$. Then:
     * <p>
     * $$ 0 \le x \lt 255 - 20 + 19 + 1 = 2^{255} \\ \Rightarrow 0 \le 2^{-255} * x
     * \lt 1. $$
     * <p>
     * Since $q$ is an integer we have
     * <p>
     * $$ [q + 2^{-255} * x] = q \quad (1) $$
     * <p>
     * Have a closer look at $x$:
     * <p>
     * $$ \begin{align} x &amp;= h - q * (2^{255} - 19) + 19 * 2^{-255} * (h - q *
     * (2^{255} - 19)) + 1/2 - 19^2 * 2^{-255} * q - 19 * 2^{-255} * (h - 2^{230} *
     * h_9) \\ &amp;= h - q * 2^{255} + 19 * q + 19 * 2^{-255} * h - 19 * q + 19^2 *
     * 2^{-255} * q + 1/2 - 19^2 * 2^{-255} * q - 19 * 2^{-255} * h + 19 * 2^{-25} *
     * h_9 \\ &amp;= h + 19 * 2^{-25} * h_9 + 1/2 - q^{255}. \end{align} $$
     * <p>
     * Inserting the expression for $x$ into $(1)$ we get the desired expression for
     * $q$.
     *
     * @return the 32-byte encoding of this FieldElement.
     */
    byte[] toByteArray() {
        int h0 = t[0];
        int h1 = t[1];
        int h2 = t[2];
        int h3 = t[3];
        int h4 = t[4];
        int h5 = t[5];
        int h6 = t[6];
        int h7 = t[7];
        int h8 = t[8];
        int h9 = t[9];
        int q;
        int carry0;
        int carry1;
        int carry2;
        int carry3;
        int carry4;
        int carry5;
        int carry6;
        int carry7;
        int carry8;
        int carry9;

        // Step 1:
        // Calculate q
        q = (19 * h9 + (1 << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        // r = h - q * p = h - 2^255 * q + 19 * q
        // First add 19 * q then discard the bit 255
        h0 += 19 * q;

        // @formatter:off
        carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
        carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
        carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
        carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
        carry9 = h9 >> 25;               h9 -= carry9 << 25;
        // @formatter:on

        // Step 2 (straight forward conversion):
        byte[] s = new byte[32];
        s[0] = (byte) h0;
        s[1] = (byte) (h0 >> 8);
        s[2] = (byte) (h0 >> 16);
        s[3] = (byte) ((h0 >> 24) | (h1 << 2));
        s[4] = (byte) (h1 >> 6);
        s[5] = (byte) (h1 >> 14);
        s[6] = (byte) ((h1 >> 22) | (h2 << 3));
        s[7] = (byte) (h2 >> 5);
        s[8] = (byte) (h2 >> 13);
        s[9] = (byte) ((h2 >> 21) | (h3 << 5));
        s[10] = (byte) (h3 >> 3);
        s[11] = (byte) (h3 >> 11);
        s[12] = (byte) ((h3 >> 19) | (h4 << 6));
        s[13] = (byte) (h4 >> 2);
        s[14] = (byte) (h4 >> 10);
        s[15] = (byte) (h4 >> 18);
        s[16] = (byte) h5;
        s[17] = (byte) (h5 >> 8);
        s[18] = (byte) (h5 >> 16);
        s[19] = (byte) ((h5 >> 24) | (h6 << 1));
        s[20] = (byte) (h6 >> 7);
        s[21] = (byte) (h6 >> 15);
        s[22] = (byte) ((h6 >> 23) | (h7 << 3));
        s[23] = (byte) (h7 >> 5);
        s[24] = (byte) (h7 >> 13);
        s[25] = (byte) ((h7 >> 21) | (h8 << 4));
        s[26] = (byte) (h8 >> 4);
        s[27] = (byte) (h8 >> 12);
        s[28] = (byte) ((h8 >> 20) | (h9 << 6));
        s[29] = (byte) (h9 >> 2);
        s[30] = (byte) (h9 >> 10);
        s[31] = (byte) (h9 >> 18);
        return s;
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
     * <p>
     * Implemented as a conditional copy. Logic is inspired by the SUPERCOP
     * implementation.
     *
     * @param that the other field element.
     * @param b    must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of val if $b == 1$.
     * @see <a href=
     *      "https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref10/fe_cmov.c"
     *      target="_top">SUPERCOP</a>
     */
    public FieldElement ctSelect(FieldElement that, int b) {
        b = -b;
        int[] result = new int[10];
        for (int i = 0; i < 10; i++) {
            result[i] = this.t[i];
            int x = this.t[i] ^ that.t[i];
            x &= b;
            result[i] ^= x;
        }
        return new FieldElement(result);
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
