package cafe.cryptography.curve25519;

import java.util.Arrays;

import cafe.cryptography.subtle.ConstantTime;

/**
 * A field element of the field $\mathbb{Z} / (2^{255} - 19)$.
 */
class FieldElement {
    public static final FieldElement ZERO = new FieldElement(new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    public static final FieldElement ONE = new FieldElement(new int[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    public static final FieldElement MINUS_ONE = ZERO.subtract(ONE);

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
     * Given unreduced coefficients $h0, ..., h9$ of any size, carry and reduce them
     * mod p to obtain a FieldElement whose coefficients have excess $b < 0.007$.
     *
     * @return the reasonably-reduced FieldElement.
     */
    static FieldElement reduce(long h0, long h1, long h2, long h3, long h4, long h5, long h6, long h7, long h8,
            long h9) {
        // Carry holder
        long c;

        // Carry the value from limbs h_i to h_{i+1}, for i = [0, 8].
        // Perform two halves of the carry chain in parallel.
        // @formatter:off
        c = (h0 + (long) (1<<25)) >> 26; h1 += c; h0 -= c << 26; c = (h4 + (long) (1<<25)) >> 26; h5 += c; h4 -= c << 26;
        c = (h1 + (long) (1<<24)) >> 25; h2 += c; h1 -= c << 25; c = (h5 + (long) (1<<24)) >> 25; h6 += c; h5 -= c << 25;
        c = (h2 + (long) (1<<25)) >> 26; h3 += c; h2 -= c << 26; c = (h6 + (long) (1<<25)) >> 26; h7 += c; h6 -= c << 26;
        c = (h3 + (long) (1<<24)) >> 25; h4 += c; h3 -= c << 25; c = (h7 + (long) (1<<24)) >> 25; h8 += c; h7 -= c << 25;

        // Since h3 < 2^64 originally, c < 2^(64 - 25) = 2^39
        // Thus h4 + c < 2^26 + 2^39 < 2^39.0002, and we need to reduce it again
        c = (h4 + (long) (1<<25)) >> 26; h5 += c; h4 -= c << 26; c = (h8 + (long) (1<<25)) >> 26; h9 += c; h8 -= c << 26;
        // Now h4 < 2^26, and c < 2^(39.0002 - 26) = 2^13.0002
        // Thus h5 + c < 2^25 + 2^13.0002 < 2^25.0004 which is within our desired bounds
        // @formatter:on

        // Last carry has a multiplication by 19:
        c = (h9 + (long) (1 << 24)) >> 25;
        h0 += c * 19;
        h9 -= c << 25;

        // Since h9 < 2^64 originally, c < 2^(64 - 25) = 2^39
        // Thus h0 + 19*c < 2^26 + 2^43.248 < 2^43.249, and we need to reduce it again
        c = (h0 + (long) (1 << 25)) >> 26;
        h1 += c;
        h0 -= c << 26;
        // Now h0 < 2^26, and c < 2^(43.249 - 26) = 2^17.249
        // Thus h1 + c < 2^25 + 2^17.249 < 2^25.007 which is within our desired bounds

        // Convert to an int[], which is now lossless.
        return new FieldElement(new int[] { (int) h0, (int) h1, (int) h2, (int) h3, (int) h4, (int) h5, (int) h6,
                (int) h7, (int) h8, (int) h9 });
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

        return FieldElement.reduce(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
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
     * <p>
     * Preconditions:
     * <ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <li>$|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <p>
     * Postconditions:
     * <ul>
     * <li>$|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     *
     * @param val The field element to add.
     * @return The field element this + val.
     */
    public FieldElement add(FieldElement val) {
        int[] g = val.t;
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = t[i] + g[i];
        }
        return new FieldElement(h);
    }

    /**
     * $h = f - g$
     * <p>
     * Can overlap $h$ with $f$ or $g$.
     * <p>
     * Preconditions:
     * <ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <li>$|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <p>
     * Postconditions:
     * <ul>
     * <li>$|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     *
     * @param val The field element to subtract.
     * @return The field element this - val.
     **/
    public FieldElement subtract(FieldElement val) {
        int[] g = val.t;
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = t[i] - g[i];
        }
        return new FieldElement(h);
    }

    /**
     * $h = -f$
     * <p>
     * Preconditions:
     * <ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <p>
     * Postconditions:
     * <ul>
     * <li>$|h|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     *
     * @return The field element (-1) * this.
     */
    public FieldElement negate() {
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = -t[i];
        }
        return new FieldElement(h);
    }

    /**
     * i32 * i32 -> i64
     */
    private static long m(final int x, final int y) {
        return ((long) x) * ((long) y);
    }

    /**
     * $h = f * g$
     * <p>
     * Can overlap $h$ with $f$ or $g$.
     * <p>
     * Preconditions:
     * <ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * <li>$|g|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * <p>
     * Postconditions:
     * <ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * <p>
     * Notes on implementation strategy:
     * <p>
     * Using schoolbook multiplication. Karatsuba would save a little in some cost
     * models.
     * <p>
     * Most multiplications by 2 and 19 are 32-bit precomputations; cheaper than
     * 64-bit postcomputations.
     * <p>
     * There is one remaining multiplication by 19 in the carry chain; one *19
     * precomputation can be merged into this, but the resulting data flow is
     * considerably less clean.
     * <p>
     * There are 12 carries below. 10 of them are 2-way parallelizable and
     * vectorizable. Can get away with 11 carries, but then data flow is much
     * deeper.
     * <p>
     * With tighter constraints on inputs can squeeze carries into int32.
     *
     * @param val The field element to multiply.
     * @return The (reasonably reduced) field element this * val.
     */
    public FieldElement multiply(FieldElement val) {
        int[] f = this.t; // avoid getfield opcode
        int[] g = val.t;  // avoid getfield opcode

        int g1_19 = 19 * g[1]; /* 1.959375*2^29 */
        int g2_19 = 19 * g[2]; /* 1.959375*2^30; still ok */
        int g3_19 = 19 * g[3];
        int g4_19 = 19 * g[4];
        int g5_19 = 19 * g[5];
        int g6_19 = 19 * g[6];
        int g7_19 = 19 * g[7];
        int g8_19 = 19 * g[8];
        int g9_19 = 19 * g[9];

        int f1_2 = 2 * f[1];
        int f3_2 = 2 * f[3];
        int f5_2 = 2 * f[5];
        int f7_2 = 2 * f[7];
        int f9_2 = 2 * f[9];

        /**
         * Remember: 2^255 congruent 19 modulo p. h = h0 * 2^0 + h1 * 2^26 + h2 *
         * 2^(26+25) + h3 * 2^(26+25+26) + ... + h9 * 2^(5*26+5*25). So to get the real
         * number we would have to multiply the coefficients with the corresponding
         * powers of 2. To get an idea what is going on below, look at the calculation
         * of h0: h0 is the coefficient to the power 2^0 so it collects (sums) all
         * products that have the power 2^0. f0 * g0 really is f0 * 2^0 * g0 * 2^0 = (f0
         * * g0) * 2^0. f1 * g9 really is f1 * 2^26 * g9 * 2^230 = f1 * g9 * 2^256 = 2 *
         * f1 * g9 * 2^255 congruent 2 * 19 * f1 * g9 * 2^0 modulo p. f2 * g8 really is
         * f2 * 2^51 * g8 * 2^204 = f2 * g8 * 2^255 congruent 19 * f2 * g8 * 2^0 modulo
         * p. and so on...
         */
        // @formatter:off
        long h0 = m(f[0],g[0]) + m(f1_2,g9_19) + m(f[2],g8_19) + m(f3_2,g7_19) + m(f[4],g6_19) + m(f5_2,g5_19) + m(f[6],g4_19) + m(f7_2,g3_19) + m(f[8],g2_19) + m(f9_2,g1_19);
        long h1 = m(f[0],g[1]) + m(f[1],g[0])  + m(f[2],g9_19) + m(f[3],g8_19) + m(f[4],g7_19) + m(f[5],g6_19) + m(f[6],g5_19) + m(f[7],g4_19) + m(f[8],g3_19) + m(f[9],g2_19);
        long h2 = m(f[0],g[2]) + m(f1_2,g[1])  + m(f[2],g[0])  + m(f3_2,g9_19) + m(f[4],g8_19) + m(f5_2,g7_19) + m(f[6],g6_19) + m(f7_2,g5_19) + m(f[8],g4_19) + m(f9_2,g3_19);
        long h3 = m(f[0],g[3]) + m(f[1],g[2])  + m(f[2],g[1])  + m(f[3],g[0])  + m(f[4],g9_19) + m(f[5],g8_19) + m(f[6],g7_19) + m(f[7],g6_19) + m(f[8],g5_19) + m(f[9],g4_19);
        long h4 = m(f[0],g[4]) + m(f1_2,g[3])  + m(f[2],g[2])  + m(f3_2,g[1])  + m(f[4],g[0])  + m(f5_2,g9_19) + m(f[6],g8_19) + m(f7_2,g7_19) + m(f[8],g6_19) + m(f9_2,g5_19);
        long h5 = m(f[0],g[5]) + m(f[1],g[4])  + m(f[2],g[3])  + m(f[3],g[2])  + m(f[4],g[1])  + m(f[5],g[0])  + m(f[6],g9_19) + m(f[7],g8_19) + m(f[8],g7_19) + m(f[9],g6_19);
        long h6 = m(f[0],g[6]) + m(f1_2,g[5])  + m(f[2],g[4])  + m(f3_2,g[3])  + m(f[4],g[2])  + m(f5_2,g[1])  + m(f[6],g[0])  + m(f7_2,g9_19) + m(f[8],g8_19) + m(f9_2,g7_19);
        long h7 = m(f[0],g[7]) + m(f[1],g[6])  + m(f[2],g[5])  + m(f[3],g[4])  + m(f[4],g[3])  + m(f[5],g[2])  + m(f[6],g[1])  + m(f[7],g[0])  + m(f[8],g9_19) + m(f[9],g8_19);
        long h8 = m(f[0],g[8]) + m(f1_2,g[7])  + m(f[2],g[6])  + m(f3_2,g[5])  + m(f[4],g[4])  + m(f5_2,g[3])  + m(f[6],g[2])  + m(f7_2,g[1])  + m(f[8],g[0])  + m(f9_2,g9_19);
        long h9 = m(f[0],g[9]) + m(f[1],g[8])  + m(f[2],g[7])  + m(f[3],g[6])  + m(f[4],g[5])  + m(f[5],g[4])  + m(f[6],g[3])  + m(f[7],g[2])  + m(f[8],g[1])  + m(f[9],g[0]);
        // @formatter:on

        return FieldElement.reduce(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    /**
     * $h = f * f$
     * <p>
     * Can overlap $h$ with $f$.
     * <p>
     * Preconditions:
     * <ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * <p>
     * Postconditions:
     * <ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * <p>
     * See {@link #multiply(FieldElement)} for discussion of implementation
     * strategy.
     *
     * @return The (reasonably reduced) square of this field element.
     */
    public FieldElement square() {
        int[] f = this.t; // avoid getfield opcode

        int f0_2 = 2 * f[0];
        int f1_2 = 2 * f[1];
        int f2_2 = 2 * f[2];
        int f3_2 = 2 * f[3];
        int f4_2 = 2 * f[4];
        int f5_2 = 2 * f[5];
        int f6_2 = 2 * f[6];
        int f7_2 = 2 * f[7];

        int f5_38 = 38 * f[5]; /* 1.959375*2^30 */
        int f6_19 = 19 * f[6]; /* 1.959375*2^30 */
        int f7_38 = 38 * f[7]; /* 1.959375*2^30 */
        int f8_19 = 19 * f[8]; /* 1.959375*2^30 */
        int f9_38 = 38 * f[9]; /* 1.959375*2^30 */

        /**
         * Same procedure as in multiply, but this time we have a higher symmetry
         * leading to less summands. e.g. m(f1_2,f9_38) really stands for f1 * 2^26 * f9 *
         * 2^230 + f9 * 2^230 + f1 * 2^26 congruent 2 * 2 * 19 * f1 * f9 2^0 modulo p.
         */
        // @formatter:off
        long h0 = m(f[0],f[0]) + m(f1_2,f9_38) + m(f2_2,f8_19) + m(f3_2,f7_38) + m(f4_2,f6_19) + m(f[5],f5_38);
        long h1 = m(f0_2,f[1]) + m(f[2],f9_38) + m(f3_2,f8_19) + m(f[4],f7_38) + m(f5_2,f6_19);
        long h2 = m(f0_2,f[2]) + m(f1_2,f[1])  + m(f3_2,f9_38) + m(f4_2,f8_19) + m(f5_2,f7_38) + m(f[6],f6_19);
        long h3 = m(f0_2,f[3]) + m(f1_2,f[2])  + m(f[4],f9_38) + m(f5_2,f8_19) + m(f[6],f7_38);
        long h4 = m(f0_2,f[4]) + m(f1_2,f3_2)  + m(f[2],f[2])  + m(f5_2,f9_38) + m(f6_2,f8_19) + m(f[7],f7_38);
        long h5 = m(f0_2,f[5]) + m(f1_2,f[4])  + m(f2_2,f[3])  + m(f[6],f9_38) + m(f7_2,f8_19);
        long h6 = m(f0_2,f[6]) + m(f1_2,f5_2)  + m(f2_2,f[4])  + m(f3_2,f[3])  + m(f7_2,f9_38) + m(f[8],f8_19);
        long h7 = m(f0_2,f[7]) + m(f1_2,f[6])  + m(f2_2,f[5])  + m(f3_2,f[4])  + m(f[8],f9_38);
        long h8 = m(f0_2,f[8]) + m(f1_2,f7_2)  + m(f2_2,f[6])  + m(f3_2,f5_2)  + m(f[4],f[4])  + m(f[9],f9_38);
        long h9 = m(f0_2,f[9]) + m(f1_2,f[8])  + m(f2_2,f[7])  + m(f3_2,f[6])  + m(f4_2,f[5]);
        // @formatter:on

        return FieldElement.reduce(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    /**
     * $h = 2 * f * f$
     * <p>
     * Can overlap $h$ with $f$.
     * <p>
     * Preconditions:
     * <ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * <p>
     * Postconditions:
     * <ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * <p>
     * See {@link #multiply(FieldElement)} for discussion of implementation
     * strategy.
     *
     * @return The (reasonably reduced) square of this field element times 2.
     */
    public FieldElement squareAndDouble() {
        int[] f = this.t; // avoid getfield opcode

        int f0_2 = 2 * f[0];
        int f1_2 = 2 * f[1];
        int f2_2 = 2 * f[2];
        int f3_2 = 2 * f[3];
        int f4_2 = 2 * f[4];
        int f5_2 = 2 * f[5];
        int f6_2 = 2 * f[6];
        int f7_2 = 2 * f[7];

        int f5_38 = 38 * f[5]; /* 1.959375*2^30 */
        int f6_19 = 19 * f[6]; /* 1.959375*2^30 */
        int f7_38 = 38 * f[7]; /* 1.959375*2^30 */
        int f8_19 = 19 * f[8]; /* 1.959375*2^30 */
        int f9_38 = 38 * f[9]; /* 1.959375*2^30 */

        // @formatter:off
        long h0 = m(f[0],f[0]) + m(f1_2,f9_38) + m(f2_2,f8_19) + m(f3_2,f7_38) + m(f4_2,f6_19) + m(f[5],f5_38);
        long h1 = m(f0_2,f[1]) + m(f[2],f9_38) + m(f3_2,f8_19) + m(f[4],f7_38) + m(f5_2,f6_19);
        long h2 = m(f0_2,f[2]) + m(f1_2,f[1])  + m(f3_2,f9_38) + m(f4_2,f8_19) + m(f5_2,f7_38) + m(f[6],f6_19);
        long h3 = m(f0_2,f[3]) + m(f1_2,f[2])  + m(f[4],f9_38) + m(f5_2,f8_19) + m(f[6],f7_38);
        long h4 = m(f0_2,f[4]) + m(f1_2,f3_2)  + m(f[2],f[2])  + m(f5_2,f9_38) + m(f6_2,f8_19) + m(f[7],f7_38);
        long h5 = m(f0_2,f[5]) + m(f1_2,f[4])  + m(f2_2,f[3])  + m(f[6],f9_38) + m(f7_2,f8_19);
        long h6 = m(f0_2,f[6]) + m(f1_2,f5_2)  + m(f2_2,f[4])  + m(f3_2,f[3])  + m(f7_2,f9_38) + m(f[8],f8_19);
        long h7 = m(f0_2,f[7]) + m(f1_2,f[6])  + m(f2_2,f[5])  + m(f3_2,f[4])  + m(f[8],f9_38);
        long h8 = m(f0_2,f[8]) + m(f1_2,f7_2)  + m(f2_2,f[6])  + m(f3_2,f5_2)  + m(f[4],f[4])  + m(f[9],f9_38);
        long h9 = m(f0_2,f[9]) + m(f1_2,f[8])  + m(f2_2,f[7])  + m(f3_2,f[6])  + m(f4_2,f[5]);
        // @formatter:on

        h0 += h0;
        h1 += h1;
        h2 += h2;
        h3 += h3;
        h4 += h4;
        h5 += h5;
        h6 += h6;
        h7 += h7;
        h8 += h8;
        h9 += h9;

        return FieldElement.reduce(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
    }

    /**
     * Compute $\text{this}^{2^k}$ by successive squarings.
     *
     * @param k the exponent of 2. Must be positive and non-zero.
     * @return $\text{this}^{2^k}$
     */
    FieldElement pow2k(int k) {
        if (!(k > 0)) {
            throw new IllegalArgumentException("Exponent must be positive and non-zero");
        }
        FieldElement z = this.square();
        for (int i = 1; i < k; i++) {
            z = z.square();
        }
        return z;
    }

    /**
     * Invert this field element.
     * <p>
     * The inverse is found via Fermat's little theorem:<br>
     * $a^p \cong a \mod p$ and therefore $a^{(p-2)} \cong a^{-1} \mod p$
     *
     * @return The inverse of this field element.
     */
    public FieldElement invert() {
        // 2 == 2 * 1
        final FieldElement t0 = square();

        // 8 == 2 * 2 * 2
        final FieldElement t1 = t0.pow2k(2);

        // 9 == 8 + 1
        final FieldElement t2 = multiply(t1);

        // 11 == 9 + 2
        final FieldElement t3 = t0.multiply(t2);

        // 22 == 2 * 11
        final FieldElement t4 = t3.square();

        // 31 == 22 + 9
        final FieldElement t5 = t2.multiply(t4);

        // 2^10 - 2^5
        final FieldElement t6 = t5.pow2k(5);

        // 2^10 - 2^0
        final FieldElement t7 = t6.multiply(t5);

        // 2^20 - 2^10
        final FieldElement t8 = t7.pow2k(10);

        // 2^20 - 2^0
        final FieldElement t9 = t8.multiply(t7);

        // 2^40 - 2^20
        final FieldElement t10 = t9.pow2k(20);

        // 2^40 - 2^0
        final FieldElement t11 = t10.multiply(t9);

        // 2^50 - 2^10
        final FieldElement t12 = t11.pow2k(10);

        // 2^50 - 2^0
        final FieldElement t13 = t12.multiply(t7);

        // 2^100 - 2^50
        final FieldElement t14 = t13.pow2k(50);

        // 2^100 - 2^0
        final FieldElement t15 = t14.multiply(t13);

        // 2^200 - 2^100
        final FieldElement t16 = t15.pow2k(100);

        // 2^200 - 2^0
        final FieldElement t17 = t16.multiply(t15);

        // 2^250 - 2^50
        final FieldElement t18 = t17.pow2k(50);

        // 2^250 - 2^0
        final FieldElement t19 = t18.multiply(t13);

        // 2^255 - 2^5
        final FieldElement t20 = t19.pow2k(5);

        // 2^255 - 21
        return t20.multiply(t3);
    }

    /**
     * Raises this field element to the power $(p-5)/8 = 2^{252} - 3$.
     * <p>
     * Helper for {@link #sqrtRatioM1(FieldElement, FieldElement)}.
     *
     * @return $\text{this}^{(p-5)/8}$.
     */
    FieldElement powP58() {
        // 2 == 2 * 1
        final FieldElement t0 = square();

        // 8 == 2 * 2 * 2
        final FieldElement t1 = t0.pow2k(2);

        // z9 = z1*z8
        final FieldElement t2 = multiply(t1);

        // 11 == 9 + 2
        final FieldElement t3 = t0.multiply(t2);

        // 22 == 2 * 11
        final FieldElement t4 = t3.square();

        // 31 == 22 + 9
        final FieldElement t5 = t2.multiply(t4);

        // 2^10 - 2^5
        final FieldElement t6 = t5.pow2k(5);

        // 2^10 - 2^0
        final FieldElement t7 = t6.multiply(t5);

        // 2^20 - 2^10
        final FieldElement t8 = t7.pow2k(10);

        // 2^20 - 2^0
        final FieldElement t9 = t8.multiply(t7);

        // 2^40 - 2^20
        final FieldElement t10 = t9.pow2k(20);

        // 2^40 - 2^0
        final FieldElement t11 = t10.multiply(t9);

        // 2^50 - 2^10
        final FieldElement t12 = t11.pow2k(10);

        // 2^50 - 2^0
        final FieldElement t13 = t12.multiply(t7);

        // 2^100 - 2^50
        final FieldElement t14 = t13.pow2k(50);

        // 2^100 - 2^0
        final FieldElement t15 = t14.multiply(t13);

        // 2^200 - 2^100
        final FieldElement t16 = t15.pow2k(100);

        // 2^200 - 2^0
        final FieldElement t17 = t16.multiply(t15);

        // 2^250 - 2^50
        final FieldElement t18 = t17.pow2k(50);

        // 2^250 - 2^0
        final FieldElement t19 = t18.multiply(t13);

        // 2^252 - 2^2
        final FieldElement t20 = t19.pow2k(2);

        // 2^252 - 3
        return this.multiply(t20);
    }

    /**
     * The result of calling {@link #sqrtRatioM1(FieldElement, FieldElement)}.
     */
    static class SqrtRatioM1Result {
        int wasSquare;
        FieldElement result;

        SqrtRatioM1Result(int wasSquare, FieldElement result) {
            this.wasSquare = wasSquare;
            this.result = result;
        }
    }

    /**
     * Given FieldElements $u$ and $v$, compute either $\sqrt{u / v}$ or $\sqrt{i *
     * u / v}$ in constant time.
     * <p>
     * This function always returns the non-negative square root.
     *
     * @param u the numerator.
     * @param v the denominator.
     * @return
     *         <ul>
     *         <li>(true, +$\sqrt{u / v}$) if $v$ is non-zero and $u / v$ is square.
     *         <li>(true, zero) if $u$ is zero.
     *         <li>(false, zero) if $v$ is zero and $u$ is non-zero.
     *         <li>(false, +$\sqrt{i * u / v}$) if $u / v$ is non-square (so $i * u
     *         / v$ is square).
     */
    static SqrtRatioM1Result sqrtRatioM1(FieldElement u, FieldElement v) {
        FieldElement v3 = v.square().multiply(v);
        FieldElement v7 = v3.square().multiply(v);
        FieldElement r = u.multiply(v3).multiply(u.multiply(v7).powP58());
        FieldElement check = v.multiply(r.square());

        FieldElement uNeg = u.negate();
        int correctSignSqrt = check.ctEquals(u);
        int flippedSignSqrt = check.ctEquals(uNeg);
        int flippedSignSqrtM1 = check.ctEquals(uNeg.multiply(Constants.SQRT_M1));

        FieldElement rPrime = r.multiply(Constants.SQRT_M1);
        r = r.ctSelect(rPrime, flippedSignSqrt | flippedSignSqrtM1);

        // Choose the non-negative square root.
        int rIsNegative = r.isNegative();
        r = r.ctSelect(r.negate(), rIsNegative);

        return new SqrtRatioM1Result(correctSignSqrt | flippedSignSqrt, r);
    }

    /**
     * For debugging.
     */
    String printInternalRepresentation() {
        String ir = "FieldElement([";
        for (int i = 0; i < this.t.length; i++) {
            if (i > 0) {
                ir += ", ";
            }
            ir += t[i];
        }
        ir += "])";
        return ir;
    }
}
