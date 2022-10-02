package cafe.cryptography.curve25519;

class SignedScalar {
    public static final Scalar PRIME = new SignedScalar(new long[] { });
    public static final Scalar PRIME_SQUARED = new SignedScalar(new long[] { });

    private static final long MASK_31_BITS = (1L << 31) - 1;

    private long[] s;

    SignedScalar(long[] input) {
        if (input.length != 17) {
            throw new IllegalArgumentException("Input must by 17 31-bit limbs");
        }
        this.s = input;
    }

    public SignedScalar add(SignedScalar b) {
        long[] sum = new long[17];

        long carry = 0;
        for (int i = 0; i < 17; i++) {
            carry = this.s[i] + b.s[i] + (carry >> 31);
            sum[i] = carry & MASK_31_BITS;
        }

        return new SignedScalar(sum);
    }

    public SignedScalar subtract(SignedScalar b) {
        long[] difference = new long[17];

        long borrow = 0;
        for (int i = 0; i < 17; i++) {
            borrow = this.s[i] - (b.s[i] + (borrow >>> 63));
            difference[i] = borrow & MASK_31_BITS;
        }

        return new SignedScalar(difference);
    }

    static long m(long a, long b) {
        return a * b;
    }

    /**
     * Compute $a * b \bmod \ell$.
     *
     * @param val the Scalar to multiply with this.
     * @return the unreduced limbs.
     */
    long[] mulInternal(final UnpackedScalar val) {
        int[] a = this.s;
        int[] b = val.s;
        long[] z = new long[17];

        // @formatter:off
        z[0] = m(a[0],b[0]);                                                             // c00
        z[1] = m(a[0],b[1]) + m(a[1],b[0]);                                              // c01
        z[2] = m(a[0],b[2]) + m(a[1],b[1]) + m(a[2],b[0]);                               // c02
        z[3] = m(a[0],b[3]) + m(a[1],b[2]) + m(a[2],b[1]) + m(a[3],b[0]);                // c03
        z[4] = m(a[0],b[4]) + m(a[1],b[3]) + m(a[2],b[2]) + m(a[3],b[1]) + m(a[4],b[0]); // c04
        z[5] =                m(a[1],b[4]) + m(a[2],b[3]) + m(a[3],b[2]) + m(a[4],b[1]); // c05
        z[6] =                               m(a[2],b[4]) + m(a[3],b[3]) + m(a[4],b[2]); // c06
        z[7] =                                              m(a[3],b[4]) + m(a[4],b[3]); // c07
        z[8] =                                                            (m(a[4],b[4])) - z[3]; // c08 - c03

        z[10] = z[5] - (m(a[5],b[5]));                                             // c05mc10
        z[11] = z[6] - (m(a[5],b[6]) + m(a[6],b[5]));                              // c06mc11
        z[12] = z[7] - (m(a[5],b[7]) + m(a[6],b[6]) + m(a[7],b[5]));               // c07mc12
        z[13] =         m(a[5],b[8]) + m(a[6],b[7]) + m(a[7],b[6]) + m(a[8],b[5]); // c13
        z[14] =                        m(a[6],b[8]) + m(a[7],b[7]) + m(a[8],b[6]); // c14
        z[15] =                                       m(a[7],b[8]) + m(a[8],b[7]); // c15
        z[16] =                                                      m(a[8],b[8]); // c16

        z[ 5] = z[10] - (z[ 0]); // c05mc10 - c00
        z[ 6] = z[11] - (z[ 1]); // c06mc11 - c01
        z[ 7] = z[12] - (z[ 2]); // c07mc12 - c02
        z[ 8] = z[ 8] - (z[13]); // c08mc13 - c03
        z[ 9] = z[14] + (z[ 4]); // c14 + c04
        z[10] = z[15] + (z[10]); // c15 + c05mc10
        z[11] = z[16] + (z[11]); // c16 + c06mc11

        int aa0 = a[0] + a[5];
        int aa1 = a[1] + a[6];
        int aa2 = a[2] + a[7];
        int aa3 = a[3] + a[8];

        int bb0 = b[0] + b[5];
        int bb1 = b[1] + b[6];
        int bb2 = b[2] + b[7];
        int bb3 = b[3] + b[8];

        z[ 5] = (m(aa0,bb0))                                                          + z[ 5]; // c20 + c05mc10 - c00
        z[ 6] = (m(aa0,bb1 ) + m(aa1,bb0))                                            + z[ 6]; // c21 + c06mc11 - c01
        z[ 7] = (m(aa0,bb2 ) + m(aa1,bb1 ) + m(aa2,bb0))                              + z[ 7]; // c22 + c07mc12 - c02
        z[ 8] = (m(aa0,bb3 ) + m(aa1,bb2 ) + m(aa2,bb1 ) + m(aa3,bb0))                + z[ 8]; // c23 + c08mc13 - c03
        z[ 9] = (m(aa0,b[4]) + m(aa1,bb3 ) + m(aa2,bb2 ) + m(aa3,bb1 ) + m(a[4],bb0)) - z[ 9]; // c24 - c14 - c04
        z[10] = (              m(aa1,b[4]) + m(aa2,bb3 ) + m(aa3,bb2 ) + m(a[4],bb1)) - z[10]; // c25 - c15 - c05mc10
        z[11] = (                            m(aa2,b[4]) + m(aa3,bb3 ) + m(a[4],bb2)) - z[11]; // c26 - c16 - c06mc11
        z[12] = (                                          m(aa3,b[4]) + m(a[4],bb3)) - z[12]; // c27 - c07mc12
        // @formatter:on

        return z;
    }

    public SignedScalar multiply(SignedScalar b) {
    }

    public SignedScalar square() {
    }
}