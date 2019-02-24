package cafe.cryptography.curve25519;

import org.junit.*;
import org.junit.rules.ExpectedException;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

public class ScalarTest {
    /**
     * x =
     * 2238329342913194256032495932344128051776374960164957527413114840482143558222
     */
    static final Scalar X = new Scalar(
            Utils.hexToBytes("4e5ab4345d4708845913b4641bc27d5252a585101bcc4244d449f4a879d9f204"));

    /**
     * 1/x =
     * 6859937278830797291664592131120606308688036382723378951768035303146619657244
     */
    static final Scalar XINV = new Scalar(
            Utils.hexToBytes("1cdc17fce0e9a5bbd9247e56bb016347bbba31edd5a9bb96d50bcd7a3f962a0f"));

    /**
     * y =
     * 2592331292931086675770238855846338635550719849568364935475441891787804997264
     */
    static final Scalar Y = new Scalar(
            Utils.hexToBytes("907633fe1c4b66a4a28d2dd7678386c353d0de5455d4fc9de8ef7ac31f35bb05"));

    /**
     * x*y =
     * 5690045403673944803228348699031245560686958845067437804563560795922180092780
     */
    static final Scalar X_TIMES_Y = new Scalar(
            Utils.hexToBytes("6c3374a1894f62210aaa2fe186a6f92ce0aa75c2779581c295fc08179a73940c"));

    /**
     * sage: l = 2^252 + 27742317777372353535851937790883648493 sage: big = 2^256 -
     * 1 sage: repr((big % l).digits(256))
     */
    static final Scalar CANONICAL_2_256_MINUS_1 = new Scalar(
            Utils.hexToBytes("1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f"));

    static final Scalar A_SCALAR = new Scalar(
            Utils.hexToBytes("1a0e978a90f6622d3747023f8ad8264da758aa1b88e040d1589e7b7f2376ef09"));

    static final byte[] A_NAF = new byte[] { 0, 13, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, -11, 0, 0,
            0, 0, 3, 0, 0, 0, 0, 1, 0, 0, 0, 0, 9, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 11, 0, 0, 0, 0, 11,
            0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0,
            9, 0, 0, 0, 0, -15, 0, 0, 0, 0, -7, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, -3, 0,
            0, 0, 0, -11, 0, 0, 0, 0, -7, 0, 0, 0, 0, -13, 0, 0, 0, 0, 11, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
            0, -15, 0, 0, 0, 0, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 11, 0,
            0, 0, 0, 0, 15, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, -15, 0,
            0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 };

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void packageConstructorDoesNotThrowOnValid() {
        byte[] s = new byte[32];
        s[31] = 0x7f;
        new Scalar(s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void packageConstructorThrowsOnHighBitSet() {
        byte[] s = new byte[32];
        s[31] = (byte) 0x80;
        new Scalar(s);
    }

    @Test(expected = IllegalArgumentException.class)
    public void packageConstructorThrowsOnTooShort() {
        new Scalar(new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void packageConstructorThrowsOnTooLong() {
        new Scalar(new byte[33]);
    }

    @Test
    public void reduce() {
        Scalar biggest = Scalar.fromBytesModOrder(
                Utils.hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        assertThat(biggest, is(CANONICAL_2_256_MINUS_1));
    }

    @Test
    public void reduceWide() {
        Scalar biggest = Scalar.fromBytesModOrderWide(Utils.hexToBytes(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000"));
        assertThat(biggest, is(CANONICAL_2_256_MINUS_1));
    }

    @Test
    public void canonicalDecoding() {
        // Canonical encoding of 1667457891
        byte[] canonicalBytes = Utils.hexToBytes("6363636300000000000000000000000000000000000000000000000000000000");

        Scalar.fromCanonicalBytes(canonicalBytes);
    }

    @Test
    public void nonCanonicalDecodingUnreduced() {
        // Encoding of
        // 7265385991361016183439748078976496179028704920197054998554201349516117938192
        // = 28380414028753969466561515933501938171588560817147392552250411230663687203
        // (mod l)
        // Non-canonical because unreduced mod l
        byte[] nonCanonicalBytesBecauseUnreduced = new byte[32];
        for (int i = 0; i < 32; i++) {
            nonCanonicalBytesBecauseUnreduced[i] = 16;
        }

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Non-canonical scalar representation");
        Scalar.fromCanonicalBytes(nonCanonicalBytesBecauseUnreduced);
    }

    @Test
    public void nonCanonicalDecodingHighbit() {
        // Encoding with high bit set, to check that the parser isn't pre-masking the
        // high bit
        byte[] nonCanonicalBytesBecauseHighbit = new byte[32];
        nonCanonicalBytesBecauseHighbit[31] = (byte) 0x80;

        expectedEx.expect(IllegalArgumentException.class);
        expectedEx.expectMessage("Invalid scalar representation");
        Scalar.fromCanonicalBytes(nonCanonicalBytesBecauseHighbit);
    }

    @Test
    public void fromBitsClearsHighbit() {
        Scalar exact = Scalar
                .fromBits(Utils.hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        assertThat(exact.toByteArray(),
                is(Utils.hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")));
    }

    @Test
    public void addReduces() {
        Scalar largestEd25519Scalar = Scalar
                .fromBits(Utils.hexToBytes("f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
        assertThat(largestEd25519Scalar.add(Scalar.ONE), is(Scalar.fromCanonicalBytes(
                Utils.hexToBytes("7e344775474a7f9723b63a8be92ae76dffffffffffffffffffffffffffffff0f"))));
    }

    @Test
    public void subtractReduces() {
        Scalar largestEd25519Scalar = Scalar
                .fromBits(Utils.hexToBytes("f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
        assertThat(largestEd25519Scalar.subtract(Scalar.ONE), is(Scalar.fromCanonicalBytes(
                Utils.hexToBytes("7c344775474a7f9723b63a8be92ae76dffffffffffffffffffffffffffffff0f"))));
    }

    @Test
    public void multiply() {
        assertThat(X.multiply(Y), is(X_TIMES_Y));
        assertThat(X_TIMES_Y.multiply(XINV), is(Y));
    }

    @Test
    public void nonAdjacentForm() {
        byte[] naf = A_SCALAR.nonAdjacentForm();
        assertThat(naf, is(A_NAF));
    }

    // Example from RFC 8032 test case 1
    static final byte[] TV1_R_INPUT = Utils.hexToBytes(
            "b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d");
    static final byte[] TV1_R = Utils.hexToBytes("f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404");
    static final byte[] TV1_H = Utils.hexToBytes("86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404");
    static final byte[] TV1_A = Utils.hexToBytes("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f");
    static final byte[] TV1_S = Utils.hexToBytes("5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    @Test
    public void testVectorFromBytesModOrderWide() {
        assertThat(Scalar.fromBytesModOrderWide(TV1_R_INPUT), is(equalTo(new Scalar(TV1_R))));
    }

    @Test
    public void testVectorMultiplyAndAdd() {
        Scalar h = new Scalar(TV1_H);
        Scalar a = new Scalar(TV1_A);
        Scalar r = new Scalar(TV1_R);
        Scalar S = new Scalar(TV1_S);
        assertThat(h.multiplyAndAdd(a, r), is(equalTo(S)));
        assertThat(h.multiply(a).add(r), is(equalTo(S)));
        assertThat(h.multiply(a), is(equalTo(S.subtract(r))));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromBytesModOrderWideThrowsOnTooShort() {
        Scalar.fromBytesModOrderWide(new byte[63]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromBytesModOrderWideThrowsOnTooLong() {
        Scalar.fromBytesModOrderWide(new byte[65]);
    }

    static final Scalar FORTYTWO = new Scalar(
            Utils.hexToBytes("2A00000000000000000000000000000000000000000000000000000000000000"));
    static final Scalar S1234567890 = new Scalar(
            Utils.hexToBytes("D202964900000000000000000000000000000000000000000000000000000000"));
    static final byte[] RADIX16_ZERO = Utils.hexToBytes(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] RADIX16_ONE = Utils.hexToBytes(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] RADIX16_42 = Utils.hexToBytes(
            "FA030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    /**
     * Test method for {@link GroupElement#toRadix16(byte[])}.
     */
    @Test
    public void testToRadix16() {
        assertThat(Scalar.ZERO.toRadix16(), is(RADIX16_ZERO));
        assertThat(Scalar.ONE.toRadix16(), is(RADIX16_ONE));
        assertThat(FORTYTWO.toRadix16(), is(RADIX16_42));

        byte[] from1234567890 = S1234567890.toRadix16();
        int total = 0;
        for (int i = 0; i < from1234567890.length; i++) {
            assertThat(from1234567890[i], is(greaterThanOrEqualTo((byte) -8)));
            assertThat(from1234567890[i], is(lessThanOrEqualTo((byte) 7)));
            total += from1234567890[i] * Math.pow(16, i);
        }
        assertThat(total, is(1234567890));

        byte[] tv1HR16 = (new Scalar(TV1_H)).toRadix16();
        for (int i = 0; i < tv1HR16.length; i++) {
            assertThat(tv1HR16[i], is(greaterThanOrEqualTo((byte) -8)));
            assertThat(tv1HR16[i], is(lessThanOrEqualTo((byte) 7)));
        }
    }
}
