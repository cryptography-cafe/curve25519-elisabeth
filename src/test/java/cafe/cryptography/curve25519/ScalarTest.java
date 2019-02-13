package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

public class ScalarTest {
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
