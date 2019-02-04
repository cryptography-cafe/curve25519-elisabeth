package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

public class ScalarTest {
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
    }
}
