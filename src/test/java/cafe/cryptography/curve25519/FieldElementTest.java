/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

public class FieldElementTest {
    // Test vectors below, and the tests they are used in, are from
    // curve25519-dalek.
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/4bdccd7b7c394d9f8ffc4b29d5acc23c972f3d7a/src/field.rs#L280-L301

    // Random element a of GF(2^255-19), from Sage
    // a = 1070314506888354081329385823235218444233221\
    // 2228051251926706380353716438957572
    static final byte[] A_BYTES = { 0x04, (byte) 0xfe, (byte) 0xdf, (byte) 0x98, (byte) 0xa7, (byte) 0xfa, 0x0a, 0x68,
            (byte) 0x84, (byte) 0x92, (byte) 0xbd, 0x59, 0x08, 0x07, (byte) 0xa7, 0x03, (byte) 0x9e, (byte) 0xd1,
            (byte) 0xf6, (byte) 0xf2, (byte) 0xe1, (byte) 0xd9, (byte) 0xe2, (byte) 0xa4, (byte) 0xa4, 0x51, 0x47, 0x36,
            (byte) 0xf3, (byte) 0xc3, (byte) 0xa9, 0x17 };

    // Byte representation of a**2
    static final byte[] ASQ_BYTES = { 0x75, (byte) 0x97, 0x24, (byte) 0x9e, (byte) 0xe6, 0x06, (byte) 0xfe, (byte) 0xab,
            0x24, 0x04, 0x56, 0x68, 0x07, (byte) 0x91, 0x2d, 0x5d, 0x0b, 0x0f, 0x3f, 0x1c, (byte) 0xb2, 0x6e,
            (byte) 0xf2, (byte) 0xe2, 0x63, (byte) 0x9c, 0x12, (byte) 0xba, 0x73, 0x0b, (byte) 0xe3, 0x62 };

    // Byte representation of 1/a
    static final byte[] AINV_BYTES = { (byte) 0x96, 0x1b, (byte) 0xcd, (byte) 0x8d, 0x4d, 0x5e, (byte) 0xa2, 0x3a,
            (byte) 0xe9, 0x36, 0x37, (byte) 0x93, (byte) 0xdb, 0x7b, 0x4d, 0x70, (byte) 0xb8, 0x0d, (byte) 0xc0, 0x55,
            (byte) 0xd0, 0x4c, 0x1d, 0x7b, (byte) 0x90, 0x71, (byte) 0xd8, (byte) 0xe9, (byte) 0xb6, 0x18, (byte) 0xe6,
            0x30 };

    @Test
    public void testAMulAVsASquaredConstant() {
        final FieldElement a = FieldElement.fromByteArray(A_BYTES);
        final FieldElement asq = FieldElement.fromByteArray(ASQ_BYTES);
        assertThat(a.multiply(a), is(asq));
    }

    @Test
    public void testASquareVsASquaredConstant() {
        final FieldElement a = FieldElement.fromByteArray(A_BYTES);
        final FieldElement asq = FieldElement.fromByteArray(ASQ_BYTES);
        assertThat(a.square(), is(asq));
    }

    @Test
    public void testASquare2VsASquaredConstant() {
        final FieldElement a = FieldElement.fromByteArray(A_BYTES);
        final FieldElement asq = FieldElement.fromByteArray(ASQ_BYTES);
        assertThat(a.squareAndDouble(), is(asq.add(asq)));
    }

    @Test
    public void testAInvertVsInverseOfAConstant() {
        final FieldElement a = FieldElement.fromByteArray(A_BYTES);
        final FieldElement ainv = FieldElement.fromByteArray(AINV_BYTES);
        final FieldElement shouldBeInverse = a.invert();
        assertThat(shouldBeInverse, is(ainv));
        assertThat(a.multiply(shouldBeInverse), is(FieldElement.ONE));
    }

    @Test
    public void equality() {
        final FieldElement a = FieldElement.fromByteArray(A_BYTES);
        final FieldElement ainv = FieldElement.fromByteArray(AINV_BYTES);
        assertThat(a, is(a));
        assertThat(a, is(not(ainv)));
    }

    // Notice that the last element has the high bit set, which
    // should be ignored.
    static final byte[] B_BYTES = { 113, (byte) 191, (byte) 169, (byte) 143, 91, (byte) 234, 121, 15, (byte) 241,
            (byte) 131, (byte) 217, 36, (byte) 230, 101, 92, (byte) 234, 8, (byte) 208, (byte) 170, (byte) 251, 97, 127,
            70, (byte) 210, 58, 23, (byte) 166, 87, (byte) 240, (byte) 169, (byte) 184, (byte) 178 };

    @Test
    public void fromByteArrayHighbitIsIgnored() {
        byte[] cleared_bytes = B_BYTES;
        cleared_bytes[31] &= 127;
        FieldElement withHighbitSet = FieldElement.fromByteArray(B_BYTES);
        FieldElement withoutHighbitSet = FieldElement.fromByteArray(cleared_bytes);
        assertThat(withoutHighbitSet, is(withHighbitSet));
    }

    @Test
    public void encodingIsCanonical() {
        // Encode 1 wrongly as 1 + (2^255 - 19) = 2^255 - 18
        byte[] oneEncodedWronglyBytes = { (byte) 0xee, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, 0x7f };

        // Decode to a field element
        FieldElement one = FieldElement.fromByteArray(oneEncodedWronglyBytes);

        // .. then check that the encoding is correct
        byte[] oneBytes = one.toByteArray();
        assertThat(oneBytes[0], is((byte) 1));
        for (int i = 1; i < 32; i++) {
            assertThat(oneBytes[i], is((byte) 0));
        }
    }

    @Test
    public void encodeAndDecodeOnZero() {
        byte[] zero = new byte[32];
        final FieldElement a = FieldElement.fromByteArray(zero);

        assertThat(a, is(FieldElement.ZERO));
        assertThat(a.toByteArray(), is(zero));
    }

    @Test
    public void ctSelectReturnsCorrectResult() {
        int[] a_t = new int[10];
        int[] b_t = new int[10];
        for (int i = 0; i < 10; i++) {
            a_t[i] = i;
            b_t[i] = 10 - i;
        }

        final FieldElement a = new FieldElement(a_t);
        final FieldElement b = new FieldElement(b_t);

        assertThat(a.ctSelect(b, 0), is(a));
        assertThat(a.ctSelect(b, 1), is(b));
        assertThat(b.ctSelect(a, 0), is(b));
        assertThat(b.ctSelect(a, 1), is(a));
    }
}
