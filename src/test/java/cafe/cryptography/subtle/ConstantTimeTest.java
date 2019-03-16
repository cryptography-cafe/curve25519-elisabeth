/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.subtle;

import java.util.Arrays;
import java.util.Random;

import org.hamcrest.core.IsEqual;
import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class ConstantTimeTest {
    @Test
    public void equalOnByte() {
        assertThat(ConstantTime.equal(0, 0), is(1));
        assertThat(ConstantTime.equal(1, 1), is(1));
        assertThat(ConstantTime.equal(1, 0), is(0));
        assertThat(ConstantTime.equal(1, 127), is(0));
        assertThat(ConstantTime.equal(-127, 127), is(0));
        assertThat(ConstantTime.equal(-42, -42), is(1));
        assertThat(ConstantTime.equal(255, 255), is(1));
        assertThat(ConstantTime.equal(-255, -256), is(0));
    }

    @Test
    public void equalOnByteArraysWithSingleDifference() {
        byte[] zero = new byte[32];
        byte[] one = new byte[32];
        one[0] = 1;

        assertThat(ConstantTime.equal(zero, zero), is(1));
        assertThat(ConstantTime.equal(one, one), is(1));
        assertThat(ConstantTime.equal(one, zero), is(0));
        assertThat(ConstantTime.equal(zero, one), is(0));
    }

    @Test
    public void equalOnByteArraysWithDifferentLengths() {
        byte[] zeroNine = new byte[9];
        byte[] zeroTen = new byte[10];

        assertThat(ConstantTime.equal(zeroNine, zeroNine), is(1));
        assertThat(ConstantTime.equal(zeroTen, zeroTen), is(1));
        assertThat(ConstantTime.equal(zeroNine, zeroTen), is(0));
        assertThat(ConstantTime.equal(zeroTen, zeroNine), is(0));
    }

    @Test
    public void equalOnByteArraysWithRandomData() {
        Random random = new Random(758094325);

        for (int i = 1; i < 33; i++) {
            byte[] a = new byte[i];
            byte[] b = new byte[i];

            random.nextBytes(a);
            random.nextBytes(b);

            assertThat(ConstantTime.equal(a, a), is(1));
            assertThat(ConstantTime.equal(b, b), is(1));
            assertThat(ConstantTime.equal(a, b), is(0));
            assertThat(ConstantTime.equal(b, a), is(0));

            // Test mutation in MSB
            byte[] aPrime = Arrays.copyOf(a, i);
            assertThat(ConstantTime.equal(a, aPrime), is(1));
            aPrime[i - 1] += 1;
            assertThat(ConstantTime.equal(a, aPrime), is(0));
        }
    }

    @Test
    public void isNegative() {
        assertThat(ConstantTime.isNegative(0), is(0));
        assertThat(ConstantTime.isNegative(1), is(0));
        assertThat(ConstantTime.isNegative(-1), is(1));
        assertThat(ConstantTime.isNegative(32), is(0));
        assertThat(ConstantTime.isNegative(-100), is(1));
        assertThat(ConstantTime.isNegative(127), is(0));
        assertThat(ConstantTime.isNegative(-255), is(1));
    }

    @Test
    public void bit() {
        assertThat(ConstantTime.bit(new byte[] { 0 }, 0), is(0));
        assertThat(ConstantTime.bit(new byte[] { 8 }, 3), is(1));
        assertThat(ConstantTime.bit(new byte[] { 1, 2, 3 }, 9), is(1));
        assertThat(ConstantTime.bit(new byte[] { 1, 2, 3 }, 15), is(0));
        assertThat(ConstantTime.bit(new byte[] { 1, 2, 3 }, 16), is(1));
    }
}
