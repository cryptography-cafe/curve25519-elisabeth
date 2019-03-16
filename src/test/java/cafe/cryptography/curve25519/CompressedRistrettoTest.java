/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

public class CompressedRistrettoTest {
    @Test
    public void constructorDoesNotThrowOnCorrectLength() {
        new CompressedRistretto(new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorThrowsOnTooShort() {
        new CompressedRistretto(new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorThrowsOnTooLong() {
        new CompressedRistretto(new byte[33]);
    }

    @Test
    public void toByteArray() {
        byte[] s = new byte[32];
        s[0] = 0x1f;
        assertThat(new CompressedRistretto(s).toByteArray(), is(s));
    }

    @Test
    public void equalityRequiresSameClass() {
        byte[] s = new byte[32];
        CompressedRistretto r = new CompressedRistretto(s);
        CompressedEdwardsY e = new CompressedEdwardsY(s);
        assertFalse(r.equals(e));
    }
}
