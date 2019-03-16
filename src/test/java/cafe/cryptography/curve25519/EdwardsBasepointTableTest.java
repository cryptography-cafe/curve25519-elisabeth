/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class EdwardsBasepointTableTest {
    @Test
    public void scalarMulVsEd25519py() {
        EdwardsBasepointTable Bt = new EdwardsBasepointTable(Constants.ED25519_BASEPOINT);
        EdwardsPoint aB = Bt.multiply(EdwardsPointTest.A_SCALAR);
        assertThat(aB.compress(), is(EdwardsPointTest.A_TIMES_BASEPOINT));
    }
}
