/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

public class UnpackedScalarTest {
    /**
     * Note: x is 2^253-1 which is slightly larger than the largest scalar produced
     * by this implementation (l-1), and should verify there are no overflows for
     * valid scalars
     *
     * x = 2^253-1 =
     * 14474011154664524427946373126085988481658748083205070504932198000989141204991
     *
     * x =
     * 7237005577332262213973186563042994240801631723825162898930247062703686954002
     * mod l
     *
     * x =
     * 5147078182513738803124273553712992179887200054963030844803268920753008712037*R
     * mod l in Montgomery form
     */
    static final UnpackedScalar X = new UnpackedScalar(new int[] { 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff,
            0x1fffffff, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x001fffff });

    /**
     * x^2 =
     * 3078544782642840487852506753550082162405942681916160040940637093560259278169
     * mod l
     */
    static final UnpackedScalar XX = new UnpackedScalar(new int[] { 0x00217559, 0x000b3401, 0x103ff43b, 0x1462a62c,
            0x1d6f9f38, 0x18e7a42f, 0x09a3dcee, 0x008dbe18, 0x0006ce65 });

    /**
     * y =
     * 6145104759870991071742105800796537629880401874866217824609283457819451087098
     */
    static final UnpackedScalar Y = new UnpackedScalar(new int[] { 0x1e1458fa, 0x165ba838, 0x1d787b36, 0x0e577f3a,
            0x1d2baf06, 0x1d689a19, 0x1fff3047, 0x117704ab, 0x000d9601 });

    /**
     * x*y = 36752150652102274958925982391442301741
     */
    static final UnpackedScalar XY = new UnpackedScalar(new int[] { 0x0ba7632d, 0x017736bb, 0x15c76138, 0x0c69daa1,
            0x000001ba, 0x00000000, 0x00000000, 0x00000000, 0x00000000 });

    /**
     * a =
     * 2351415481556538453565687241199399922945659411799870114962672658845158063753
     */
    static final UnpackedScalar A = new UnpackedScalar(new int[] { 0x07b3be89, 0x02291b60, 0x14a99f03, 0x07dc3787,
            0x0a782aae, 0x16262525, 0x0cfdb93f, 0x13f5718d, 0x000532da });

    /**
     * b =
     * 4885590095775723760407499321843594317911456947580037491039278279440296187236
     */
    static final UnpackedScalar B = new UnpackedScalar(new int[] { 0x15421564, 0x1e69fd72, 0x093d9692, 0x161785be,
            0x1587d69f, 0x09d9dada, 0x130246c0, 0x0c0a8e72, 0x000acd25 });

    /**
     * a+b = 0
     */

    /**
     * a-b =
     * 4702830963113076907131374482398799845891318823599740229925345317690316127506
     */
    static final UnpackedScalar AB = new UnpackedScalar(new int[] { 0x0f677d12, 0x045236c0, 0x09533e06, 0x0fb86f0f,
            0x14f0555c, 0x0c4c4a4a, 0x19fb727f, 0x07eae31a, 0x000a65b5 });

    @Test
    public void unpackThenPack() {
        assertThat(UnpackedScalar.fromByteArray(ScalarTest.TV1_R).toByteArray(), is(ScalarTest.TV1_R));
        assertThat(UnpackedScalar.fromByteArray(ScalarTest.TV1_H).toByteArray(), is(ScalarTest.TV1_H));
        assertThat(UnpackedScalar.fromByteArray(ScalarTest.TV1_A).toByteArray(), is(ScalarTest.TV1_A));
        assertThat(UnpackedScalar.fromByteArray(ScalarTest.TV1_S).toByteArray(), is(ScalarTest.TV1_S));
    }

    @Test
    public void addLToZero() {
        assertThat(UnpackedScalar.ZERO.add(Constants.L).s, is(UnpackedScalar.ZERO.s));
    }

    @Test
    public void add() {
        assertThat(A.add(B).s, is(UnpackedScalar.ZERO.s));
    }

    @Test
    public void subtract() {
        assertThat(A.subtract(B).s, is(AB.s));
    }

    @Test
    public void multiply() {
        assertThat(X.multiply(Y).s, is(XY.s));
    }

    @Test
    public void multiplyMax() {
        assertThat(X.multiply(X).s, is(XX.s));
    }
}
