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
import static org.junit.Assert.assertTrue;

public class EdwardsPointTest {
    /**
     * Compressed Edwards Y form of the Ed25519 basepoint.
     */
    static final CompressedEdwardsY ED25519_BASEPOINT_COMPRESSED = new CompressedEdwardsY(
            Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"));

    /**
     * Compressed Edwards Y form of 2*basepoint.
     */
    static final CompressedEdwardsY BASE2_CMPRSSD = new CompressedEdwardsY(
            Utils.hexToBytes("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"));

    /**
     * Compressed Edwards Y form of 16*basepoint.
     */
    static final CompressedEdwardsY BASE16_CMPRSSD = new CompressedEdwardsY(
            Utils.hexToBytes("eb2767c137ab7ad8279c078eff116ab0786ead3a2e0f989f72c37f82f2969670"));

    /**
     * 4493907448824000747700850167940867464579944529806937181821189941592931634714
     */
    static final Scalar A_SCALAR = new Scalar(
            Utils.hexToBytes("1a0e978a90f6622d3747023f8ad8264da758aa1b88e040d1589e7b7f2376ef09"));

    /**
     * 2506056684125797857694181776241676200180934651973138769173342316833279714961
     */
    static final Scalar B_SCALAR = new Scalar(
            Utils.hexToBytes("91267acf25c2091ba217747b66f0b32e9df2a56741cfdac456a7d4aab8608a05"));

    /**
     * A_SCALAR * basepoint, computed with ed25519.py
     */
    static final CompressedEdwardsY A_TIMES_BASEPOINT = new CompressedEdwardsY(
            Utils.hexToBytes("ea27e26053df1b5956f14d5dec3c34c384a269b74cc3803ea8e2e7c9425e40a5"));

    /**
     * A_SCALAR * (A_TIMES_BASEPOINT) + B_SCALAR * BASEPOINT computed with
     * ed25519.py
     */
    static final CompressedEdwardsY DOUBLE_SCALAR_MULT_RESULT = new CompressedEdwardsY(
            Utils.hexToBytes("7dfd6c45af6d6e0eba20371a236459c4c0468343de704b85096ffe354f132b42"));

    /**
     * The 8-torsion subgroup $\mathcal E [8]$.
     * <p>
     * In the case of Curve25519, it is cyclic; the $i$-th element of the array is
     * $[i]P$, where $P$ is a point of order $8$ generating $\mathcal E[8]$.
     * <p>
     * Thus $\mathcal E[8]$ is the points indexed by 0,2,4,6, and $\mathcal E[2]$ is
     * the points indexed by 0,4.
     */
    static final CompressedEdwardsY[] EIGHT_TORSION_COMPRESSED = new CompressedEdwardsY[] {
            new CompressedEdwardsY(
                    Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000080")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000")),
            new CompressedEdwardsY(
                    Utils.hexToBytes("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")) };

    @Test
    public void basepointDecompressionCompression() {
        EdwardsPoint B = ED25519_BASEPOINT_COMPRESSED.decompress();
        assertThat(B.compress(), is(ED25519_BASEPOINT_COMPRESSED));
    }

    @Test
    public void decompressionSignHandling() {
        // Manually set the high bit of the last byte to flip the sign
        byte[] minusBasepointBytes = ED25519_BASEPOINT_COMPRESSED.toByteArray();
        minusBasepointBytes[31] |= 1 << 7;
        EdwardsPoint minusB = new CompressedEdwardsY(minusBasepointBytes).decompress();
        // Test projective coordinates exactly since we know they should
        // only differ by a flipped sign.
        assertThat(minusB.X, is(Constants.ED25519_BASEPOINT.X.negate()));
        assertThat(minusB.Y, is(Constants.ED25519_BASEPOINT.Y));
        assertThat(minusB.Z, is(Constants.ED25519_BASEPOINT.Z));
        assertThat(minusB.T, is(Constants.ED25519_BASEPOINT.T.negate()));
    }

    @Test
    public void ctSelectReturnsCorrectResult() {
        assertThat(Constants.ED25519_BASEPOINT.ctSelect(EdwardsPoint.IDENTITY, 0), is(Constants.ED25519_BASEPOINT));
        assertThat(Constants.ED25519_BASEPOINT.ctSelect(EdwardsPoint.IDENTITY, 1), is(EdwardsPoint.IDENTITY));
        assertThat(EdwardsPoint.IDENTITY.ctSelect(Constants.ED25519_BASEPOINT, 0), is(EdwardsPoint.IDENTITY));
        assertThat(EdwardsPoint.IDENTITY.ctSelect(Constants.ED25519_BASEPOINT, 1), is(Constants.ED25519_BASEPOINT));
    }

    @Test
    public void basepointPlusBasepointVsBasepoint2Constant() {
        EdwardsPoint B2 = Constants.ED25519_BASEPOINT.add(Constants.ED25519_BASEPOINT);
        assertThat(B2.compress(), is(BASE2_CMPRSSD));
    }

    @Test
    public void basepointPlusBasepointProjectiveNielsVsBasepoint2Constant() {
        EdwardsPoint B2 = Constants.ED25519_BASEPOINT.add(Constants.ED25519_BASEPOINT.toProjectiveNiels()).toExtended();
        assertThat(B2.compress(), is(EdwardsPointTest.BASE2_CMPRSSD));
    }

    @Test
    public void basepointPlusBasepointAffineNielsVsBasepoint2Constant() {
        EdwardsPoint B2 = Constants.ED25519_BASEPOINT.add(Constants.ED25519_BASEPOINT.toAffineNiels()).toExtended();
        assertThat(B2.compress(), is(EdwardsPointTest.BASE2_CMPRSSD));
    }

    @Test
    public void basepointDoubleVsBasepoint2Constant() {
        EdwardsPoint B2 = Constants.ED25519_BASEPOINT.dbl();
        assertThat(B2.compress(), is(BASE2_CMPRSSD));
    }

    @Test
    public void basepointDoubleMinusBasepoint() {
        EdwardsPoint B2 = Constants.ED25519_BASEPOINT.dbl();
        assertThat(B2.subtract(Constants.ED25519_BASEPOINT), is(Constants.ED25519_BASEPOINT));
    }

    @Test
    public void basepointNegateVsZeroMinusBasepoint() {
        assertThat(Constants.ED25519_BASEPOINT.negate(),
                is(EdwardsPoint.IDENTITY.subtract(Constants.ED25519_BASEPOINT)));
    }

    @Test
    public void scalarMulVsEd25519py() {
        EdwardsPoint aB = Constants.ED25519_BASEPOINT.multiply(A_SCALAR);
        assertThat(aB.compress(), is(A_TIMES_BASEPOINT));
    }

    @Test
    public void testVartimeDoubleScalarMultiplyBasepoint() {
        // Little-endian
        Scalar zero = Scalar.ZERO;
        Scalar one = Scalar.ONE;
        Scalar two = new Scalar(Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000"));
        Scalar a = new Scalar(Utils.hexToBytes("d072f8dd9c07fa7bc8d22a4b325d26301ee9202f6db89aa7c3731529e37e437c"));
        EdwardsPoint A = new CompressedEdwardsY(
                Utils.hexToBytes("d4cf8595571830644bd14af416954d09ab7159751ad9e0f7a6cbd92379e71a66")).decompress();
        EdwardsPoint B = Constants.ED25519_BASEPOINT;
        EdwardsPoint I = EdwardsPoint.IDENTITY;

        // 0 * I + 0 * B = I
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(zero, I, zero), is(I));
        // 1 * I + 0 * B = I
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(one, I, zero), is(I));
        // 1 * I + 1 * B = B
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(one, I, one), is(B));
        // 1 * B + 1 * B = 2 * B
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(one, B, one), is(B.dbl()));
        // 1 * B + 2 * B = 3 * B
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(one, B, two), is(B.dbl().add(B)));
        // 2 * B + 2 * B = 4 * B
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(two, B, two), is(B.dbl().dbl()));

        // 0 * B + a * B = A
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(zero, B, a), is(A));
        // a * B + 0 * B = A
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(a, B, zero), is(A));
        // a * B + a * B = 2 * A
        assertThat(EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(a, B, a), is(A.dbl()));
    }

    @Test
    public void doubleScalarMulBasepointVsEd25519py() {
        EdwardsPoint A = A_TIMES_BASEPOINT.decompress();
        EdwardsPoint result = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(A_SCALAR, A, B_SCALAR);
        assertThat(result.compress(), is(DOUBLE_SCALAR_MULT_RESULT));
    }

    @Test
    public void basepointMulByPow24VsBasepoint16Constant() {
        assertThat(Constants.ED25519_BASEPOINT.multiplyByPow2(4), is(BASE16_CMPRSSD.decompress()));
    }

    @Test
    public void isIdentity() {
        assertTrue(EdwardsPoint.IDENTITY.isIdentity());
        assertFalse(Constants.ED25519_BASEPOINT.isIdentity());
    }

    @Test
    public void isSmallOrder() {
        // The basepoint has large prime order
        assertFalse(Constants.ED25519_BASEPOINT.isSmallOrder());
        // EIGHT_TORSION_COMPRESSED has all points of small order.
        for (int i = 0; i < EIGHT_TORSION_COMPRESSED.length; i++) {
            assertTrue(EIGHT_TORSION_COMPRESSED[i].decompress().isSmallOrder());
        }
    }

    @Test
    public void isTorsionFree() {
        // The basepoint is torsion-free.
        assertTrue(Constants.ED25519_BASEPOINT.isTorsionFree());

        // Adding the identity leaves it torsion-free.
        assertTrue(Constants.ED25519_BASEPOINT.add(EdwardsPoint.IDENTITY).isTorsionFree());

        // Adding any of the 8-torsion points to it (except the identity) affects the
        // result.
        assertThat(EdwardsPoint.IDENTITY.compress(), is(EIGHT_TORSION_COMPRESSED[0]));
        for (int i = 1; i < EIGHT_TORSION_COMPRESSED.length; i++) {
            EdwardsPoint withTorsion = Constants.ED25519_BASEPOINT.add(EIGHT_TORSION_COMPRESSED[i].decompress());
            assertFalse(withTorsion.isTorsionFree());
        }
    }
}
