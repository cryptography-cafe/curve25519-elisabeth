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
    public void basepointMulByPow24VsBasepoint16Constant() {
        assertThat(Constants.ED25519_BASEPOINT.multiplyByPow2(4), is(BASE16_CMPRSSD.decompress()));
    }

    @Test
    public void isIdentity() {
        assertTrue(EdwardsPoint.IDENTITY.isIdentity());
        assertFalse(Constants.ED25519_BASEPOINT.isIdentity());
    }
}
