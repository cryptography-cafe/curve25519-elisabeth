package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class ConstantsTest {
    @Test
    public void checkEdwardsD() {
        assertThat(Constants.EDWARDS_D, is(FieldElement
                .fromByteArray(Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"))));
    }

    @Test
    public void checkSqrtM1() {
        assertThat(Constants.SQRT_M1, is(FieldElement
                .fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))));
    }

    @Test
    public void checkEd25519Basepoint() {
        CompressedEdwardsY encoded = new CompressedEdwardsY(
                Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"));
        EdwardsPoint B = encoded.decompress();
        assertThat(Constants.ED25519_BASEPOINT.X, is(B.X));
        assertThat(Constants.ED25519_BASEPOINT.Y, is(B.Y));
        assertThat(Constants.ED25519_BASEPOINT.Z, is(B.Z));
        assertThat(Constants.ED25519_BASEPOINT.T, is(B.T));
    }
}
