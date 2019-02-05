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
}
