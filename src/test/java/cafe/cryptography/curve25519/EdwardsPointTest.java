package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class EdwardsPointTest {
    @Test
    public void basepointDecompressionCompression() {
        CompressedEdwardsY encoded = new CompressedEdwardsY(
                Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"));
        EdwardsPoint B = encoded.decompress();
        assertThat(B.compress(), is(encoded));
    }
}
