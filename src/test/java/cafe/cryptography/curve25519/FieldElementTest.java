package cafe.cryptography.curve25519;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class FieldElementTest {
    @Test
    public void encodeAndDecodeOnZero() {
        byte[] zero = new byte[32];
        final FieldElement a = FieldElement.fromByteArray(zero);

        assertThat(a, is(FieldElement.ZERO));
        assertThat(a.toByteArray(), is(zero));
    }
}
