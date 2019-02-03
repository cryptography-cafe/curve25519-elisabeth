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

    @Test
    public void ctSelectReturnsCorrectResult() {
        int[] a_t = new int[10];
        int[] b_t = new int[10];
        for (int i = 0; i < 10; i++) {
            a_t[i] = i;
            b_t[i] = 10 - i;
        }

        final FieldElement a = new FieldElement(a_t);
        final FieldElement b = new FieldElement(b_t);

        assertThat(a.ctSelect(b, 0), is(a));
        assertThat(a.ctSelect(b, 1), is(b));
        assertThat(b.ctSelect(a, 0), is(b));
        assertThat(b.ctSelect(a, 1), is(a));
    }
}
