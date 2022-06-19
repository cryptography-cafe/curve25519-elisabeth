/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.junit.*;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class CompressedEdwardsYTest {
    @Test
    public void constructorDoesNotThrowOnCorrectLength() {
        new CompressedEdwardsY(new byte[32]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorThrowsOnTooShort() {
        new CompressedEdwardsY(new byte[31]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorThrowsOnTooLong() {
        new CompressedEdwardsY(new byte[33]);
    }

    @Test
    public void serializeDeserialize() throws IOException, ClassNotFoundException {
        byte[] s = new byte[32];
        s[0] = 0x1f;
        CompressedEdwardsY expected = new CompressedEdwardsY(s);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(expected);
        oos.close();
        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bais);
        CompressedEdwardsY actual = (CompressedEdwardsY) ois.readObject();
        assertThat(actual, is(expected));
    }

    @Test
    public void toByteArray() {
        byte[] s = new byte[32];
        s[0] = 0x1f;
        assertThat(new CompressedEdwardsY(s).toByteArray(), is(s));
    }
}
