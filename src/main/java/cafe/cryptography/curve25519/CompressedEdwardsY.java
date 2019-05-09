/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.Arrays;

import cafe.cryptography.subtle.ConstantTime;

/**
 * An Edwards point encoded in "Edwards y" / "Ed25519" format.
 * <p>
 * In "Edwards y" / "Ed25519" format, the curve point $(x, y)$ is determined by
 * the $y$-coordinate and the sign of $x$.
 * <p>
 * The first 255 bits of a CompressedEdwardsY represent the $y$-coordinate. The
 * high bit of the 32nd byte represents the sign of $x$.
 */
public class CompressedEdwardsY implements Serializable {
    private static final long serialVersionUID = 1L;

    /**
     * The encoded point.
     */
    private transient final byte[] data;

    public CompressedEdwardsY(byte[] data) {
        if (data.length != 32) {
            throw new IllegalArgumentException("Invalid CompressedEdwardsY encoding");
        }
        this.data = data;
    }

    /**
     * Overrides class serialization to use the canonical encoded format.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        out.write(this.toByteArray());
    }

    /**
     * Overrides class serialization to use the canonical encoded format.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        byte[] encoded = new byte[32];
        in.readFully(encoded);

        // CompressedEdwardsY fields are all final, so we need to carefully set them.
        Field fieldData = null;
        try {
            fieldData = CompressedEdwardsY.class.getDeclaredField("data");
            fieldData.setAccessible(true);
            fieldData.set(this, encoded);
        } catch (NoSuchFieldException nsfe) {
            // Should never occur, but just in case...
            throw new IOException(nsfe);
        } catch (IllegalAccessException iae) {
            // Could occur if a SecurityManager is enabled.
            throw new IOException(iae);
        } finally {
            // Ensure the fields are always set back to final if there is a chance
            // they might have been made accessible.
            if (fieldData != null) {
                fieldData.setAccessible(false);
            }
        }
    }

    @SuppressWarnings("unused")
    private void readObjectNoData() throws ObjectStreamException {
        throw new InvalidObjectException("Cannot deserialize CompressedEdwardsY from no data");
    }

    /**
     * Attempts to decompress to an EdwardsPoint.
     *
     * @return an EdwardsPoint, if this is a valid encoding.
     * @throws InvalidEncodingException if this is an invalid encoding.
     */
    public EdwardsPoint decompress() throws InvalidEncodingException {
        FieldElement Y = FieldElement.fromByteArray(data);
        FieldElement YY = Y.square();

        // u = y²-1
        FieldElement u = YY.subtract(FieldElement.ONE);

        // v = dy²+1
        FieldElement v = YY.multiply(Constants.EDWARDS_D).add(FieldElement.ONE);

        FieldElement.SqrtRatioM1Result sqrt = FieldElement.sqrtRatioM1(u, v);
        if (sqrt.wasSquare != 1) {
            throw new InvalidEncodingException("not a valid EdwardsPoint");
        }

        FieldElement X = sqrt.result.negate().ctSelect(sqrt.result,
                ConstantTime.equal(sqrt.result.isNegative(), ConstantTime.bit(data, 255)));

        return new EdwardsPoint(X, Y, FieldElement.ONE, X.multiply(Y));
    }

    /**
     * Encode the point to its compressed 32-byte form.
     *
     * @return the encoded point.
     */
    public byte[] toByteArray() {
        return data;
    }

    /**
     * Constant-time equality check.
     *
     * @return 1 if this and other are equal, 0 otherwise.
     */
    public int ctEquals(CompressedEdwardsY other) {
        return ConstantTime.equal(data, other.data);
    }

    /**
     * Equality check overridden to be constant-time.
     * <p>
     * Fails fast if the objects are of different types.
     *
     * @return true if this and other are equal, false otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CompressedEdwardsY)) {
            return false;
        }

        CompressedEdwardsY other = (CompressedEdwardsY) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
