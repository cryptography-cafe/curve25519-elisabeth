package cafe.cryptography.curve25519;

import java.util.Arrays;

import cafe.cryptography.subtle.ConstantTime;

/**
 * A Ristretto point in compressed wire format.
 * <p>
 * The Ristretto encoding is canonical, so two points are equal if and only if
 * their encodings are equal.
 */
public class CompressedRistretto {
    /**
     * The encoded point.
     */
    private final byte[] data;

    public CompressedRistretto(byte[] data) {
        if (data.length != 32) {
            throw new IllegalArgumentException("Invalid CompressedRistretto encoding");
        }
        this.data = data;
    }

    /**
     * Attempts to decompress to a RistrettoElement.
     *
     * @return a RistrettoElement, if this is the canonical encoding of an element
     *         of the ristretto255 group.
     */
    public RistrettoElement decompress() {
        throw new UnsupportedOperationException();
    }

    /**
     * Encode the element to its compressed 32-byte form.
     *
     * @return the encoded element.
     */
    public byte[] toByteArray() {
        return data;
    }

    /**
     * Constant-time equality check.
     *
     * @return 1 if this and other are equal, 0 otherwise.
     */
    public int ctEquals(CompressedRistretto other) {
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
        if (!(obj instanceof CompressedRistretto)) {
            return false;
        }

        CompressedRistretto other = (CompressedRistretto) obj;
        return ctEquals(other) == 1;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(data);
    }
}
