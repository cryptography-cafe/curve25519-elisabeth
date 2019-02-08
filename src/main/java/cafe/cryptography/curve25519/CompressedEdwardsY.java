package cafe.cryptography.curve25519;

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
public class CompressedEdwardsY {
    /**
     * The encoded point.
     */
    private final byte[] data;

    public CompressedEdwardsY(byte[] data) {
        if (data.length != 32) {
            throw new IllegalArgumentException("Invalid CompressedEdwardsY encoding");
        }
        this.data = data;
    }

    /**
     * Attempts to decompress to an EdwardsPoint.
     *
     * @return an EdwardsPoint, if this is a valid encoding.
     */
    public EdwardsPoint decompress() {
        FieldElement Y = FieldElement.fromByteArray(data);
        FieldElement YY = Y.square();

        // u = y²-1
        FieldElement u = YY.subtract(FieldElement.ONE);

        // v = dy²+1
        FieldElement v = YY.multiply(Constants.EDWARDS_D).add(FieldElement.ONE);

        FieldElement.SqrtRatioM1 sqrt = FieldElement.sqrtRatioM1(u, v);
        if (sqrt.wasSquare != 1) {
            throw new IllegalArgumentException("not a valid EdwardsPoint");
        }

        FieldElement X = sqrt.result;
        if (sqrt.result.isNegative() != ConstantTime.bit(data, 255)) {
            X = X.negate();
        }

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
