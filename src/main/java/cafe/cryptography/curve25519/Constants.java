package cafe.cryptography.curve25519;

/**
 * Various constants and useful parameters.
 */
public final class Constants {
    /**
     * Edwards $d$ value, equal to $-121665/121666 \bmod p$.
     */
    public static final FieldElement EDWARDS_D = new FieldElement(new int[] {
        // @formatter:off
        -10913610, 13857413, -15372611,   6949391,    114729,
         -8787816, -6275908,  -3247719, -18696448, -12055116,
        // @formatter:on
    });

    /**
     * Precomputed value of one of the square roots of -1 (mod p).
     */
    public static final FieldElement SQRT_M1 = new FieldElement(new int[] {
        // @formatter:off
        -32595792,  -7943725,  9377950, 3500415, 12389472,
          -272473, -25146209, -2005654,  326686, 11406482,
        // @formatter:on
    });
}
