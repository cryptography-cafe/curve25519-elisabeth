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

    /**
     * The Ed25519 basepoint, as an EdwardsPoint.
     */
    public static final EdwardsPoint ED25519_BASEPOINT = new EdwardsPoint(
    // @formatter:off
        new FieldElement(new int[] {
            -14297830,  -7645148, 16144683, -16471763, 27570974,
             -2696100, -26142465,  8378389,  20764389,  8758491,
        }),
        new FieldElement(new int[] {
            -26843541,  -6710886, 13421773, -13421773, 26843546,
              6710886, -13421773, 13421773, -26843546, -6710886,
        }),
        new FieldElement(new int[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }),
        new FieldElement(new int[] {
            28827062, -6116119, -27349572,   244363,  8635006,
            11264893, 19351346,  13413597, 16611511, -6414980,
        })
    // @formatter:on
    );
}
