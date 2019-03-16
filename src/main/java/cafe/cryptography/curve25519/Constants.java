/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

/**
 * Various constants and useful parameters.
 */
public final class Constants {
    /**
     * The order of the Ed25519 basepoint, $\ell = 2^{252} +
     * 27742317777372353535851937790883648493$.
     */
    public static final Scalar BASEPOINT_ORDER = new Scalar(new byte[] {
        // @formatter:off
        (byte) 0xed, (byte) 0xd3, (byte) 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        (byte) 0xd6, (byte) 0x9c, (byte) 0xf7, (byte) 0xa2, (byte) 0xde, (byte) 0xf9, (byte) 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        // @formatter:on
    });

    /**
     * The unpacked form of the Ed25519 basepoint order.
     */
    static final UnpackedScalar L = UnpackedScalar.fromByteArray(BASEPOINT_ORDER.toByteArray());

    /**
     * $\ell * \text{LFACTOR} = -1 \bmod 2^29$
     */
    static final int LFACTOR = 0x12547e1b;

    /**
     * `R` = R % L where R = 2^261
     */
    static final UnpackedScalar R = new UnpackedScalar(new int[] { 0x114df9ed, 0x1a617303, 0x0f7c098c, 0x16793167,
            0x1ffd656e, 0x1fffffff, 0x1fffffff, 0x1fffffff, 0x000fffff });

    /**
     * `RR` = (R^2) % L where R = 2^261
     */
    static final UnpackedScalar RR = new UnpackedScalar(new int[] { 0x0b5f9d12, 0x1e141b17, 0x158d7f3d, 0x143f3757,
            0x1972d781, 0x042feb7c, 0x1ceec73d, 0x1e184d1e, 0x0005046d });

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
     * Edwards $-d$ value, equal to $121665/121666 \bmod p$.
     */
    public static final FieldElement NEG_EDWARDS_D = EDWARDS_D.negate();

    /**
     * Edwards $2*d$ value, equal to $2*(-121665/121666) \bmod p$.
     */
    public static final FieldElement EDWARDS_2D = new FieldElement(new int[] {
        // @formatter:off
        -21827239,  -5839606, -30745221, 13898782,  229458,
         15978800, -12551817,  -6495438, 29715968, 9444199,
        // @formatter:on
    });

    /**
     * $= 1 - d^2$, where $d$ is the Edwards curve parameter.
     */
    public static final FieldElement ONE_MINUS_D_SQ = FieldElement.ONE.subtract(EDWARDS_D.square());

    /**
     * $= (d - 1)^2$, where $d$ is the Edwards curve parameter.
     */
    public static final FieldElement D_MINUS_ONE_SQ = EDWARDS_D.subtract(FieldElement.ONE).square();

    /**
     * $= \sqrt{a*d - 1}$, where $a = -1 \bmod p$, $d$ are the Edwards curve
     * parameters.
     */
    public static final FieldElement SQRT_AD_MINUS_ONE = new FieldElement(new int[] {
        // @formatter:off
        24849947,   -153582, -23613485, 6347715, -21072328,
         -667138, -25271143, -15367704, -870347,  14525639,
        // @formatter:on
    });

    /**
     * $= 1/\sqrt{a-d}$, where $a = -1 \bmod p$, $d$ are the Edwards curve
     * parameters.
     */
    public static final FieldElement INVSQRT_A_MINUS_D = new FieldElement(new int[] {
        // @formatter:off
        6111485,  4156064, -27798727, 12243468, -25904040,
         120897, 20826367,  -7060776,  6093568,  -1986012,
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

    /**
     * Table containing pre-computed multiples of the Ed25519 basepoint.
     */
    public static final EdwardsBasepointTable ED25519_BASEPOINT_TABLE = new EdwardsBasepointTable(ED25519_BASEPOINT);

    /**
     * The ristretto255 generator, as a RistrettoElement.
     */
    public static final RistrettoElement RISTRETTO_GENERATOR = new RistrettoElement(ED25519_BASEPOINT);
}
