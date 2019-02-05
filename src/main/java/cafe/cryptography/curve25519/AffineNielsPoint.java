package cafe.cryptography.curve25519;

/**
 * A pre-computed point on the affine model of the curve, represented as $(y+x,
 * y-x, 2dxy)$ in "Niels coordinates".
 */
class AffineNielsPoint {
    final FieldElement yPlusx;
    final FieldElement yMinusx;
    final FieldElement xy2D;

    AffineNielsPoint(FieldElement yPlusx, FieldElement yMinusx, FieldElement xy2D) {
        this.yPlusx = yPlusx;
        this.yMinusx = yMinusx;
        this.xy2D = xy2D;
    }
}
