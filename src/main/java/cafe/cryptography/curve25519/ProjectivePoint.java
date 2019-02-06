package cafe.cryptography.curve25519;

/**
 * A point $(X:Y:Z)$ on the $\mathbb P^2$ model of the curve.
 */
class ProjectivePoint {
    final FieldElement X;
    final FieldElement Y;
    final FieldElement Z;

    ProjectivePoint(FieldElement X, FieldElement Y, FieldElement Z) {
        this.X = X;
        this.Y = Y;
        this.Z = Z;
    }

    /**
     * Convert this point from the $\mathbb P^2$ model to the $\mathbb P^3$ model.
     * <p>
     * This costs $3 \mathrm M + 1 \mathrm S$.
     */
    EdwardsPoint toExtended() {
        return new EdwardsPoint(this.X.multiply(this.Z), Y.multiply(this.Z), this.Z.square(), this.X.multiply(this.Y));
    }

    /**
     * Point doubling: add this point to itself.
     *
     * @return $[2]P$ as a CompletedPoint.
     */
    CompletedPoint dbl() {
        FieldElement XX = this.X.square();
        FieldElement YY = this.Y.square();
        FieldElement ZZ2 = this.Z.squareAndDouble();
        FieldElement XPlusY = this.X.add(this.Y);
        FieldElement XPlusYSq = XPlusY.square();
        FieldElement YYPlusXX = YY.add(XX);
        FieldElement YYMinusXX = YY.subtract(XX);
        return new CompletedPoint(XPlusYSq.subtract(YYPlusXX), YYPlusXX, YYMinusXX, ZZ2.subtract(YYMinusXX));
    }
}
