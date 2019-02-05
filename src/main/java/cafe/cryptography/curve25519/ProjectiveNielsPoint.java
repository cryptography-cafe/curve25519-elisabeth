package cafe.cryptography.curve25519;

/**
 * A pre-computed point on the $\mathbb P^3$ model of the curve, represented as
 * $(Y+X, Y-X, Z, 2dXY)$ in "Niels coordinates".
 */
class ProjectiveNielsPoint {
    final FieldElement YPlusX;
    final FieldElement YMinusX;
    final FieldElement Z;
    final FieldElement T2D;

    ProjectiveNielsPoint(FieldElement YPlusX, FieldElement YMinusX, FieldElement Z, FieldElement T2D) {
        this.YPlusX = YPlusX;
        this.YMinusX = YMinusX;
        this.Z = Z;
        this.T2D = T2D;
    }
}
