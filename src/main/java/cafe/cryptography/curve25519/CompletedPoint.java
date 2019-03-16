/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

/**
 * A point $((X:Z), (Y:T))$ on the $\mathbb P^1 \times \mathbb P^1$ model of the
 * curve.
 */
class CompletedPoint {
    final FieldElement X;
    final FieldElement Y;
    final FieldElement Z;
    final FieldElement T;

    CompletedPoint(FieldElement X, FieldElement Y, FieldElement Z, FieldElement T) {
        this.X = X;
        this.Y = Y;
        this.Z = Z;
        this.T = T;
    }

    /**
     * Convert this point from the $\mathbb P^1 \times \mathbb P^1$ model to the
     * $\mathbb P^2$ model.
     * <p>
     * This costs $3 \mathrm M$.
     */
    ProjectivePoint toProjective() {
        return new ProjectivePoint(this.X.multiply(this.T), Y.multiply(this.Z), this.Z.multiply(this.T));
    }

    /**
     * Convert this point from the $\mathbb P^1 \times \mathbb P^1$ model to the
     * $\mathbb P^3$ model.
     * <p>
     * This costs $4 \mathrm M$.
     */
    EdwardsPoint toExtended() {
        return new EdwardsPoint(this.X.multiply(this.T), Y.multiply(this.Z), this.Z.multiply(this.T),
                this.X.multiply(this.Y));
    }
}
