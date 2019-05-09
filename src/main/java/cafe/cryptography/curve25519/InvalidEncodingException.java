/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

/**
 * Thrown to indicate that a {@link CompressedEdwardsY} or
 * {@link CompressedRistretto} was an invalid encoding of an
 * {@link EdwardsPoint} or {@link RistrettoElement}.
 */
public class InvalidEncodingException extends Exception {
    private static final long serialVersionUID = 1L;

    InvalidEncodingException(String msg) {
        super(msg);
    }
}
