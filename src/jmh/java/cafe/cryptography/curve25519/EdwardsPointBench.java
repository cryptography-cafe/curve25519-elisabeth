/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class EdwardsPointBench {
    public EdwardsPoint P;
    public EdwardsBasepointTable Pt;
    public EdwardsPoint Q;
    public Scalar a;
    public Scalar b;

    static Scalar randomScalar(Random r) {
        byte[] input = new byte[64];
        r.nextBytes(input);
        return Scalar.fromBytesModOrderWide(input);
    }

    @Setup
    public void prepare() {
        Random r = new Random();
        this.P = Constants.ED25519_BASEPOINT.multiply(randomScalar(r));
        this.Pt = new EdwardsBasepointTable(this.P);
        this.Q = Constants.ED25519_BASEPOINT.multiply(randomScalar(r));
        this.a = randomScalar(r);
        this.b = randomScalar(r);
    }

    @Benchmark
    public EdwardsPoint add() {
        return this.P.add(this.Q);
    }

    @Benchmark
    public EdwardsPoint dbl() {
        return this.P.dbl();
    }

    @Benchmark
    public EdwardsPoint variableBaseScalarMultiply() {
        return this.P.multiply(this.a);
    }

    @Benchmark
    public EdwardsPoint fixedBaseScalarMultiply() {
        return this.Pt.multiply(this.a);
    }

    @Benchmark
    public EdwardsPoint doubleScalarMultiplyBasepoint() {
        return EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(this.a, this.P, this.b);
    }
}
