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
public class RistrettoElementBench {
    public byte[] bytesWide = new byte[64];
    public RistrettoElement P;
    public CompressedRistretto Penc;
    public RistrettoGeneratorTable Pt;
    public RistrettoElement Q;
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
        r.nextBytes(this.bytesWide);
        this.P = Constants.RISTRETTO_GENERATOR.multiply(randomScalar(r));
        this.Penc = this.P.compress();
        this.Pt = new RistrettoGeneratorTable(this.P);
        this.Q = Constants.RISTRETTO_GENERATOR.multiply(randomScalar(r));
        this.a = randomScalar(r);
        this.b = randomScalar(r);
    }

    @Benchmark
    public RistrettoElement fromUniformBytes() {
        return RistrettoElement.fromUniformBytes(this.bytesWide);
    }

    @Benchmark
    public RistrettoElement decompress() {
        return this.Penc.decompress();
    }

    @Benchmark
    public CompressedRistretto compress() {
        return this.P.compress();
    }

    @Benchmark
    public RistrettoElement add() {
        return this.P.add(this.Q);
    }

    @Benchmark
    public RistrettoElement dbl() {
        return this.P.dbl();
    }

    @Benchmark
    public RistrettoElement variableBaseScalarMultiply() {
        return this.P.multiply(this.a);
    }

    @Benchmark
    public RistrettoElement fixedBaseScalarMultiply() {
        return this.Pt.multiply(this.a);
    }
}
