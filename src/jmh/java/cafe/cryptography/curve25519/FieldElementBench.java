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
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class FieldElementBench {
    public FieldElement a;
    public FieldElement b;

    @Setup
    public void prepare() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        Random r = new Random();
        r.nextBytes(a);
        r.nextBytes(b);
        this.a = FieldElement.fromByteArray(a);
        this.b = FieldElement.fromByteArray(b);
    }

    @Benchmark
    public FieldElement add() {
        return this.a.add(this.b);
    }

    @Benchmark
    public void addAssign() {
        this.a.addAssign(this.b);
    }

    @Benchmark
    public FieldElement multiply() {
        return this.a.multiply(this.b);
    }

    @Benchmark
    public void multiplyAssign() {
        this.a.multiplyAssign(this.b);
    }

    @Benchmark
    public FieldElement square() {
        return this.a.square();
    }

    @Benchmark
    public void squareAssign() {
        this.a.squareAssign();
    }

    @Benchmark
    public FieldElement squareAndDouble() {
        return this.a.squareAndDouble();
    }

    @Benchmark
    public void squareAndDoubleAssign() {
        this.a.squareAndDoubleAssign();
    }

    @Benchmark
    public FieldElement invert() {
        return this.a.invert();
    }

    @Benchmark
    public FieldElement.SqrtRatioM1Result sqrtRatioM1() {
        return FieldElement.sqrtRatioM1(this.a, this.b);
    }
}
