/*
 * This file is part of curve25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.curve25519;

import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.*;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class ScalarBench {
    public byte[] aBytes;
    public Scalar a;
    public Scalar b;
    public Scalar c;

    @Setup
    public void prepare() {
        byte[] a = new byte[64];
        byte[] b = new byte[64];
        byte[] c = new byte[64];
        Random r = new Random();
        r.nextBytes(a);
        r.nextBytes(b);
        r.nextBytes(c);
        this.aBytes = a;
        this.a = Scalar.fromBytesModOrderWide(a);
        this.b = Scalar.fromBytesModOrderWide(b);
        this.c = Scalar.fromBytesModOrderWide(c);
    }

    @Benchmark
    public Scalar fromBytesModOrderWide() {
        return Scalar.fromBytesModOrderWide(this.aBytes);
    }

    @Benchmark
    public Scalar add() {
        return this.a.add(this.b);
    }

    @Benchmark
    public Scalar subtract() {
        return this.a.subtract(this.b);
    }

    @Benchmark
    public Scalar multiply() {
        return this.a.multiply(this.b);
    }

    @Benchmark
    public Scalar multiplyAndAddManual() {
        return this.a.multiply(this.b).add(this.c);
    }

    @Benchmark
    public Scalar multiplyAndAdd() {
        return this.a.multiplyAndAdd(this.b, this.c);
    }
}
