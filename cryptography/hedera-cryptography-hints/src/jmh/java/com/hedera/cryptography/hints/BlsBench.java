// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@SuppressWarnings("unused")
@State(Scope.Benchmark)
@Fork(3)
@Warmup(iterations = 3)
@Measurement(iterations = 5)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.Throughput)
public class BlsBench {
    private static final int INVOCATIONS = 10000;

    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void arkBls_G1(final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(HINTS.decompressG1ToEip2537(BlsConstants.G1_COMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void blst_G1(final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(HINTS.decompressG1ToEip2537Blst(BlsConstants.G1_COMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void arkBls_G2(final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(HINTS.decompressG2ToEip2537(BlsConstants.G2_COMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void blst_G2(final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(HINTS.decompressG2ToEip2537Blst(BlsConstants.G2_COMPRESSED));
        }
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(BlsBench.class.getSimpleName())
                .jvmArgs("--enable-native-access=ALL-UNNAMED")
                .addProfiler(GCProfiler.class)
                .build();

        new Runner(opt).run();
    }
}
