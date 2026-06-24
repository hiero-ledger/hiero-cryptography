// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsodium;

import java.lang.foreign.MemorySegment;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@SuppressWarnings("unused")
@State(Scope.Benchmark)
@Fork(3)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.Throughput)
public class LibsodiumBench {
    private static final int INVOCATIONS = 10000;

    private static final Libsodium LIBSODIUM = Libsodium.getInstance();

    /// Non-deterministic because JMH is multithreaded and non-deterministic.
    /// The non-determinism shouldn't affect the benchmark.
    private static final Random RANDOM = new Random();

    @State(Scope.Thread)
    public static class LibsodiumState {
        byte[] msg;
        byte[] pk;
        byte[] sk;
        byte[] sig;

        MemorySegment msgSeg;
        MemorySegment pkSeg;
        MemorySegment skSeg;
        MemorySegment sigSeg;

        @Setup(Level.Trial)
        public void setup() throws Throwable {
            msg = new byte[64];
            RANDOM.nextBytes(msg);

            pk = new byte[32];
            sk = new byte[64];
            LIBSODIUM.cryptoSignKeypair(MemorySegment.ofArray(pk), MemorySegment.ofArray(sk));

            sig = new byte[64];

            msgSeg = MemorySegment.ofArray(msg);
            pkSeg = MemorySegment.ofArray(pk);
            skSeg = MemorySegment.ofArray(sk);
            sigSeg = MemorySegment.ofArray(sig);

            LIBSODIUM.cryptoSignDetached(sigSeg, MemorySegment.NULL, msgSeg, msg.length, skSeg);
        }

        @TearDown(Level.Trial)
        public void tearDown() {}
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignDetached(final LibsodiumState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignDetached(
                    MemorySegment.ofArray(state.sig),
                    MemorySegment.NULL,
                    MemorySegment.ofArray(state.msg),
                    state.msg.length,
                    MemorySegment.ofArray(state.sk)));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignDetached_MemorySegments(final LibsodiumState state, final Blackhole blackhole)
            throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignDetached(
                    state.sigSeg, MemorySegment.NULL, state.msgSeg, state.msg.length, state.skSeg));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignDetachedNoChecks(final LibsodiumState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignDetachedNoChecks(
                    MemorySegment.ofArray(state.sig),
                    MemorySegment.NULL,
                    MemorySegment.ofArray(state.msg),
                    state.msg.length,
                    MemorySegment.ofArray(state.sk)));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignDetachedNoChecks_MemorySegments(final LibsodiumState state, final Blackhole blackhole)
            throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignDetachedNoChecks(
                    state.sigSeg, MemorySegment.NULL, state.msgSeg, state.msg.length, state.skSeg));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignVerifyDetached(final LibsodiumState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignVerifyDetached(
                    MemorySegment.ofArray(state.sig),
                    MemorySegment.ofArray(state.msg),
                    state.msg.length,
                    MemorySegment.ofArray(state.pk)));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignVerifyDetached_MemorySegments(final LibsodiumState state, final Blackhole blackhole)
            throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(
                    LIBSODIUM.cryptoSignVerifyDetached(state.sigSeg, state.msgSeg, state.msg.length, state.pkSeg));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignVerifyDetachedNoChecks(final LibsodiumState state, final Blackhole blackhole)
            throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignVerifyDetachedNoChecks(
                    MemorySegment.ofArray(state.sig),
                    MemorySegment.ofArray(state.msg),
                    state.msg.length,
                    MemorySegment.ofArray(state.pk)));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignVerifyDetachedNoChecks_MemorySegments(final LibsodiumState state, final Blackhole blackhole)
            throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LIBSODIUM.cryptoSignVerifyDetachedNoChecks(
                    state.sigSeg, state.msgSeg, state.msg.length, state.pkSeg));
        }
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(LibsodiumBench.class.getSimpleName())
                .jvmArgs("--enable-native-access=ALL-UNNAMED")
                .build();

        new Runner(opt).run();
    }
}
