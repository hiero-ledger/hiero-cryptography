// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libxkcp;

import java.lang.foreign.MemorySegment;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.jcajce.provider.digest.Keccak;
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
public class Keccak256Bench {
    private static final int INVOCATIONS = 10000;

    private static final Libxkcp LIBXKCP = Libxkcp.getInstance();

    private static final Random RANDOM = new Random(394857);

    @State(Scope.Thread)
    public static class KeccakState {
        byte[] msg;

        @Setup(Level.Trial)
        public void setup() throws Throwable {
            msg = new byte[64];
            RANDOM.nextBytes(msg);
        }

        @TearDown(Level.Trial)
        public void tearDown() {}
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void libxkcp(final KeccakState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            // Yes, we do allocate arrays inside the benchmark method
            // because that's what Bouncy Castle Keccak256 does behind the scenes as well.
            final byte[] hashInstance = new byte[LIBXKCP.sizeOfKeccakHashInstance];
            final MemorySegment hashInstanceSeg = MemorySegment.ofArray(hashInstance);
            LIBXKCP.keccakHashInitialize(
                    hashInstanceSeg,
                    Libxkcp.SHA3_256_RATE,
                    Libxkcp.SHA3_256_CAPACITY,
                    Libxkcp.SHA3_256_HASHBITLEN,
                    Libxkcp.SHA3_256_DELIMITED_SUFFIX_ORIGINAL);
            LIBXKCP.keccakHashUpdate(hashInstanceSeg, MemorySegment.ofArray(state.msg), state.msg.length * 8L);

            final byte[] hash = new byte[Libxkcp.SHA3_256_HASHVAL_LENGTH_BYTES];
            blackhole.consume(LIBXKCP.keccakHashFinal(hashInstanceSeg, MemorySegment.ofArray(hash)));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void bouncyCastle(final KeccakState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(new Keccak.Digest256().digest(state.msg));
        }
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(Keccak256Bench.class.getSimpleName())
                .jvmArgs("--enable-native-access=ALL-UNNAMED")
                .addProfiler(GCProfiler.class)
                .build();

        new Runner(opt).run();
    }
}
