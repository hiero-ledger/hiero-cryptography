// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsodium;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.interfaces.Sign;
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
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/// A separate LazySodium bench to prevent loading both our and their native libs into the JVM.
@SuppressWarnings("unused")
@State(Scope.Benchmark)
@Fork(3)
@Warmup(iterations = 3)
@Measurement(iterations = 5)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.Throughput)
public class LazysodiumBench {
    private static final int INVOCATIONS = 10000;

    static final Sign.Native LAZYSODIUM = new LazySodiumJava(new SodiumJava());

    /// Non-deterministic because JMH is multithreaded and non-deterministic.
    /// The non-determinism shouldn't affect the benchmark.
    private static final Random RANDOM = new Random();

    @State(Scope.Thread)
    public static class LazysodiumState {
        byte[] msg;
        byte[] pk;
        byte[] sk;
        byte[] sig;

        @Setup(Level.Trial)
        public void setup() throws Throwable {
            msg = new byte[64];
            RANDOM.nextBytes(msg);

            pk = new byte[32];
            sk = new byte[64];
            LAZYSODIUM.cryptoSignKeypair(pk, sk);

            sig = new byte[64];

            LAZYSODIUM.cryptoSignDetached(sig, msg, msg.length, sk);
        }

        @TearDown(Level.Trial)
        public void tearDown() {}
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignDetached(final LazysodiumState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LAZYSODIUM.cryptoSignDetached(state.sig, state.msg, state.msg.length, state.sk));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void cryptoSignVerifyDetached(final LazysodiumState state, final Blackhole blackhole) throws Throwable {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LAZYSODIUM.cryptoSignVerifyDetached(state.sig, state.msg, state.msg.length, state.pk));
        }
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(LazysodiumBench.class.getSimpleName())
                .jvmArgs("--enable-native-access=ALL-UNNAMED")
                .addProfiler(GCProfiler.class)
                .build();

        new Runner(opt).run();
    }
}
