// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

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
public class Libsecp256k1Bench {
    private static final int INVOCATIONS = 10000;

    private static final ContextualLibsecp256k1 INSTANCE = ContextualLibsecp256k1.getInstance();

    private static final Random RANDOM = new Random(11111);

    @State(Scope.Thread)
    public static class Libsecp256k1State {
        byte[] sk;
        byte[] pk;

        MemorySegment pkSeg;
        MemorySegment skSeg;

        byte[] pkSerialized;
        byte[] pkSerializedCompressed;
        long[] sizeArr;

        byte[] messageHash32;
        byte[] recoverableSignature;
        byte[] signature;
        int[] recId;

        byte[] normalizedSignature;

        // Scratch buffer
        byte[] nativeSignature;
        byte[] nativePublicKey;
        byte[] publicKeyInput;

        @Setup(Level.Trial)
        public void setup() throws Throwable {
            sk = new byte[Libsecp256k1.SECRET_KEY_BYTES];
            pk = new byte[Libsecp256k1.PUBLIC_KEY_BYTES];

            pkSeg = MemorySegment.ofArray(pk);
            skSeg = MemorySegment.ofArray(sk);

            pkSerialized = new byte[65];
            pkSerializedCompressed = new byte[33];
            sizeArr = new long[1];

            RANDOM.nextBytes(sk);

            INSTANCE.secp256k1EcPubkeyCreate(pkSeg, skSeg);

            sizeArr[0] = pkSerialized.length;
            INSTANCE.secp256k1EcPubkeySerialize(
                    MemorySegment.ofArray(pkSerialized),
                    MemorySegment.ofArray(sizeArr),
                    pkSeg,
                    Libsecp256k1.SECP256K1_EC_UNCOMPRESSED);

            sizeArr[0] = pkSerializedCompressed.length;
            INSTANCE.secp256k1EcPubkeySerialize(
                    MemorySegment.ofArray(pkSerializedCompressed),
                    MemorySegment.ofArray(sizeArr),
                    pkSeg,
                    Libsecp256k1.SECP256K1_EC_COMPRESSED);

            messageHash32 = new byte[32];
            RANDOM.nextBytes(messageHash32);

            recoverableSignature = new byte[65];
            INSTANCE.secp256k1EcdsaSignRecoverable(
                    MemorySegment.ofArray(recoverableSignature),
                    MemorySegment.ofArray(messageHash32),
                    skSeg,
                    MemorySegment.NULL,
                    MemorySegment.NULL);

            signature = new byte[64];
            recId = new int[1];
            INSTANCE.secp256k1EcdsaRecoverableSignatureSerializeCompact(
                    MemorySegment.ofArray(signature),
                    MemorySegment.ofArray(recId),
                    MemorySegment.ofArray(recoverableSignature));

            normalizedSignature = new byte[64];
            INSTANCE.secp256k1EcdsaSignatureNormalize(
                    MemorySegment.ofArray(normalizedSignature), MemorySegment.ofArray(signature));

            nativeSignature = new byte[Libsecp256k1.SIGNATURE_BYTES];
            nativePublicKey = new byte[Libsecp256k1.PUBLIC_KEY_BYTES];
            publicKeyInput = new byte[65];
            publicKeyInput[0] = 0x04;
        }

        @TearDown(Level.Trial)
        public void tearDown() {}
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeySerialize_Uncompressed(Libsecp256k1State state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            state.sizeArr[0] = state.pkSerialized.length;
            blackhole.consume(INSTANCE.secp256k1EcPubkeySerialize(
                    MemorySegment.ofArray(state.pkSerialized),
                    MemorySegment.ofArray(state.sizeArr),
                    MemorySegment.ofArray(state.pk),
                    Libsecp256k1.SECP256K1_EC_UNCOMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeySerialize_Compressed(Libsecp256k1State state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            state.sizeArr[0] = state.pkSerialized.length;
            blackhole.consume(INSTANCE.secp256k1EcPubkeySerialize(
                    MemorySegment.ofArray(state.pkSerialized),
                    MemorySegment.ofArray(state.sizeArr),
                    MemorySegment.ofArray(state.pk),
                    Libsecp256k1.SECP256K1_EC_COMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeyParse_Uncompressed(Libsecp256k1State state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(INSTANCE.secp256k1EcPubkeyParse(
                    MemorySegment.ofArray(state.pk), MemorySegment.ofArray(state.pkSerialized), 65));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeyParse_Compressed(Libsecp256k1State state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(INSTANCE.secp256k1EcPubkeyParse(
                    MemorySegment.ofArray(state.pk), MemorySegment.ofArray(state.pkSerializedCompressed), 33));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcdsaSignatureNormalize(Libsecp256k1State state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(INSTANCE.secp256k1EcdsaSignatureNormalize(
                    MemorySegment.ofArray(state.normalizedSignature), MemorySegment.ofArray(state.signature)));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcdsaVerify(Libsecp256k1State state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            // Logic from EcdsaSecp256k1Verifier.verify()
            final MemorySegment nativeSignatureSeg = MemorySegment.ofArray(state.nativeSignature);
            final MemorySegment nativePublicKeySeg = MemorySegment.ofArray(state.nativePublicKey);

            INSTANCE.secp256k1EcdsaSignatureParseCompact(nativeSignatureSeg, MemorySegment.ofArray(state.signature));
            INSTANCE.secp256k1EcdsaSignatureNormalize(nativeSignatureSeg, nativeSignatureSeg);
            System.arraycopy(state.pkSerialized, 1, state.publicKeyInput, 1, state.pkSerialized.length - 1);
            INSTANCE.secp256k1EcPubkeyParse(
                    nativePublicKeySeg, MemorySegment.ofArray(state.publicKeyInput), state.publicKeyInput.length);
            blackhole.consume(INSTANCE.secp256k1EcdsaVerify(
                    nativeSignatureSeg, MemorySegment.ofArray(state.messageHash32), nativePublicKeySeg));
        }
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(Libsecp256k1Bench.class.getSimpleName())
                .jvmArgs("--enable-native-access=ALL-UNNAMED")
                .addProfiler(GCProfiler.class)
                .build();

        new Runner(opt).run();
    }
}
