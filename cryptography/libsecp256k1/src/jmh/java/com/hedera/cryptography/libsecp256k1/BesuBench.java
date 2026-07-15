// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.CONTEXT;

import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1;
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
public class BesuBench {
    private static final int INVOCATIONS = 10000;

    private static final Random RANDOM = new Random(11111);

    @State(Scope.Thread)
    public static class BesuState {
        LibSecp256k1.secp256k1_pubkey pubKey;

        byte[] sk;
        byte[] pk;

        ByteBuffer pkSerialized;
        byte[] pkSerializedArr;
        ByteBuffer pkSerializedCompressed;
        byte[] pkSerializedCompressedArr;
        LongByReference sizeRef;

        byte[] messageHash32;
        LibSecp256k1.secp256k1_ecdsa_recoverable_signature recoverableSignature;
        LibSecp256k1.secp256k1_ecdsa_signature signature;

        LibSecp256k1.secp256k1_ecdsa_signature normalizedSignature;

        // Scratch buffer
        LibSecp256k1.secp256k1_ecdsa_signature nativeSignature;
        LibSecp256k1.secp256k1_pubkey nativePublicKey;
        byte[] publicKeyInput;

        @Setup(Level.Trial)
        public void setup() throws Throwable {
            pubKey = new LibSecp256k1.secp256k1_pubkey();

            sk = new byte[Libsecp256k1.SECRET_KEY_BYTES];
            pk = new byte[Libsecp256k1.PUBLIC_KEY_BYTES];

            pkSerializedArr = new byte[65];
            pkSerialized = ByteBuffer.wrap(pkSerializedArr);
            pkSerializedCompressed = ByteBuffer.allocate(33);
            pkSerializedCompressedArr = new byte[33];
            sizeRef = new LongByReference(pkSerialized.limit());

            RANDOM.nextBytes(sk);

            LibSecp256k1.secp256k1_ec_pubkey_create(CONTEXT, pubKey, sk);
            System.arraycopy(pubKey.data, 0, pk, 0, pubKey.data.length);

            pkSerialized.clear();
            sizeRef.setValue(pkSerialized.limit());
            LibSecp256k1.secp256k1_ec_pubkey_serialize(
                    CONTEXT, pkSerialized, sizeRef, pubKey, LibSecp256k1.SECP256K1_EC_UNCOMPRESSED);
            pkSerialized.get(0, pkSerializedArr);

            pkSerializedCompressed.clear();
            sizeRef.setValue(pkSerializedCompressed.limit());
            LibSecp256k1.secp256k1_ec_pubkey_serialize(
                    CONTEXT, pkSerializedCompressed, sizeRef, pubKey, LibSecp256k1.SECP256K1_EC_COMPRESSED);
            pkSerializedCompressed.get(0, pkSerializedCompressedArr);

            messageHash32 = new byte[32];
            RANDOM.nextBytes(messageHash32);

            recoverableSignature = new LibSecp256k1.secp256k1_ecdsa_recoverable_signature();
            LibSecp256k1.secp256k1_ecdsa_sign_recoverable(CONTEXT, recoverableSignature, messageHash32, sk, null, null);

            signature = new LibSecp256k1.secp256k1_ecdsa_signature();
            LibSecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
                    CONTEXT, ByteBuffer.wrap(signature.data), new IntByReference(), recoverableSignature);

            normalizedSignature = new LibSecp256k1.secp256k1_ecdsa_signature();
            LibSecp256k1.secp256k1_ecdsa_signature_normalize(CONTEXT, normalizedSignature, signature);

            nativeSignature = new LibSecp256k1.secp256k1_ecdsa_signature();
            nativePublicKey = new LibSecp256k1.secp256k1_pubkey();
            publicKeyInput = new byte[65];
            publicKeyInput[0] = 0x04;
        }

        @TearDown(Level.Trial)
        public void tearDown() {}
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeySerialize_Uncompressed(BesuState state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            state.pkSerialized.clear();
            state.sizeRef.setValue(state.pkSerialized.limit());
            blackhole.consume(LibSecp256k1.secp256k1_ec_pubkey_serialize(
                    CONTEXT, state.pkSerialized, state.sizeRef, state.pubKey, LibSecp256k1.SECP256K1_EC_UNCOMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeySerialize_Compressed(BesuState state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            state.pkSerialized.clear();
            state.sizeRef.setValue(state.pkSerialized.limit());
            blackhole.consume(LibSecp256k1.secp256k1_ec_pubkey_serialize(
                    CONTEXT, state.pkSerialized, state.sizeRef, state.pubKey, LibSecp256k1.SECP256K1_EC_COMPRESSED));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeyParse_Uncompressed(BesuState state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LibSecp256k1.secp256k1_ec_pubkey_parse(CONTEXT, state.pubKey, state.pkSerializedArr, 65));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcPubkeyParse_Compressed(BesuState state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(
                    LibSecp256k1.secp256k1_ec_pubkey_parse(CONTEXT, state.pubKey, state.pkSerializedCompressedArr, 33));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcdsaSignatureNormalize(BesuState state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            blackhole.consume(LibSecp256k1.secp256k1_ecdsa_signature_normalize(
                    CONTEXT, state.normalizedSignature, state.signature));
        }
    }

    @Benchmark
    @OperationsPerInvocation(INVOCATIONS)
    public void secp256k1EcdsaVerify(BesuState state, Blackhole blackhole) {
        for (int i = 0; i < INVOCATIONS; i++) {
            // Logic from EcdsaSecp256k1Verifier.verify()
            LibSecp256k1.secp256k1_ecdsa_signature_parse_compact(CONTEXT, state.nativeSignature, state.signature.data);
            LibSecp256k1.secp256k1_ecdsa_signature_normalize(CONTEXT, state.nativeSignature, state.nativeSignature);
            System.arraycopy(state.pkSerializedArr, 1, state.publicKeyInput, 1, state.pkSerializedArr.length - 1);
            LibSecp256k1.secp256k1_ec_pubkey_parse(
                    CONTEXT, state.nativePublicKey, state.publicKeyInput, state.publicKeyInput.length);
            blackhole.consume(LibSecp256k1.secp256k1_ecdsa_verify(
                    CONTEXT, state.nativeSignature, state.messageHash32, state.nativePublicKey));
        }
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(BesuBench.class.getSimpleName())
                .jvmArgs("--enable-native-access=ALL-UNNAMED")
                .addProfiler(GCProfiler.class)
                .build();

        new Runner(opt).run();
    }
}
