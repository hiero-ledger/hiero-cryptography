// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptogaphy.wraps;

import com.hedera.cryptography.hints.AggregationAndVerificationKeys;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import com.hedera.cryptography.wraps.SchnorrKeys;
import com.hedera.cryptography.wraps.WRAPSLibraryBridge;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
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
@Fork(1)
@Warmup(iterations = 1, time = 2, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 2, time = 2, timeUnit = TimeUnit.SECONDS)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class SignatureBench {
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();

    private static final Random RANDOM = new Random();

    /// Non-deterministic because JMH is multithreaded and non-deterministic.
    /// The non-determinism shouldn't affect the benchmark.
    private static byte[] generateRandom32() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] MESSAGE = generateRandom32();

    private static byte[][] listToArray(List<byte[]> list) {
        return list.toArray(new byte[list.size()][]);
    }

    public record Node(byte[] seed, SchnorrKeys schnorrKeys, long weight, long nodeId, byte[] hintsSecretKey) {
        public static Node from(byte[] seed, long weight, int partyId) {
            final byte[] hintsSecretKey = HINTS.generateSecretKey(seed);
            return new Node(
                    seed,
                    WRAPS.generateSchnorrKeys(seed),
                    weight,
                    partyId, // use partyId as nodeId
                    hintsSecretKey);
        }
    }

    public record Network(List<Node> nodes) {
        public byte[][] publicKeys() {
            return listToArray(
                    nodes.stream().map(n -> n.schnorrKeys().publicKey()).toList());
        }

        public long[] weights() {
            return nodes.stream().mapToLong(Node::weight).toArray();
        }

        public long[] nodeIds() {
            return nodes.stream().mapToLong(Node::nodeId).toArray();
        }

        public int[] intNodeIds() {
            return nodes.stream().mapToInt(node -> (int) node.nodeId).toArray();
        }
    }

    @State(Scope.Thread)
    public static class HintsState {
        // Domain sizes include the reserved slot and support up to HintsLibraryBridge.MAX_SIGNERS_NUM signers.
        @Param({"4", "8", "16", "32", "64"})
        short crsSize;

        /// false - do 3 signers, true - do (crsSize/2 + 1) signers
        @Param({"false", "true"})
        boolean fullNumOfSigners;

        byte[] crs;
        int numOfSigners;
        Network network;
        AggregationAndVerificationKeys hintsKeys;
        byte[][] blsSignatures;

        @Setup(Level.Trial)
        public void setup() {
            // New CRS, new AggregationKey:
            HINTS.resetCache();

            crs = HINTS.initCRS(crsSize);
            numOfSigners = fullNumOfSigners ? (crsSize / 2 + 1) : 3;

            network = new Network(IntStream.range(0, numOfSigners)
                    .mapToObj(i -> Node.from(generateRandom32(), 666, i))
                    .toList());

            blsSignatures = network.nodes().stream()
                    .map(node -> HINTS.signBls(MESSAGE, node.hintsSecretKey()))
                    .toList()
                    .toArray(new byte[numOfSigners][]);

            hintsKeys = HINTS.preprocess(
                    crs,
                    network.intNodeIds(),
                    network.nodes().stream()
                            .map(node -> HINTS.computeHints(crs, node.hintsSecretKey(), (int) node.nodeId(), crsSize))
                            .toList()
                            .toArray(new byte[numOfSigners][]),
                    network.weights(),
                    crsSize);
        }

        @TearDown(Level.Trial)
        public void tearDown() {}
    }

    @Benchmark
    public void benchAggregateSignature(final HintsState state, final Blackhole blackhole) {
        blackhole.consume(HINTS.aggregateSignatures(
                state.crs,
                state.hintsKeys.aggregationKey(),
                state.hintsKeys.verificationKey(),
                state.network.intNodeIds(),
                state.blsSignatures));
    }

    @Benchmark
    public void benchVerifyBls(final HintsState state, final Blackhole blackhole) {
        final int i = RANDOM.nextInt(state.numOfSigners);
        blackhole.consume(HINTS.verifyBls(state.blsSignatures[i], MESSAGE, state.hintsKeys.aggregationKey(), i));
    }

    public static void main(String[] args) throws Exception {
        Options opt = new OptionsBuilder()
                .include(SignatureBench.class.getSimpleName())
                .build();

        new Runner(opt).run();
    }
}
