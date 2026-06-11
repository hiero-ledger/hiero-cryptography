// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hedera.cryptography.hints.AggregationAndVerificationKeys;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class WRAPSLibraryBridgeTest {
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final byte[][] EMPTY_BYTE_ARRAY_2 = new byte[0][];

    // We use ABs with 4 and 5 entries, so 8 should be good.
    private static final int SIGNERS_NUM = 8;

    private static final byte[] CRS;

    static {
        byte[] crs = HINTS.initCRS((short) SIGNERS_NUM);
        CRS = HINTS.updateCRS(crs, Constants.CRS_RANDOM);
    }

    public record Node(
            byte[] seed, SchnorrKeys schnorrKeys, long weight, long nodeId, byte[] hintsSecretKey, byte[] hints) {
        public static Node from(byte[] seed, long weight, int partyId) {
            final byte[] hintsSecretKey = HINTS.generateSecretKey(seed);
            return new Node(
                    seed,
                    WRAPS.generateSchnorrKeys(seed),
                    weight,
                    partyId, // use partyId as nodeId
                    hintsSecretKey,
                    HINTS.computeHints(CRS, hintsSecretKey, partyId, SIGNERS_NUM));
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
    }

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    public void testGenerateSchnorrKeys() {
        final SchnorrKeys schnorrKeys = WRAPS.generateSchnorrKeys(Constants.SEED_0);

        assertArrayEquals(Constants.SCHNORR_PRIVATE_KEY_0, schnorrKeys.privateKey());
        assertArrayEquals(Constants.SCHNORR_PUBLIC_KEY_0, schnorrKeys.publicKey());

        // Verify if a different seed generates different keys:
        final SchnorrKeys keys1 = WRAPS.generateSchnorrKeys(Constants.SEED_1);
        assertFalse(Arrays.equals(keys1.privateKey(), schnorrKeys.privateKey()));
        assertFalse(Arrays.equals(keys1.publicKey(), schnorrKeys.publicKey()));
    }

    @Test
    public void testProvideSentinelPublicKey() {
        final byte[] key = WRAPS.provideSentinelPublicKey();

        assertArrayEquals(Constants.SENTINEL_KEY, key);

        // Also check if it's deterministic as it should be:
        final byte[] key2 = WRAPS.provideSentinelPublicKey();

        assertArrayEquals(Constants.SENTINEL_KEY, key2);
    }

    @Test
    public void testGenerateSchnorrKeysConstraints() {
        assertEquals(null, WRAPS.generateSchnorrKeys(null));
        assertEquals(null, WRAPS.generateSchnorrKeys(new byte[0]));

        // length less than ENTROPY_SIZE:
        assertEquals(null, WRAPS.generateSchnorrKeys(new byte[] {1, 2, 3}));

        // length greater than ENTROPY_SIZE:
        byte[] tooLargeArray = new byte[WRAPSLibraryBridge.ENTROPY_SIZE + 3];
        assertEquals(null, WRAPS.generateSchnorrKeys(tooLargeArray));
    }

    private static byte[][] listToArray(List<byte[]> list) {
        return list.toArray(new byte[list.size()][]);
    }

    public record SigningProtocolOutput(byte[] signature, List<List<byte[]>> roundMessages) {}

    public static SigningProtocolOutput aggregateSignature(final Network network, final byte[] message) {
        final boolean[] signers = new boolean[network.publicKeys().length];
        Arrays.fill(signers, true);

        final List<byte[]> round1 = network.nodes().stream()
                .map(node -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R1,
                        node.seed(),
                        message,
                        node.schnorrKeys().privateKey(),
                        EMPTY_BYTE_ARRAY_2,
                        null,
                        null,
                        null,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2))
                .toList();
        final byte[][] round1Array = listToArray(round1);

        final List<byte[]> round2 = network.nodes().stream()
                .map(node -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R2,
                        node.seed(),
                        message,
                        node.schnorrKeys().privateKey(),
                        network.publicKeys(),
                        network.weights(),
                        network.nodeIds(),
                        signers,
                        round1Array,
                        EMPTY_BYTE_ARRAY_2,
                        EMPTY_BYTE_ARRAY_2))
                .toList();
        final byte[][] round2Array = listToArray(round2);

        final List<byte[]> round3 = network.nodes().stream()
                .map(node -> WRAPS.runSigningProtocolPhase(
                        WRAPSLibraryBridge.SigningProtocolPhase.R3,
                        node.seed(),
                        message,
                        node.schnorrKeys().privateKey(),
                        network.publicKeys(),
                        network.weights(),
                        network.nodeIds(),
                        signers,
                        round1Array,
                        round2Array,
                        EMPTY_BYTE_ARRAY_2))
                .toList();
        final byte[][] round3Array = listToArray(round3);

        final byte[] signature = WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                network.publicKeys(),
                network.weights(),
                network.nodeIds(),
                signers,
                round1Array,
                round2Array,
                round3Array);

        return new SigningProtocolOutput(signature, List.of(round1, round2, round3));
    }

    @Test
    public void testRunSigningProtocolPhaseAndVerifySignature() {
        final Network network = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2)));

        final SigningProtocolOutput output = aggregateSignature(network, Constants.MESSAGE_0);
        for (int roundIndex = 0; roundIndex < 3; roundIndex++) {
            for (int i = 0; i < output.roundMessages().get(roundIndex).size(); i++) {
                assertArrayEquals(
                        Constants.ROUND_MESSAGES[roundIndex][i],
                        output.roundMessages().get(roundIndex).get(i));
            }
        }

        assertArrayEquals(Constants.SIGNATURE, output.signature());

        // Let's also verify the signature while we're at it, so that we don't duplicate the code above:
        assertTrue(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        network.publicKeys()[0][20]++;
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        network.publicKeys()[0][20]--;
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), Constants.MESSAGE_1, output.signature()));

        // 128 is the MAX_AB_SIZE. The sig has a bool-vector prefix with the signers. Easier to corrupt the sig itself:
        output.signature()[128 + 7]++;
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        output.signature()[128 + 7]--;

        // And while we're at it, let's test verifySignature constraints
        assertFalse(WRAPS.verifySignature(
                null, network.weights(), network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                EMPTY_BYTE_ARRAY_2, network.weights(), network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), null, network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), new long[0], network.nodeIds(), Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), null, Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), new long[0], Constants.MESSAGE_0, output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), null, output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), new byte[0], output.signature()));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), Constants.MESSAGE_0, null));
        assertFalse(WRAPS.verifySignature(
                network.publicKeys(), network.weights(), network.nodeIds(), Constants.MESSAGE_0, new byte[0]));
        assertFalse(WRAPS.verifySignature(
                new byte[][] {network.publicKeys()[0], null},
                network.weights(),
                network.nodeIds(),
                Constants.MESSAGE_0,
                output.signature()));
        assertFalse(WRAPS.verifySignature(
                new byte[][] {network.publicKeys()[0], new byte[0]},
                network.weights(),
                network.nodeIds(),
                Constants.MESSAGE_0,
                output.signature()));
    }

    @Test
    public void testRunSigningProtocolPhaseConstraints() {
        final Network network = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2)));
        final boolean[] signers = new boolean[] {true, true, true};

        final Node node = network.nodes().get(0);
        final byte[] message = Constants.MESSAGE_0;

        assertNull(WRAPS.runSigningProtocolPhase(
                null,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                null,
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                new byte[0],
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                new byte[] {1},
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                null,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                null,
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                new byte[0],
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R1,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}}));

        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                null,
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                null,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}, new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R2,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}}));

        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}, new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {null},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.R3,
                node.seed(),
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));

        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                node.seed(),
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                node.schnorrKeys().privateKey(),
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                EMPTY_BYTE_ARRAY_2,
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {null},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}, new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2,
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}},
                new byte[][] {new byte[] {1}}));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                EMPTY_BYTE_ARRAY_2));
        assertNull(WRAPS.runSigningProtocolPhase(
                WRAPSLibraryBridge.SigningProtocolPhase.Aggregate,
                null,
                message,
                null,
                new byte[][] {new byte[] {1}},
                network.weights(),
                network.nodeIds(),
                signers,
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}},
                new byte[][] {new byte[] {1}, new byte[] {1}}));
    }

    @Test
    public void testHashAddressBook() {
        final List<SchnorrKeys> keys = List.of(Constants.SEED_0, Constants.SEED_1, Constants.SEED_2).stream()
                .map(WRAPS::generateSchnorrKeys)
                .toList();
        final byte[][] schnorrPublicKeys =
                listToArray(keys.stream().map(SchnorrKeys::publicKey).toList());

        assertArrayEquals(
                Constants.HASH_0,
                WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1000, 0, 100}, new long[] {0, 1, 3}));

        assertArrayEquals(
                Constants.HASH_1,
                WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1001, 0, 100}, new long[] {0, 1, 3}));

        assertArrayEquals(
                Constants.HASH_3,
                WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1001, 0, 100}, new long[] {0, 1, 2}));

        byte[] temp = schnorrPublicKeys[0];
        schnorrPublicKeys[0] = schnorrPublicKeys[1];
        schnorrPublicKeys[1] = temp;
        assertArrayEquals(
                Constants.HASH_2,
                WRAPS.hashAddressBook(schnorrPublicKeys, new long[] {1001, 0, 100}, new long[] {0, 1, 3}));
    }

    @Test
    public void testHashAddressBookConstraints() {
        final SchnorrKeys schnorrKeys = WRAPS.generateSchnorrKeys(Constants.SEED_0);

        assertNull(WRAPS.hashAddressBook(null, new long[] {1000, 0, 100}, new long[] {0, 1, 3}));
        assertNull(WRAPS.hashAddressBook(new byte[0][], null, new long[] {0, 1, 3}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), schnorrKeys.publicKey()},
                new long[] {1000, 0, 100},
                new long[] {0, 1, 3}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), schnorrKeys.publicKey(), schnorrKeys.publicKey()},
                new long[] {1000, -1, 100},
                new long[] {0, 1, 3}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), schnorrKeys.publicKey(), schnorrKeys.publicKey()},
                new long[] {Long.MAX_VALUE, 0, 100},
                new long[] {0, 1, 3}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), null, schnorrKeys.publicKey()},
                new long[] {1000, 0, 100},
                new long[] {0, 1, 3}));
        assertNull(WRAPS.hashAddressBook(
                new byte[][] {schnorrKeys.publicKey(), new byte[0], schnorrKeys.publicKey()},
                new long[] {1000, 0, 100},
                new long[] {0, 1, 3}));

        // Native code supports up to MAX_AB_SIZE = 128 (as of 10/20/2025), so let's try 128 and 129:
        // This should succeed (aka return non-null):
        final int maxAllowedNum = 128;
        assertNotNull(WRAPS.hashAddressBook(
                listToArray(IntStream.range(0, maxAllowedNum)
                        .mapToObj(i -> schnorrKeys.publicKey())
                        .toList()),
                new long[maxAllowedNum],
                new long[maxAllowedNum]));
        // Now do the same but exceed the max allowed size, and this should fail (return null):
        final int tooBigNum = maxAllowedNum + 1;
        assertNull(WRAPS.hashAddressBook(
                listToArray(IntStream.range(0, tooBigNum)
                        .mapToObj(i -> schnorrKeys.publicKey())
                        .toList()),
                new long[tooBigNum],
                new long[tooBigNum]));
    }

    @Test
    public void testFormatRotationMessageConstraints() {
        final byte[][] keys = new byte[][] {new byte[] {1}, new byte[] {2}, new byte[] {3}};
        final long[] weights = new long[] {1, 2, 3};
        final long[] nodeIds = new long[] {0, 1, 3};
        final byte[] hintsKey = new byte[1480];

        assertNull(WRAPS.formatRotationMessage(null, weights, nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(new byte[0][], weights, nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(new byte[][] {null, keys[1], keys[2]}, weights, nodeIds, hintsKey));
        assertNull(
                WRAPS.formatRotationMessage(new byte[][] {new byte[0], keys[1], keys[2]}, weights, nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, null, nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, new long[0], nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, new long[] {-1, 2, 3}, nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, new long[] {1, Long.MAX_VALUE, 3}, nodeIds, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, weights, null, hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, weights, new long[1], hintsKey));
        assertNull(WRAPS.formatRotationMessage(keys, weights, nodeIds, null));
        assertNull(WRAPS.formatRotationMessage(keys, weights, nodeIds, new byte[0]));
    }

    @Test
    public void testConstructWrapsProof() {
        if (!WRAPSLibraryBridge.isProofSupported()) {
            // Gradle script will download artifacts and set TSS_LIB_WRAPS_ARTIFACTS_PATH to bypass this.
            return;
        }

        final Network genesisNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3)));
        final byte[] genesisAddressBookHash =
                WRAPS.hashAddressBook(genesisNetwork.publicKeys(), genesisNetwork.weights(), genesisNetwork.nodeIds());

        final byte[] dummyHintsKey = new byte[1288];

        final byte[] message0 = WRAPS.formatRotationMessage(
                genesisNetwork.publicKeys(), genesisNetwork.weights(), genesisNetwork.nodeIds(), dummyHintsKey);
        final SigningProtocolOutput output0 = aggregateSignature(genesisNetwork, message0);

        System.err.println("Computing proof0 which may take up to 30 minutes...");
        final Proof proof0 = WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature());

        assertEquals(31568344, proof0.uncompressed().length);
        assertEquals(704, proof0.compressed().length);

        // Note: the compressed proof is non-deterministic, so we can only check the size, and then verify it:
        assertTrue(WRAPS.verifyCompressedProof(proof0.compressed(), genesisAddressBookHash, dummyHintsKey));

        // Now let's test a rotated AddressBook.

        // NOTE: we rely on the TSS_LIB_WRAPS_ARTIFACTS_CACHE_ENABLED env var set to "true" in Gradle.
        // so that the proving key is cached and the second proof here takes only a few minutes.
        // Otherwise, this test is going to take ~1 hour because loading the key takes ~27 minutes.
        // With the cache enabled, both the proofs together take ~30 minutes only.

        final Network nextNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3),
                Node.from(Constants.SEED_4, 1666, 4)));

        final AggregationAndVerificationKeys hintsKeys = HINTS.preprocess(
                CRS,
                new int[] {0, 1, 2, 3},
                listToArray(genesisNetwork.nodes().stream().map(Node::hints).toList()),
                genesisNetwork.weights(),
                SIGNERS_NUM);

        final byte[] message1 = WRAPS.formatRotationMessage(
                nextNetwork.publicKeys(), nextNetwork.weights(), nextNetwork.nodeIds(), hintsKeys.verificationKey());
        final SigningProtocolOutput output1 = aggregateSignature(genesisNetwork, message1);

        System.err.println(
                "Computing proof1 which should take only a few minutes because we assume we cache the proving key...");
        final Proof proof1 = WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                nextNetwork.publicKeys(),
                nextNetwork.weights(),
                nextNetwork.nodeIds(),
                proof0.uncompressed(),
                hintsKeys.verificationKey(),
                output1.signature());

        assertEquals(31568344, proof1.uncompressed().length);
        assertEquals(704, proof1.compressed().length);
        assertTrue(
                WRAPS.verifyCompressedProof(proof1.compressed(), genesisAddressBookHash, hintsKeys.verificationKey()));
    }

    @Test
    public void testConstructWrapsProofConstraints() {
        final Network genesisNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3)));
        final byte[] genesisAddressBookHash =
                WRAPS.hashAddressBook(genesisNetwork.publicKeys(), genesisNetwork.weights(), genesisNetwork.nodeIds());

        final byte[] dummyHintsKey = new byte[1288];

        final byte[] message0 = WRAPS.formatRotationMessage(
                genesisNetwork.publicKeys(), genesisNetwork.weights(), genesisNetwork.nodeIds(), dummyHintsKey);
        final SigningProtocolOutput output0 = aggregateSignature(genesisNetwork, message0);

        assertNull(WRAPS.constructWrapsProof(
                null,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                new byte[0],
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                null,
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                new byte[][] {genesisNetwork.publicKeys()[0]},
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    null,
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    new byte[0],
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                null,
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                new long[] {1},
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                new long[] {1, -1, 2, 3},
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                new long[] {1, Long.MAX_VALUE, 2, 3},
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                new byte[][] {genesisNetwork.publicKeys()[0]},
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    null,
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                new byte[][] {
                    genesisNetwork.publicKeys()[0],
                    new byte[0],
                    genesisNetwork.publicKeys()[2],
                    genesisNetwork.publicKeys()[3]
                },
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                null,
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                new long[] {1},
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                new long[] {1, -1, 2, 3},
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                new long[] {1, Long.MAX_VALUE, 2, 3},
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                null,
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                new byte[0],
                output0.signature()));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                null));
        assertNull(WRAPS.constructWrapsProof(
                genesisAddressBookHash,
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                null,
                dummyHintsKey,
                new byte[0]));
    }

    @Test
    public void testVerifyCompressedProofConstraints() {
        assertFalse(WRAPS.verifyCompressedProof(null, new byte[] {0}, new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[0], new byte[] {0}, new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, null, new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, new byte[0], new byte[] {0}));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, new byte[] {0}, null));
        assertFalse(WRAPS.verifyCompressedProof(new byte[] {0}, new byte[] {0}, new byte[0]));
    }
}
