// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.tss;

import static com.hedera.cryptography.wraps.WRAPSLibraryBridgeTest.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.hedera.cryptography.hints.AggregationAndVerificationKeys;
import com.hedera.cryptography.hints.HintsLibraryBridge;
import com.hedera.cryptography.wraps.Constants;
import com.hedera.cryptography.wraps.Proof;
import com.hedera.cryptography.wraps.WRAPSLibraryBridge;
import com.hedera.cryptography.wraps.WRAPSLibraryBridgeTest;
import com.hedera.cryptography.wraps.WRAPSLibraryBridgeTest.Network;
import com.hedera.cryptography.wraps.WRAPSLibraryBridgeTest.Node;
import com.hedera.cryptography.wraps.WRAPSLibraryBridgeTest.SigningProtocolOutput;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

public class TSSTest {
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();
    private static final WRAPSLibraryBridge WRAPS = WRAPSLibraryBridge.getInstance();

    private static final byte[] EMPTY = new byte[0];
    private static final byte[] ONE = new byte[] {1};

    @Test
    void testComposeSignature() {
        // Happy cases first
        assertArrayEquals(
                TSSTestConstants.TSS_SIGNATURE_WITH_SCHNORR,
                TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertArrayEquals(
                TSSTestConstants.TSS_SIGNATURE_WITH_WRAPS,
                TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF));

        // Unhappy cases last
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, EMPTY));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, ONE));

        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        null, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        EMPTY, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        ONE, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, null, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, EMPTY, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, ONE, TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE));

        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        null, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        EMPTY, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        ONE, TSSTestConstants.HINTS_SIGNATURE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, null, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, EMPTY, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.composeSignature(
                        TSSTestConstants.HINTS_VERIFICATION_KEY, ONE, TSSTestConstants.COMPRESSED_WRAPS_PROOF));
    }

    /**
     * An arrays concatenator.
     * @param arrays byte arrays
     * @return a concatenated array in the order present
     */
    private byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] arr : arrays) {
            len += arr.length;
        }

        final byte[] ret = new byte[len];

        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, ret, pos, arr.length);
            pos += arr.length;
        }

        return ret;
    }

    /**
     * Randomly corrupted array copier.
     * @param arr an input array
     * @param rnd a Random
     * @return a copy of arr with one random byte randomly modified
     */
    private byte[] rnd(byte[] arr, Random rnd) {
        final byte[] clone = arr.clone();
        final int val = rnd.nextInt(256);
        final int i = rnd.nextInt(clone.length);

        if (clone[i] == val) {
            clone[i] = (byte) (val == 0 ? 1 : val + 1);
        } else {
            clone[i] = (byte) val;
        }

        return clone;
    }

    @Test
    void testVerifyTSS() {
        // A fixed seed for reproducibility:
        final Random rnd = new Random(945863847);

        // Two happy cases first:

        TSS.setAddressBook(TSSTestConstants.SCHNORR_PUBLIC_KEYS, TSSTestConstants.WEIGHTS, TSSTestConstants.NODE_IDS);
        assertTrue(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));

        TSS.setAddressBook(null, null, null);
        assertTrue(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));

        // Then unhappy cases, starting with unverifiable data
        assertFalse(TSS.verifyTSS(
                rnd(TSSTestConstants.ADDRESS_BOOK_HASH, rnd),
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        rnd(TSSTestConstants.HINTS_VERIFICATION_KEY, rnd),
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        rnd(TSSTestConstants.HINTS_SIGNATURE, rnd),
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        rnd(TSSTestConstants.COMPRESSED_WRAPS_PROOF, rnd)),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                rnd(TSSTestConstants.MESSAGE, rnd)));

        TSS.setAddressBook(TSSTestConstants.SCHNORR_PUBLIC_KEYS, TSSTestConstants.WEIGHTS, TSSTestConstants.NODE_IDS);
        assertFalse(TSS.verifyTSS(
                rnd(TSSTestConstants.ADDRESS_BOOK_HASH, rnd),
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        rnd(TSSTestConstants.HINTS_VERIFICATION_KEY, rnd),
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        rnd(TSSTestConstants.HINTS_SIGNATURE, rnd),
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        rnd(TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE, rnd)),
                TSSTestConstants.MESSAGE));
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                rnd(TSSTestConstants.MESSAGE, rnd)));
        final byte[][] badSchnorrKeys = new byte[TSSTestConstants.SCHNORR_PUBLIC_KEYS.length][];
        for (int i = 0; i < TSSTestConstants.SCHNORR_PUBLIC_KEYS.length; i++) {
            badSchnorrKeys[i] = TSSTestConstants.SCHNORR_PUBLIC_KEYS[i];
            if (i == 0) {
                badSchnorrKeys[i] = rnd(badSchnorrKeys[i], rnd);
            }
        }
        TSS.setAddressBook(badSchnorrKeys, TSSTestConstants.WEIGHTS, TSSTestConstants.NODE_IDS);
        assertFalse(TSS.verifyTSS(
                TSSTestConstants.ADDRESS_BOOK_HASH,
                concat(
                        TSSTestConstants.HINTS_VERIFICATION_KEY,
                        TSSTestConstants.HINTS_SIGNATURE,
                        TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                TSSTestConstants.MESSAGE));

        // Then test the missing keys
        TSS.setAddressBook(null, null, null);
        assertThrows(
                IllegalStateException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.AGGREGATE_SCHNORR_SIGNATURE),
                        TSSTestConstants.MESSAGE));

        // And finally check bad args
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        null,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        EMPTY,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        ONE,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(TSSTestConstants.ADDRESS_BOOK_HASH, null, TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(TSSTestConstants.ADDRESS_BOOK_HASH, EMPTY, TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(TSSTestConstants.HINTS_VERIFICATION_KEY, new byte[] {1, 2, 3}, new byte[] {1, 2, 3}),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(TSSTestConstants.HINTS_VERIFICATION_KEY, TSSTestConstants.HINTS_SIGNATURE, new byte[] {
                            1, 2, 3
                        }),
                        TSSTestConstants.MESSAGE));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        null));
        assertThrows(
                IllegalArgumentException.class,
                () -> TSS.verifyTSS(
                        TSSTestConstants.ADDRESS_BOOK_HASH,
                        concat(
                                TSSTestConstants.HINTS_VERIFICATION_KEY,
                                TSSTestConstants.HINTS_SIGNATURE,
                                TSSTestConstants.COMPRESSED_WRAPS_PROOF),
                        EMPTY));
    }

    /**
     * This isn't a test per se, but rather a utility to capture all the TSSTestConstants
     * used in unit tests here. It's designed to be run manually by uncommenting the
     * `@Test` annotation below. It's useless and time-expensive to keep this "test" enabled
     * otherwise because the WRAPS proof construction would add an extra 30 minutes to the runtime.
     */
    // @Test
    void captureTestData() throws Exception {
        if (!WRAPSLibraryBridge.isProofSupported()) {
            // Gradle script should download artifacts and set TSS_LIB_WRAPS_ARTIFACTS_PATH to bypass this.
            fail("Must have TSS_LIB_WRAPS_ARTIFACTS_PATH downloaded, or comment out @Test annotation instead.");
        }

        try (FileInputStream fis =
                new FileInputStream(System.getenv("TSS_LIB_WRAPS_ARTIFACTS_PATH") + "/decider_vp.bin")) {
            final byte[] bytes = fis.readNBytes(4096); // It's 1.7KB, but limit to 4KB for safety.
            System.err.println("decider_vp.bin aka WRAPSVerificationKey.DEFAULT_KEY = " + Arrays.toString(bytes));
        }

        final Network genesisNetwork = new Network(List.of(
                Node.from(Constants.SEED_0, 1000, 0),
                Node.from(Constants.SEED_1, 0, 1),
                Node.from(Constants.SEED_2, 100, 2),
                Node.from(Constants.SEED_3, 666, 3)));
        System.err.println("SCHNORR_PUBLIC_KEYS:");
        for (int i = 0; i < genesisNetwork.publicKeys().length; i++) {
            System.err.println(
                    "    " + i + ": " + Arrays.toString(genesisNetwork.publicKeys()[i]));
        }

        final byte[] genesisAddressBookHash =
                WRAPS.hashAddressBook(genesisNetwork.publicKeys(), genesisNetwork.weights(), genesisNetwork.nodeIds());
        System.err.println("ADDRESS_BOOK_HASH = " + Arrays.toString(genesisAddressBookHash));

        final int N = 8;

        final byte[] crs = HINTS.initCRS((short) N);
        // For simplicity, use the same secretKey for all:
        final byte[] secretKey = HINTS.generateSecretKey(TSSTestConstants.RANDOM);

        final AggregationAndVerificationKeys keys = HINTS.preprocess(
                crs,
                new int[] {0, 1, 2, 3},
                Stream.of(0, 1, 2, 3)
                        .map(i -> HINTS.computeHints(crs, secretKey, i, N))
                        .toList()
                        .toArray(new byte[4][]),
                genesisNetwork.weights(),
                N);

        System.err.println("HINTS_VERIFICATION_KEY = " + Arrays.toString(keys.verificationKey()));

        // Since we use the same key, the signature is also the same for all:
        final byte[] blsSignature = HINTS.signBls(TSSTestConstants.MESSAGE, secretKey);
        final byte[] hintsSignature = HINTS.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 1, 2, 3}, new byte[][] {
                    blsSignature, blsSignature, blsSignature, blsSignature
                });
        System.err.println("HINTS_SIGNATURE = " + Arrays.toString(hintsSignature));

        final byte[] message0 = WRAPS.formatRotationMessage(
                genesisNetwork.publicKeys(),
                genesisNetwork.weights(),
                genesisNetwork.nodeIds(),
                keys.verificationKey());
        final SigningProtocolOutput output0 = WRAPSLibraryBridgeTest.aggregateSignature(genesisNetwork, message0);

        System.err.println("AGGREGATE_SCHNORR_SIGNATURE = " + Arrays.toString(output0.signature()));

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
                keys.verificationKey(),
                output0.signature());

        System.err.println("uncompressed proof size: " + proof0.uncompressed().length);
        System.err.println("compressed proof size: " + proof0.compressed().length);

        System.err.println("COMPRESSED_WRAPS_PROOF = " + Arrays.toString(proof0.compressed()));
    }
}
