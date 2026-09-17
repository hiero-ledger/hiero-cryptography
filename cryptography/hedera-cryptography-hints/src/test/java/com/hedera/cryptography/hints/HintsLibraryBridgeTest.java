// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HintsLibraryBridgeTest {
    private static final HintsLibraryBridge INSTANCE = HintsLibraryBridge.getInstance();
    private static final byte[] EMPTY = new byte[0];

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    private void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @BeforeEach
    void setup() {
        INSTANCE.resetCache();
    }

    byte[] initAndUpdateCRS(short n) {
        byte[] crs = INSTANCE.initCRS(n);
        crs = INSTANCE.updateCRS(crs, CRSConstants.RANDOM);
        return crs;
    }

    // Regression guard for the CRS size gate. `304 + n * 288` was evaluated in int arithmetic and wraps for large
    // powers of two -- to a negative value at 2^23 and 2^26, and to exactly 304 for 2^27 through 2^30 -- so a 304-byte
    // blob satisfied the gate for a network of up to a billion parties. preprocess was the reachable caller because
    // the bound on n lived in validatePartyId, which it reaches only inside a loop over the party list; an empty list
    // skipped it. The native sufficiency check underflowed on the resulting empty CRS and passed too, after which the
    // vanishing polynomial was sized from n and grew without bound in native memory.
    @Test
    void testPreprocessRejectsOverflowingNetworkSize() {
        final byte[] tinyCrs = new byte[304];

        for (final int n : new int[] {1 << 23, 1 << 26, 1 << 27, 1 << 28, 1 << 29, 1 << 30}) {
            INSTANCE.resetCache();
            assertNull(
                    INSTANCE.preprocess(tinyCrs, new int[0], new byte[0][], new long[0], n),
                    () -> "a 304-byte CRS must not satisfy the size gate for n = " + n);
        }

        // Negative control: the same blob is rejected for a small, in-range n as well, so the rejections above are the
        // size comparison working rather than only the bound on n.
        INSTANCE.resetCache();
        assertNull(INSTANCE.preprocess(tinyCrs, new int[0], new byte[0][], new long[0], 4));
    }

    @Test
    void testGenerateSecretKey() {
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 1, 16, 31, 33})
    void testGenerateSecretKeyInvalidRangeForRandomInput(final int range) {
        assertNull(INSTANCE.generateSecretKey(range == -1 ? null : new byte[range]));
    }

    @Test
    void testComputeHints() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);

        assertArrayEquals(HintsConstants.HINTS, hints);
    }

    @Test
    void testComputeHintsConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);

        // n must be power of two
        assertNull(INSTANCE.computeHints(crs, secretKey, 2, 3));
        assertNull(INSTANCE.computeHints(crs, secretKey, 2, 5));

        // n must match the CRS size...
        assertNull(INSTANCE.computeHints(crs, secretKey, 2, 8));
        // ...or be smaller than the CRS size, but should still be a positive power of two
        assertNotNull(INSTANCE.computeHints(crs, secretKey, 0, 2));

        // 0 <= partyId < n
        assertNull(INSTANCE.computeHints(crs, secretKey, -1, 4));
        assertNull(INSTANCE.computeHints(crs, secretKey, Integer.MIN_VALUE, 4));
        assertNull(INSTANCE.computeHints(crs, secretKey, 4, 4));
        assertNull(INSTANCE.computeHints(crs, secretKey, Integer.MAX_VALUE, 4));

        // nulls
        INSTANCE.resetCache();
        assertNull(INSTANCE.computeHints(null, secretKey, 2, 4));
        INSTANCE.resetCache();
        assertNull(INSTANCE.computeHints(crs, null, 2, 4));

        // corrupt the CRS
        crs[27]++;
        crs[172]--;
        crs[387]++;
        INSTANCE.resetCache();
        assertNull(INSTANCE.computeHints(crs, secretKey, 2, 4));

        // uncorrupt the CRS...
        crs[27]--;
        crs[172]++;
        crs[387]--;
        INSTANCE.resetCache();
        // and corrupt the key instead
        secretKey[7]++;
        // surprisingly, a corrupted key works just fine, although of course the result should be incorrect
        final byte[] resultWithCorruptedKey = INSTANCE.computeHints(crs, secretKey, 2, 4);

        // uncorrupt the key and perform the last sanity check
        secretKey[7]--;
        final byte[] normalResult = INSTANCE.computeHints(crs, secretKey, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, normalResult);
        assertFalse(Arrays.equals(resultWithCorruptedKey, normalResult));
    }

    @Test
    void testValidateHintsKey() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints);

        assertTrue(INSTANCE.validateHintsKey(crs, hints, 2, 4));
    }

    @Test
    void testValidateHintsConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);

        // n must be power of two
        assertFalse(INSTANCE.validateHintsKey(crs, hints, 2, 3));
        assertFalse(INSTANCE.validateHintsKey(crs, hints, 2, 5));

        // n must match the CRS size
        assertFalse(INSTANCE.validateHintsKey(crs, hints, 2, 8));

        // 0 <= partyId < n
        assertFalse(INSTANCE.validateHintsKey(crs, hints, -1, 4));
        assertFalse(INSTANCE.validateHintsKey(crs, hints, Integer.MIN_VALUE, 4));
        assertFalse(INSTANCE.validateHintsKey(crs, hints, 4, 4));
        assertFalse(INSTANCE.validateHintsKey(crs, hints, Integer.MAX_VALUE, 4));

        // nulls
        INSTANCE.resetCache();
        assertFalse(INSTANCE.validateHintsKey(null, hints, 2, 4));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.validateHintsKey(crs, null, 2, 4));

        // corrupt the CRS
        crs[27]++;
        crs[172]--;
        crs[387]++;
        INSTANCE.resetCache();
        assertFalse(INSTANCE.validateHintsKey(crs, hints, 2, 4));

        // uncorrupt the CRS...
        crs[27]--;
        crs[172]++;
        crs[387]--;
        INSTANCE.resetCache();
        // and corrupt the hints instead
        hints[17]++;
        hints[111]--;
        hints[302]++;
        assertFalse(INSTANCE.validateHintsKey(crs, hints, 2, 4));

        // undo hints corruption and perform a sanity check
        hints[17]--;
        hints[111]++;
        hints[302]--;
        assertTrue(INSTANCE.validateHintsKey(crs, hints, 2, 4));
    }

    @Test
    void testPreprocess() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {2}, new byte[][] {hints}, new long[] {111}, 4);
        assertArrayEquals(HintsConstants.VERIFICATION_KEY, keys.verificationKey());
        assertArrayEquals(HintsConstants.AGGREGATION_KEY, keys.aggregationKey());
    }

    @Test
    void testPreprocessConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);

        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 1, 4);

        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);

        final byte[] secretKey3 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_3);
        final byte[] hints3 = INSTANCE.computeHints(crs, secretKey3, 3, 4);

        // check n and crs length
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 3));
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 5));
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 8));

        // nulls
        INSTANCE.resetCache();
        assertNull(INSTANCE.preprocess(
                null, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 4));
        INSTANCE.resetCache();
        assertNull(INSTANCE.preprocess(crs, null, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 4));
        assertNull(INSTANCE.preprocess(crs, new int[] {0, 1, 2}, null, new long[] {111, 1, 222}, 4));
        assertNull(INSTANCE.preprocess(crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, null, 4));

        // parties lengths
        assertNull(INSTANCE.preprocess(
                crs,
                new int[] {0, 1, 2, 3},
                new byte[][] {hints0, hints1, hints2, hints3},
                new long[] {111, 1, 222, 999},
                4));
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1}, new long[] {111, 1, 222}, 4));
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1}, 4));

        // sane values
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 4}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 4));
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {null, hints1, hints2}, new long[] {111, 1, 222}, 4));
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, -1, 222}, 4));

        // corrupt the CRS
        crs[27]++;
        crs[172]--;
        crs[387]++;
        INSTANCE.resetCache();
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 4));

        // uncorrupt the CRS...
        crs[27]--;
        crs[172]++;
        crs[387]--;
        INSTANCE.resetCache();
        // and corrupt the hints instead
        hints1[17]++;
        hints1[111]--;
        hints1[302]++;
        assertNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 4));

        // uncorrupt the hints
        hints1[17]--;
        hints1[111]++;
        hints1[302]--;
        // and check if weights cannot overflow `long`:
        assertNull(INSTANCE.preprocess(
                crs,
                new int[] {0, 1, 2},
                new byte[][] {hints0, hints1, hints2},
                new long[] {Long.MAX_VALUE - 1L, 1, 222},
                4));

        // and finally do a sanity check:
        assertNotNull(INSTANCE.preprocess(
                crs, new int[] {0, 1, 2}, new byte[][] {hints0, hints1, hints2}, new long[] {111, 1, 222}, 4));
    }

    @Test
    void testSignBls() {
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey);
        assertArrayEquals(HintsConstants.SIGNATURE, signature);
    }

    @Test
    void testSignBlsConstraints() {
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);

        assertNull(INSTANCE.signBls(null, secretKey));
        assertNull(INSTANCE.signBls(EMPTY, secretKey));
        assertNull(INSTANCE.signBls(HintsConstants.RANDOM_2, null));
        assertNull(INSTANCE.signBls(HintsConstants.RANDOM_2, EMPTY));

        // The message can be anything, and the key is just a number, so it technically can be anything too.
        // So there's nothing more to test.
    }

    @Test
    void testVerifyBls() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey);

        final int partyId = 2;

        final byte[] hints = INSTANCE.computeHints(crs, secretKey, partyId, 4);
        assertArrayEquals(HintsConstants.HINTS, hints);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {partyId}, new byte[][] {hints}, new long[] {111}, 4);

        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey);
        assertArrayEquals(HintsConstants.SIGNATURE, signature);

        assertTrue(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, keys.aggregationKey(), partyId));
    }

    @Test
    void testVerifyBlsConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);
        final byte[] secretKey = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final int partyId = 2;
        final byte[] hints = INSTANCE.computeHints(crs, secretKey, partyId, 4);
        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {partyId}, new byte[][] {hints}, new long[] {111}, 4);
        final byte[] signature = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey);

        assertFalse(INSTANCE.verifyBls(null, HintsConstants.RANDOM_2, keys.aggregationKey(), partyId));
        assertFalse(INSTANCE.verifyBls(EMPTY, HintsConstants.RANDOM_2, keys.aggregationKey(), partyId));
        assertFalse(INSTANCE.verifyBls(signature, null, keys.aggregationKey(), partyId));
        assertFalse(INSTANCE.verifyBls(signature, EMPTY, keys.aggregationKey(), partyId));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, null, partyId));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, EMPTY, partyId));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, keys.aggregationKey(), -1));
        assertFalse(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, keys.aggregationKey(), 666));

        // Corrupt the signature
        signature[23]++;
        assertFalse(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, keys.aggregationKey(), partyId));

        // undo the signature...
        signature[23]--;
        // and corrupt the aggregationKey instead
        keys.aggregationKey()[17]++;
        keys.aggregationKey()[111]--;
        keys.aggregationKey()[302]++;
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, keys.aggregationKey(), partyId));

        // uncorrupt the aggregationKey and do a sanity check
        keys.aggregationKey()[17]--;
        keys.aggregationKey()[111]++;
        keys.aggregationKey()[302]--;
        INSTANCE.resetCache();
        assertTrue(INSTANCE.verifyBls(signature, HintsConstants.RANDOM_2, keys.aggregationKey(), partyId));
    }

    @Test
    void testVerifyBlsBatch() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final int partyId0 = 0;
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, partyId0, 4);
        final AggregationAndVerificationKeys keys0 =
                INSTANCE.preprocess(crs, new int[] {partyId0}, new byte[][] {hints0}, new long[] {111}, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        final int partyId2 = 2;
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, partyId2, 4);
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);

        final AggregationAndVerificationKeys keys = INSTANCE.preprocess(
                crs, new int[] {partyId0, partyId2}, new byte[][] {hints0, hints2}, new long[] {111, 222}, 4);

        assertTrue(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {partyId0, partyId2}, new byte[][] {
                    signature0, signature2
                }));
    }

    @Test
    void testVerifyBlsBatchConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        // partyId 0
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        // partyId 2
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {0, 2}, new byte[][] {hints0, hints2}, new long[] {111, 222}, 4);

        assertFalse(INSTANCE.verifyBlsBatch(
                null, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0}));
        assertFalse(INSTANCE.verifyBlsBatch(
                EMPTY, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0}));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, null, new int[] {0, 2}, new byte[][] {signature2, signature0}));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, EMPTY, new int[] {0, 2}, new byte[][] {signature2, signature0}));
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), null, new byte[][] {signature2, signature0}));
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[0], new byte[][] {signature2, signature0}));
        assertFalse(INSTANCE.verifyBlsBatch(HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {0, 2}, null));
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {}));
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {signature2}));

        // Corrupt the aggregationKey
        keys.aggregationKey()[11]++;
        INSTANCE.resetCache();
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0
                }));

        // uncorrupt the aggregationKey...
        keys.aggregationKey()[11]--;
        INSTANCE.resetCache();
        // corrupt a signature instead
        signature2[17]++;
        assertFalse(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0
                }));

        // undo the damage and run a sanity check
        signature2[17]--;
        assertTrue(INSTANCE.verifyBlsBatch(
                HintsConstants.RANDOM_2, keys.aggregationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0
                }));
    }

    @Test
    void testAggregateSignatures() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        // partyId 2
        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints1);
        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature1 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey1);
        assertArrayEquals(HintsConstants.SIGNATURE, signature1);

        // partyId 0
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 0, 4);
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {0, 2}, new byte[][] {hints2, hints1}, new long[] {111, 222}, 4);

        final byte[] result = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature1, signature2
                });

        assertArrayEquals(HintsConstants.AGGREGATE_SIGNATURE, result);
    }

    @Test
    void testAggregateSignaturesConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        // partyId 0
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        // partyId 2
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);

        final AggregationAndVerificationKeys keys =
                INSTANCE.preprocess(crs, new int[] {0, 2}, new byte[][] {hints0, hints2}, new long[] {111, 222}, 4);

        INSTANCE.resetCache();
        assertNull(INSTANCE.aggregateSignatures(
                null, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature2, signature0
                }));
        INSTANCE.resetCache();
        assertNull(INSTANCE.aggregateSignatures(
                EMPTY, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature2, signature0
                }));
        INSTANCE.resetCache();
        assertNull(INSTANCE.aggregateSignatures(
                crs, null, keys.verificationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0}));
        INSTANCE.resetCache();
        assertNull(INSTANCE.aggregateSignatures(
                crs, EMPTY, keys.verificationKey(), new int[] {0, 2}, new byte[][] {signature2, signature0}));
        INSTANCE.resetCache();
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), null, new int[] {0, 2}, new byte[][] {signature2, signature0}));
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), EMPTY, new int[] {0, 2}, new byte[][] {signature2, signature0}));
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), null, new byte[][] {signature2, signature0}));
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[0], new byte[][] {signature2, signature0}));
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, null));
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {}));
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {signature2}));

        // corrupt the CRS
        crs[27]++;
        crs[172]--;
        crs[387]++;
        INSTANCE.resetCache();
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature2, signature0
                }));
        // uncorrupt the CRS...
        crs[27]--;
        crs[172]++;
        crs[387]--;
        INSTANCE.resetCache();
        // and corrupt the aggregationKey
        keys.aggregationKey()[11]++;
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature2, signature0
                }));

        // uncorrupt the aggregationKey...
        keys.aggregationKey()[11]--;
        INSTANCE.resetCache();
        // the method survives a corrupt verificationKey, so...
        // corrupt a signature instead
        signature2[17]++;
        assertNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature2, signature0
                }));

        // undo the damage and run a sanity check
        signature2[17]--;
        assertNotNull(INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {0, 2}, new byte[][] {
                    signature2, signature0
                }));
    }

    @Test
    void testVerifyAggregate_meetsThreshold() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        // partyId 2
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints2);
        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);
        assertArrayEquals(HintsConstants.SIGNATURE, signature2);

        // partyId 0
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        // partyId 1
        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 1, 4);

        // Here, the partyId 1 has a tiny weight of 1, so it doesn't matter
        final AggregationAndVerificationKeys keys = INSTANCE.preprocess(
                crs, new int[] {0, 2, 1}, new byte[][] {hints0, hints2, hints1}, new long[] {111, 222, 1}, 4);

        final byte[] result = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {2, 0}, new byte[][] {
                    signature2, signature0
                });
        assertArrayEquals(HintsConstants.AGGREGATE_SIGNATURE_2, result);

        assertTrue(INSTANCE.verifyAggregate(result, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
        // Also verify if it meets the 1/2 threshold, because it does:
        assertTrue(INSTANCE.verifyAggregate(result, HintsConstants.RANDOM_2, keys.verificationKey()));
    }

    @Test
    void testVerifyAggregate_doesNotMeetThreshold() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        // partyId 2
        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        assertArrayEquals(HintsConstants.SECRET_KEY, secretKey2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        assertArrayEquals(HintsConstants.HINTS, hints2);
        // Use the RANDOM as a message to sign, because why not?
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);
        assertArrayEquals(HintsConstants.SIGNATURE, signature2);

        // partyId 0
        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        // partyId 1
        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 1, 4);

        // Here, the partyId 1 has a huge weight of 999, so it matters a lot more than the other two
        final AggregationAndVerificationKeys keys = INSTANCE.preprocess(
                crs, new int[] {0, 2, 1}, new byte[][] {hints0, hints2, hints1}, new long[] {111, 222, 999}, 4);

        final byte[] result = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {2, 0}, new byte[][] {
                    signature2, signature0
                });
        assertArrayEquals(HintsConstants.AGGREGATE_SIGNATURE_3, result);

        assertFalse(INSTANCE.verifyAggregate(result, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
        // Also verify if it doesn't meet the 1/2 threshold, because it doesn't:
        assertFalse(INSTANCE.verifyAggregate(result, HintsConstants.RANDOM_2, keys.verificationKey()));
    }

    @Test
    void testVerifyAggregateConstraints() {
        final byte[] crs = initAndUpdateCRS((short) 4);

        final byte[] secretKey0 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_0);
        final byte[] hints0 = INSTANCE.computeHints(crs, secretKey0, 0, 4);
        final byte[] signature0 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey0);

        final byte[] secretKey1 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_1);
        final byte[] hints1 = INSTANCE.computeHints(crs, secretKey1, 1, 4);

        final byte[] secretKey2 = INSTANCE.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] hints2 = INSTANCE.computeHints(crs, secretKey2, 2, 4);
        final byte[] signature2 = INSTANCE.signBls(HintsConstants.RANDOM_2, secretKey2);

        final AggregationAndVerificationKeys keys = INSTANCE.preprocess(
                crs, new int[] {0, 2, 1}, new byte[][] {hints0, hints2, hints1}, new long[] {111, 222, 1}, 4);

        final byte[] aggregateSignature = INSTANCE.aggregateSignatures(
                crs, keys.aggregationKey(), keys.verificationKey(), new int[] {2, 0}, new byte[][] {
                    signature2, signature0
                });

        assertFalse(INSTANCE.verifyAggregate(null, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
        assertFalse(INSTANCE.verifyAggregate(EMPTY, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
        assertFalse(INSTANCE.verifyAggregate(aggregateSignature, null, keys.verificationKey(), 1, 3));
        assertFalse(INSTANCE.verifyAggregate(aggregateSignature, EMPTY, keys.verificationKey(), 1, 3));
        assertFalse(INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, null, 1, 3));
        assertFalse(INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, EMPTY, 1, 3));
        assertFalse(
                INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), 0, 3));
        assertFalse(
                INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), -1, 3));
        assertFalse(
                INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 0));
        assertFalse(
                INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), 1, -3));

        // corrupt the aggregate aggregateSignature
        aggregateSignature[17]++;
        assertFalse(
                INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
        // undo
        aggregateSignature[17]--;

        // corrupt the message, or rather, just supply an incorrect one
        assertFalse(INSTANCE.verifyAggregate(aggregateSignature, new byte[] {1, 2, 3}, keys.verificationKey(), 1, 3));

        // corrupt the verificationKey
        keys.verificationKey()[17]--;
        assertFalse(
                INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
        // undo
        keys.verificationKey()[17]++;

        // and run a sanity check
        assertTrue(INSTANCE.verifyAggregate(aggregateSignature, HintsConstants.RANDOM_2, keys.verificationKey(), 1, 3));
    }
}
