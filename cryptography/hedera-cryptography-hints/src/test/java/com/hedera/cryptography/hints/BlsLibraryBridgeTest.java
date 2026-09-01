// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class BlsLibraryBridgeTest {
    private static final BlsLibraryBridge INSTANCE = BlsLibraryBridge.getInstance();
    private static final HintsLibraryBridge HINTS = HintsLibraryBridge.getInstance();

    private static final byte[] EMPTY = new byte[0];

    /** The message the vectors in {@link BlsMultisigConstants} are signed over. */
    private static final byte[] MESSAGE = HintsConstants.RANDOM_2;

    /** The signature of the party holding {@link BlsMultisigConstants#PUBLIC_KEY_2} on {@link #MESSAGE}. */
    private static final byte[] SIGNATURE = HintsConstants.SIGNATURE;

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    private void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    private static byte[] copyOf(final byte[] array) {
        return Arrays.copyOf(array, array.length);
    }

    // -------------------------------------------------------------------------
    // verifySignature
    // -------------------------------------------------------------------------

    @Test
    void testVerifySignature() {
        // a signature produced by the hinTS signer verifies under the BLS bridge
        final byte[] secretKey = HINTS.generateSecretKey(HintsConstants.RANDOM_2);
        final byte[] signature = HINTS.signBls(MESSAGE, secretKey);
        assertArrayEquals(SIGNATURE, signature);

        assertTrue(INSTANCE.verifySignature(signature, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));
    }

    @Test
    void testVerifySignatureAcceptsCompressedEncodings() {
        assertTrue(INSTANCE.verifySignature(SIGNATURE, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2_COMPRESSED));
        assertTrue(INSTANCE.verifySignature(
                BlsMultisigConstants.SIGNATURE_2_COMPRESSED, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));
        assertTrue(INSTANCE.verifySignature(
                BlsMultisigConstants.SIGNATURE_2_COMPRESSED, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2_COMPRESSED));
    }

    @Test
    void testVerifySignatureRejectsWrongInputs() {
        // a different message
        assertFalse(INSTANCE.verifySignature(SIGNATURE, new byte[] {1, 2, 3}, BlsMultisigConstants.PUBLIC_KEY_2));
        // a different signer's public key
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_0));
        // an aggregate public key that expects more signers than signed
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, BlsMultisigConstants.AGGREGATE_PUBLIC_KEY_0_2));

        // a corrupted signature
        final byte[] signature = copyOf(SIGNATURE);
        signature[23]++;
        assertFalse(INSTANCE.verifySignature(signature, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));

        // a corrupted public key
        final byte[] publicKey = copyOf(BlsMultisigConstants.PUBLIC_KEY_2);
        publicKey[17]++;
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, publicKey));

        // byte arrays of the right length that are not group elements at all
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, new byte[96]));
        assertFalse(INSTANCE.verifySignature(new byte[192], MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));
    }

    @Test
    void testVerifySignatureConstraints() {
        assertFalse(INSTANCE.verifySignature(null, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));
        assertFalse(INSTANCE.verifySignature(EMPTY, MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));
        assertFalse(INSTANCE.verifySignature(SIGNATURE, null, BlsMultisigConstants.PUBLIC_KEY_2));
        assertFalse(INSTANCE.verifySignature(SIGNATURE, EMPTY, BlsMultisigConstants.PUBLIC_KEY_2));
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, null));
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, EMPTY));

        // the public key and the signature live in different groups and cannot be swapped
        assertFalse(INSTANCE.verifySignature(BlsMultisigConstants.PUBLIC_KEY_2, MESSAGE, SIGNATURE));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 47, 49, 95, 97, 192})
    void testVerifySignatureRejectsWrongPublicKeyLength(final int length) {
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, new byte[length]));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 48, 95, 97, 191, 193})
    void testVerifySignatureRejectsWrongSignatureLength(final int length) {
        assertFalse(INSTANCE.verifySignature(new byte[length], MESSAGE, BlsMultisigConstants.PUBLIC_KEY_2));
    }

    // -------------------------------------------------------------------------
    // aggregatePublicKeys
    // -------------------------------------------------------------------------

    @Test
    void testAggregatePublicKeys() {
        final byte[][] publicKeys = {
            BlsMultisigConstants.PUBLIC_KEY_0,
            BlsMultisigConstants.PUBLIC_KEY_1,
            BlsMultisigConstants.PUBLIC_KEY_2,
            BlsMultisigConstants.PUBLIC_KEY_3
        };

        final byte[] aggregate = INSTANCE.aggregatePublicKeys(publicKeys, new boolean[] {true, false, true, false});
        assertArrayEquals(BlsMultisigConstants.AGGREGATE_PUBLIC_KEY_0_2, aggregate);

        // the aggregate public key verifies the sum of the two signatures
        assertTrue(INSTANCE.verifySignature(BlsMultisigConstants.AGGREGATE_SIGNATURE_0_2, MESSAGE, aggregate));
        // but not the signature of a single one of the two signers
        assertFalse(INSTANCE.verifySignature(SIGNATURE, MESSAGE, aggregate));
    }

    @Test
    void testAggregatePublicKeysIsOrderIndependent() {
        final byte[] aggregate = INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.PUBLIC_KEY_2, BlsMultisigConstants.PUBLIC_KEY_0},
                new boolean[] {true, true});
        assertArrayEquals(BlsMultisigConstants.AGGREGATE_PUBLIC_KEY_0_2, aggregate);
    }

    @Test
    void testAggregatePublicKeysAcceptsMixedEncodings() {
        // the second key is given compressed, the first uncompressed
        final byte[] aggregate = INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.PUBLIC_KEY_0, BlsMultisigConstants.PUBLIC_KEY_2_COMPRESSED},
                new boolean[] {true, true});
        assertArrayEquals(BlsMultisigConstants.AGGREGATE_PUBLIC_KEY_0_2, aggregate);
    }

    @Test
    void testAggregatePublicKeysOfASingleKeyIsThatKey() {
        final byte[] aggregate =
                INSTANCE.aggregatePublicKeys(new byte[][] {BlsMultisigConstants.PUBLIC_KEY_2}, new boolean[] {true});
        assertArrayEquals(BlsMultisigConstants.PUBLIC_KEY_2, aggregate);
        assertTrue(INSTANCE.verifySignature(SIGNATURE, MESSAGE, aggregate));

        // a compressed input still yields the uncompressed serialization on output
        final byte[] fromCompressed = INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.PUBLIC_KEY_2_COMPRESSED}, new boolean[] {true});
        assertArrayEquals(BlsMultisigConstants.PUBLIC_KEY_2, fromCompressed);
    }

    @Test
    void testAggregatePublicKeysIgnoresUnselectedEntries() {
        // the entries the bitvector skips are never read, so they may be null or garbage
        final byte[][] publicKeys = {
            null, BlsMultisigConstants.PUBLIC_KEY_0, new byte[7], BlsMultisigConstants.PUBLIC_KEY_2, EMPTY
        };

        final byte[] aggregate =
                INSTANCE.aggregatePublicKeys(publicKeys, new boolean[] {false, true, false, true, false});
        assertArrayEquals(BlsMultisigConstants.AGGREGATE_PUBLIC_KEY_0_2, aggregate);
    }

    @Test
    void testAggregatePublicKeysConstraints() {
        final byte[][] publicKeys = {
            BlsMultisigConstants.PUBLIC_KEY_0, BlsMultisigConstants.PUBLIC_KEY_1, BlsMultisigConstants.PUBLIC_KEY_2
        };

        // nulls
        assertNull(INSTANCE.aggregatePublicKeys(null, new boolean[] {true, true, true}));
        assertNull(INSTANCE.aggregatePublicKeys(publicKeys, null));

        // the two arrays must be of the same, non-zero length
        assertNull(INSTANCE.aggregatePublicKeys(new byte[0][], new boolean[0]));
        assertNull(INSTANCE.aggregatePublicKeys(publicKeys, new boolean[] {true, true}));
        assertNull(INSTANCE.aggregatePublicKeys(publicKeys, new boolean[] {true, true, true, true}));

        // and at least one public key must be selected
        assertNull(INSTANCE.aggregatePublicKeys(publicKeys, new boolean[] {false, false, false}));

        // a selected entry that is missing, of the wrong length, or not a group element
        assertNull(INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.PUBLIC_KEY_0, null, BlsMultisigConstants.PUBLIC_KEY_2},
                new boolean[] {true, true, true}));
        assertNull(INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.PUBLIC_KEY_0, new byte[64], BlsMultisigConstants.PUBLIC_KEY_2},
                new boolean[] {true, true, true}));
        assertNull(INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.PUBLIC_KEY_0, new byte[96], BlsMultisigConstants.PUBLIC_KEY_2},
                new boolean[] {true, true, true}));

        // a signature is not a public key, even though it has the length of a compressed one
        assertNull(INSTANCE.aggregatePublicKeys(
                new byte[][] {BlsMultisigConstants.SIGNATURE_2_COMPRESSED}, new boolean[] {true}));

        // and a corrupted public key does not aggregate either
        final byte[] corrupted = copyOf(BlsMultisigConstants.PUBLIC_KEY_2);
        corrupted[17]++;
        assertNull(INSTANCE.aggregatePublicKeys(new byte[][] {corrupted}, new boolean[] {true}));

        // finally, a sanity check that the very same call succeeds with the key restored
        corrupted[17]--;
        assertNotNull(INSTANCE.aggregatePublicKeys(new byte[][] {corrupted}, new boolean[] {true}));
    }
}
