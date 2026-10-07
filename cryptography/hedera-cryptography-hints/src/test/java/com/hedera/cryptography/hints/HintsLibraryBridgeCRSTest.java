// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static com.hedera.cryptography.hints.HintsLibraryBridge.MAX_SIGNERS_NUM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HintsLibraryBridgeCRSTest {
    private static final HintsLibraryBridge INSTANCE = HintsLibraryBridge.getInstance();

    private static final int CRS_4_LENGTH = 1456;

    private static final int CONTRIBUTION_PROOF_LENGTH = 128;

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    private byte[] initAndVerifyCRS() {
        final byte[] crs = INSTANCE.initCRS((short) 4);

        assertNotNull(crs);
        assertEquals(CRS_4_LENGTH, crs.length);
        assertArrayEquals(CRSConstants.INIT_CRS_4, crs);

        return crs;
    }

    @Test
    void testInitCRS() {
        initAndVerifyCRS();
    }

    @Test
    void testInitCRSConstraints() {
        assertNull(INSTANCE.initCRS((short) 0));
        assertNull(INSTANCE.initCRS((short) -2));
        assertNull(INSTANCE.initCRS(Short.MIN_VALUE));

        assertNull(INSTANCE.initCRS((short) (MAX_SIGNERS_NUM + 2)));
    }

    @Test
    void testPruneCRS() {
        final byte[] origCRS = INSTANCE.initCRS((short) 4);
        final byte[] crs = INSTANCE.pruneCRS(origCRS, (short) 2);
        assertArrayEquals(CRSConstants.PRUNE_CRS_2, crs);

        // A full universe needs one CRS slot beyond the maximum number of signers.
        final short maxDegree = (short) (MAX_SIGNERS_NUM + 1);
        final byte[] maxCRS = INSTANCE.initCRS(maxDegree);
        assertNotNull(maxCRS);
        assertArrayEquals(maxCRS, INSTANCE.pruneCRS(maxCRS, maxDegree));
    }

    @Test
    void testPruneCRSConstraints() {
        final byte[] crs = INSTANCE.initCRS((short) 4);

        assertNull(INSTANCE.pruneCRS(null, (short) 4));

        assertNull(INSTANCE.pruneCRS(crs, (short) 0));
        assertNull(INSTANCE.pruneCRS(crs, (short) -2));
        assertNull(INSTANCE.pruneCRS(crs, Short.MIN_VALUE));

        assertNull(INSTANCE.pruneCRS(crs, (short) (MAX_SIGNERS_NUM + 2)));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 11, MAX_SIGNERS_NUM, MAX_SIGNERS_NUM + 1})
    void testInitCRSLength(final int n) {
        assertEquals(304 + n * 288, INSTANCE.initCRS((short) n).length);
    }

    private byte[] updateAndVerifyCRS(final byte[] prevCRS) {
        final byte[] nextCRSandContributionProof = INSTANCE.updateCRS(prevCRS, CRSConstants.RANDOM);

        assertNotNull(nextCRSandContributionProof);
        assertEquals(CRS_4_LENGTH + CONTRIBUTION_PROOF_LENGTH, nextCRSandContributionProof.length);

        // The ContributionProof is random by design, so we can only check the nextCRS which is deterministic
        // given the constant prevCRS and randomness inputs in the updateCRS call above:
        final byte[] nextCRS = Arrays.copyOf(nextCRSandContributionProof, CRS_4_LENGTH);
        assertArrayEquals(CRSConstants.UPDATED_CRS_4, nextCRS);

        return nextCRSandContributionProof;
    }

    @Test
    void testUpdateCRS() {
        final byte[] prevCRS = initAndVerifyCRS();

        updateAndVerifyCRS(prevCRS);
    }

    @Test
    void testUpdateCRSConstraints() {
        assertNull(INSTANCE.updateCRS(null, CRSConstants.RANDOM));
        assertNull(INSTANCE.updateCRS(initAndVerifyCRS(), null));

        // Only byte[32] is valid for entropy input:
        assertNull(INSTANCE.updateCRS(initAndVerifyCRS(), new byte[0]));
        assertNull(INSTANCE.updateCRS(initAndVerifyCRS(), new byte[2]));
        assertNull(INSTANCE.updateCRS(initAndVerifyCRS(), new byte[33]));

        // Only a real CRS should work correctly
        assertNull(INSTANCE.updateCRS(new byte[0], CRSConstants.RANDOM));
        assertNull(INSTANCE.updateCRS(new byte[1], CRSConstants.RANDOM));

        // These two could cause a panic, but we can handle that gracefully:
        assertNull(INSTANCE.updateCRS(new byte[16], CRSConstants.RANDOM));
        assertNull(INSTANCE.updateCRS(new byte[100], new byte[32]));
    }

    @Test
    void testVerifyCRS() {
        final byte[] prevCRS = initAndVerifyCRS();
        final byte[] nextCRSandContributionProof = updateAndVerifyCRS(prevCRS);

        final byte[] nextCRS = Arrays.copyOf(nextCRSandContributionProof, CRS_4_LENGTH);
        final byte[] contributionProof =
                Arrays.copyOfRange(nextCRSandContributionProof, CRS_4_LENGTH, nextCRSandContributionProof.length);

        assertTrue(INSTANCE.verifyCRS(prevCRS, nextCRS, contributionProof));

        // Damage the nextCRS first:
        nextCRS[456]++;
        nextCRS[917]--;
        nextCRS[1357]++;

        assertFalse(INSTANCE.verifyCRS(prevCRS, nextCRS, contributionProof));

        // Undo the nextCRS dmage:
        nextCRS[456]--;
        nextCRS[917]++;
        nextCRS[1357]--;
        // and damage the contributionProof instead:
        contributionProof[55]++;
        contributionProof[79]--;
        contributionProof[102]++;

        assertFalse(INSTANCE.verifyCRS(prevCRS, nextCRS, contributionProof));

        // Restore the contributionProof back, and check one more time, just for sanity:
        contributionProof[55]--;
        contributionProof[79]++;
        contributionProof[102]--;

        assertTrue(INSTANCE.verifyCRS(prevCRS, nextCRS, contributionProof));
    }

    @Test
    void testVerifyCRSConstraints() {
        final byte[] prevCRS = initAndVerifyCRS();
        final byte[] nextCRSandContributionProof = updateAndVerifyCRS(prevCRS);

        final byte[] nextCRS = Arrays.copyOf(nextCRSandContributionProof, CRS_4_LENGTH);
        final byte[] contributionProof =
                Arrays.copyOfRange(nextCRSandContributionProof, CRS_4_LENGTH, nextCRSandContributionProof.length);

        assertFalse(INSTANCE.verifyCRS(null, nextCRS, contributionProof));
        assertFalse(INSTANCE.verifyCRS(prevCRS, null, contributionProof));
        assertFalse(INSTANCE.verifyCRS(prevCRS, nextCRS, null));
    }
}
