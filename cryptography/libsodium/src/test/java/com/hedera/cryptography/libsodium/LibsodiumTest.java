// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsodium;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibsodiumTest {
    private static final Libsodium INSTANCE = Libsodium.getInstance();

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    private void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    void cryptoSignKeypair() throws Throwable {
        byte[] pk = new byte[32];
        byte[] sk = new byte[64];

        assertEquals(0, INSTANCE.cryptoSignKeypair(MemorySegment.ofArray(pk), MemorySegment.ofArray(sk)));

        boolean hasNonZero = false;
        for (int i = 0; i < pk.length; i++) {
            if (pk[i] != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Generated pk must have non-zero bytes");

        hasNonZero = false;
        for (int i = 0; i < sk.length; i++) {
            if (sk[i] != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Generated sk must have non-zero bytes");

        byte[] pk2 = new byte[32];
        byte[] sk2 = new byte[64];
        assertEquals(0, INSTANCE.cryptoSignKeypair(MemorySegment.ofArray(pk2), MemorySegment.ofArray(sk2)));

        assertFalse(Arrays.equals(pk, pk2), "Generated pks must have different bytes");
        assertFalse(Arrays.equals(sk, sk2), "Generated sks must have different bytes");
    }

    @Test
    void cryptoSignDetached() throws Throwable {
        byte[] sig = new byte[64];
        byte[] sigLen = new byte[Long.BYTES];

        assertEquals(
                0,
                INSTANCE.cryptoSignDetached(
                        MemorySegment.ofArray(sig),
                        MemorySegment.ofArray(sigLen),
                        MemorySegment.ofArray(Constants.M),
                        Constants.M.length,
                        MemorySegment.ofArray(Constants.SK)));

        assertEquals(64, sigLen[0]);
        for (int i = 1; i < sigLen.length; i++) {
            assertEquals(0, sigLen[i]);
        }

        assertArrayEquals(Constants.SIG, sig);
    }

    @Test
    void cryptoSignDetachedNullSiglenP() throws Throwable {
        byte[] sig = new byte[64];

        assertEquals(
                0,
                INSTANCE.cryptoSignDetached(
                        MemorySegment.ofArray(sig),
                        null,
                        MemorySegment.ofArray(Constants.M),
                        Constants.M.length,
                        MemorySegment.ofArray(Constants.SK)));

        assertArrayEquals(Constants.SIG, sig);
    }

    @Test
    void cryptoSignVerifyDetached() throws Throwable {
        assertEquals(
                0,
                INSTANCE.cryptoSignVerifyDetached(
                        MemorySegment.ofArray(Constants.SIG),
                        MemorySegment.ofArray(Constants.M),
                        Constants.M.length,
                        MemorySegment.ofArray(Constants.PK)));

        final byte[] badSig = Arrays.copyOf(Constants.SIG, Constants.SIG.length);
        badSig[badSig.length / 2]++;
        final byte[] badM = Arrays.copyOf(Constants.M, Constants.M.length);
        badM[badM.length / 2]++;
        final byte[] badPK = Arrays.copyOf(Constants.PK, Constants.PK.length);
        badPK[badPK.length / 2]++;

        assertNotEquals(
                0,
                INSTANCE.cryptoSignVerifyDetached(
                        MemorySegment.ofArray(badSig),
                        MemorySegment.ofArray(Constants.M),
                        Constants.M.length,
                        MemorySegment.ofArray(Constants.PK)));
        assertNotEquals(
                0,
                INSTANCE.cryptoSignVerifyDetached(
                        MemorySegment.ofArray(Constants.SIG),
                        MemorySegment.ofArray(badM),
                        Constants.M.length,
                        MemorySegment.ofArray(Constants.PK)));
        assertNotEquals(
                0,
                INSTANCE.cryptoSignVerifyDetached(
                        MemorySegment.ofArray(Constants.SIG),
                        MemorySegment.ofArray(Constants.M),
                        Constants.M.length - 1,
                        MemorySegment.ofArray(Constants.PK)));
        assertNotEquals(
                0,
                INSTANCE.cryptoSignVerifyDetached(
                        MemorySegment.ofArray(Constants.SIG),
                        MemorySegment.ofArray(Constants.M),
                        Constants.M.length,
                        MemorySegment.ofArray(badPK)));
    }
}
