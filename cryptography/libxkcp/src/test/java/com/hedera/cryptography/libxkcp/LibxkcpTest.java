// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libxkcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LibxkcpTest {
    private static final Libxkcp INSTANCE = Libxkcp.getInstance();

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    private void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    void size() throws Throwable {
        // Just testing if we can call this method and receive a reasonable value.
        // We cannot hard-code a value because it's platform-dependent.
        assertTrue(INSTANCE.hieroSizeofKeccakHashInstance() > 0);

        // Also check if it's the same value as when we loaded the library:
        assertEquals(INSTANCE.sizeOfKeccakHashInstance, INSTANCE.hieroSizeofKeccakHashInstance());
    }

    @Test
    void hash() throws Throwable {
        final byte[] hashInstance = new byte[INSTANCE.sizeOfKeccakHashInstance];
        final MemorySegment hashInstanceSeg = MemorySegment.ofArray(hashInstance);

        assertEquals(
                Libxkcp.KECCAK_SUCCESS,
                INSTANCE.keccakHashInitialize(
                        hashInstanceSeg,
                        Libxkcp.SHA3_256_RATE,
                        Libxkcp.SHA3_256_CAPACITY,
                        Libxkcp.SHA3_256_HASHBITLEN,
                        Libxkcp.SHA3_256_DELIMITED_SUFFIX_ORIGINAL));

        assertEquals(
                Libxkcp.KECCAK_SUCCESS,
                INSTANCE.keccakHashUpdate(
                        hashInstanceSeg, MemorySegment.ofArray(Constants.MESSAGE), Constants.MESSAGE.length * 8L));

        final byte[] hash = new byte[Libxkcp.SHA3_256_HASHVAL_LENGTH_BYTES];
        assertEquals(Libxkcp.KECCAK_SUCCESS, INSTANCE.keccakHashFinal(hashInstanceSeg, MemorySegment.ofArray(hash)));
        assertArrayEquals(Constants.HASH, hash);

        // Also check if we produce the same hash as Bouncy Castle:
        final byte[] bcHash = new Keccak.Digest256().digest(Constants.MESSAGE);
        assertArrayEquals(bcHash, hash);
    }
}
