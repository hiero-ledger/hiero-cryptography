// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.foreign.MemorySegment;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Libsecp256k1Test {
    private static final ContextualLibsecp256k1 INSTANCE = ContextualLibsecp256k1.getInstance();

    // A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    private void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }

    @Test
    void secp256k1EcPubkeyCreate() throws Throwable {
        byte[] pk = new byte[64];

        assertEquals(
                1, INSTANCE.secp256k1EcPubkeyCreate(MemorySegment.ofArray(pk), MemorySegment.ofArray(Constants.SK)));

        assertArrayEquals(Constants.PK, pk);
    }

    @Test
    void secp256k1EcPubkeySerialize() throws Throwable {
        long[] size = new long[1];

        byte[] output = new byte[65];
        size[0] = output.length;
        assertEquals(
                1,
                INSTANCE.secp256k1EcPubkeySerialize(
                        MemorySegment.ofArray(output),
                        MemorySegment.ofArray(size),
                        MemorySegment.ofArray(Constants.PK),
                        Libsecp256k1.SECP256K1_EC_UNCOMPRESSED));
        assertEquals(65, size[0]);
        assertArrayEquals(Constants.UNCOMPRESSED, output);

        byte[] pk = new byte[64];
        assertEquals(1, INSTANCE.secp256k1EcPubkeyParse(MemorySegment.ofArray(pk), MemorySegment.ofArray(output), 65));
        assertArrayEquals(Constants.PK, pk);

        size[0] = output.length;
        assertEquals(
                1,
                INSTANCE.secp256k1EcPubkeySerialize(
                        MemorySegment.ofArray(output),
                        MemorySegment.ofArray(size),
                        MemorySegment.ofArray(Constants.PK),
                        Libsecp256k1.SECP256K1_EC_COMPRESSED));
        assertEquals(33, size[0]);
        assertArrayEquals(Constants.COMPRESSED, Arrays.copyOf(output, 33));

        Arrays.fill(pk, (byte) 0);
        assertEquals(
                1,
                INSTANCE.secp256k1EcPubkeyParse(
                        MemorySegment.ofArray(pk), MemorySegment.ofArray(Arrays.copyOf(output, 33)), 33));
        assertArrayEquals(Constants.PK, pk);
    }
}
