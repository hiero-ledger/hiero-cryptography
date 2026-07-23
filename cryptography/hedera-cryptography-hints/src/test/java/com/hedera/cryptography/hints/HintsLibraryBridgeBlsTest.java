// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.hints;

import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HintsLibraryBridgeBlsTest {
    private static final HintsLibraryBridge INSTANCE = HintsLibraryBridge.getInstance();

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

    // -------------------------------------------------------------------------
    // decompressG1ToEip2537
    // -------------------------------------------------------------------------

    @Test
    void testDecompressG1ToEip2537() {
        assertArrayEquals(BlsConstants.G1_EIP2537, INSTANCE.decompressG1ToEip2537(BlsConstants.G1_COMPRESSED));
    }

    @Test
    void testDecompressG1ToEip2537NullInput() {
        assertNull(INSTANCE.decompressG1ToEip2537(null));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 47, 49, 96})
    void testDecompressG1ToEip2537WrongLength(int length) {
        assertNull(INSTANCE.decompressG1ToEip2537(new byte[length]));
    }

    @Test
    void testDecompressG1ToEip2537InvalidPoint() {
        // 48 zero bytes is not a valid compressed G1 point.
        assertNull(INSTANCE.decompressG1ToEip2537(new byte[48]));
    }

    // -------------------------------------------------------------------------
    // decompressG2ToEip2537
    // -------------------------------------------------------------------------

    @Test
    void testDecompressG2ToEip2537() {
        assertArrayEquals(BlsConstants.G2_EIP2537, INSTANCE.decompressG2ToEip2537(BlsConstants.G2_COMPRESSED));
    }

    @Test
    void testDecompressG2ToEip2537NullInput() {
        assertNull(INSTANCE.decompressG2ToEip2537(null));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 48, 95, 97, 128})
    void testDecompressG2ToEip2537WrongLength(int length) {
        assertNull(INSTANCE.decompressG2ToEip2537(new byte[length]));
    }

    @Test
    void testDecompressG2ToEip2537InvalidPoint() {
        // 96 zero bytes is not a valid compressed G2 point.
        assertNull(INSTANCE.decompressG2ToEip2537(new byte[96]));
    }
}