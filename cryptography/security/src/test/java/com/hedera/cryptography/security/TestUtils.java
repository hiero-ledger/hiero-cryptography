// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.security;

import java.util.Arrays;
import org.junit.jupiter.api.Assertions;

public final class TestUtils {
    private TestUtils() {}

    /// A helper assertion that also prints entire arrays in addition to the default first mismatching index only
    public static void assertArrayEquals(byte[] expected, byte[] actual) {
        Assertions.assertArrayEquals(
                expected,
                actual,
                () -> "Expected:\n" + Arrays.toString(expected) + "\nbut got:\n" + Arrays.toString(actual) + "\n");
    }
}
