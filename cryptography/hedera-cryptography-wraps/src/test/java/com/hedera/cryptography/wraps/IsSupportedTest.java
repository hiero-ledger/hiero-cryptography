// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.wraps;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.net.URLClassLoader;
import java.security.CodeSource;
import org.junit.jupiter.api.Test;

/// Test if isVerificationSupported methods works before getInstance().
public class IsSupportedTest {
    private static final String NATIVE_SUPPORT_CLASS = "com.hedera.common.nativesupport.SingletonLoader";

    @Test
    public void testIsVerificationSupported() throws Exception {
        // Other tests in this repository may have already loaded and initialized the WRAPSLibraryBridge class,
        // in which case calling the isSupported() would pass anyway.
        // In this test, we want to check if we can call a static isSupported() method from this class
        // BEFORE calling its getInstance() method. For this reason, we want to load this class into the JVM
        // again, using a custom class loader. This is how we do it:
        // (the approach was borrowed from IsolatedHintsLibrary.java
        // at
        // https://github.com/hiero-ledger/hiero-consensus-node/pull/27506/changes/BASE..ce15c40ae684d5b6c19eb662dac76efb7b4ec0a2#diff-431af84e3ae57bc201147fa8115c75c1f9bbd0f2119e894de85ed35bd70d4f1e
        // ):
        URLClassLoader loader = null;
        try {
            final Class<?> nativeSupport =
                    Class.forName(NATIVE_SUPPORT_CLASS, false, WRAPSLibraryBridge.class.getClassLoader());
            final String resourcesLocation =
                    locationOf(WRAPSLibraryBridge.class).toString().replace("classes/java/main/", "resources/main/");
            loader = new URLClassLoader(
                    new URL[] {
                        locationOf(WRAPSLibraryBridge.class), locationOf(nativeSupport), new URL(resourcesLocation)
                    },
                    null);
            final Class<?> bridgeType = Class.forName(WRAPSLibraryBridge.class.getName(), true, loader);
            requireIsolated(bridgeType, loader);
            requireIsolated(Class.forName(NATIVE_SUPPORT_CLASS, false, loader), loader);

            // First, try calling the isSupported method BEFORE an instance of the class is created:
            final Boolean isSupported =
                    (Boolean) bridgeType.getMethod("isVerificationSupported").invoke(null);
            assertTrue(isSupported);

            // Then try calling getInstance():
            final Object bridge = bridgeType.getMethod("getInstance").invoke(null);
            assertNotNull(bridge);
        } finally {
            if (loader != null) {
                loader.close();
            }
        }
    }

    private static void requireIsolated(final Class<?> type, final URLClassLoader loader) {
        if (type.getClassLoader() != loader) {
            throw new IllegalStateException("Class is not isolated: " + type.getName());
        }
    }

    private static URL locationOf(final Class<?> type) {
        final CodeSource source = requireNonNull(type.getProtectionDomain().getCodeSource(), "Missing location");
        return source.getLocation();
    }
}
