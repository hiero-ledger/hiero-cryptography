// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libxkcp;

/// libXKCP native library Java FFM bindings.
/// https://github.com/XKCP/XKCP .
public final class Libxkcp {

    /// Singleton support
    private static final class InstanceHolder {
        private static final Libxkcp INSTANCE = new Libxkcp();
    }

    /// Return a singleton instance of the Libxkcp object.
    public static Libxkcp getInstance() {
        return InstanceHolder.INSTANCE;
    }

    // FUTURE WORK: implement it
}
