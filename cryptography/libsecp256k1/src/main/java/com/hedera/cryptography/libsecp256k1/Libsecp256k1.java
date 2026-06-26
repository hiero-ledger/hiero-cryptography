// SPDX-License-Identifier: Apache-2.0
package com.hedera.cryptography.libsecp256k1;

/// Libsecp256k1 native library Java FFM bindings.
/// https://github.com/bitcoin-core/secp256k1 .
public final class Libsecp256k1 {
    // FUTURE WORK: to be implemented

    /// Singleton support
    private static final class InstanceHolder {
        private static final Libsecp256k1 INSTANCE = new Libsecp256k1();
    }

    /// Return a singleton instance of the Libsecp256k1 object.
    public static Libsecp256k1 getInstance() {
        return InstanceHolder.INSTANCE;
    }
}
