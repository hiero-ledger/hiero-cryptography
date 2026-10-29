// SPDX-License-Identifier: Apache-2.0
/// Java FFM bindings for libsecp256k1.
module com.hedera.cryptography.libsecp256k1 {
    exports com.hedera.cryptography.libsecp256k1;

    requires transitive com.hedera.cryptography.security;
    requires com.hedera.common.nativesupport;
}
