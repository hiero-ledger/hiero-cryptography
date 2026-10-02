// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.benchmark")
}

description = "Ledger-bound ML-DSA-44 transaction signatures for Hedera"

testModuleInfo { requires("org.junit.jupiter.api") }

jmhModuleInfo { requires("com.hedera.cryptography.hcpq") }
