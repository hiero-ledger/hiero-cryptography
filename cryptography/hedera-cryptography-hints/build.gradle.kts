// SPDX-License-Identifier: Apache-2.0
plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("org.hiero.gradle.feature.benchmark")
}

cargo { libname = "hints" }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
}

jmhModuleInfo { requires("com.hedera.cryptography.hints") }

tasks.test {
    jvmArgs("--enable-native-access=com.hedera.common.nativesupport,com.hedera.cryptography.hints")
}
