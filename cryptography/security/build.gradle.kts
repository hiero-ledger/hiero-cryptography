// SPDX-License-Identifier: Apache-2.0
plugins { id("org.hiero.gradle.module.library") }

testModuleInfo {
    requires("org.junit.jupiter.api")
    requires("org.junit.jupiter.params")
    requires("org.bouncycastle.provider")
    requires("org.bouncycastle.pkix")
}
