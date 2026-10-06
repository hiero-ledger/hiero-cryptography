// SPDX-License-Identifier: Apache-2.0
pluginManagement { includeBuild("gradle/plugins") }

plugins { id("org.hiero.cryptography.gradle.build") }

rootProject.name = "hedera-cryptography"

javaModules {
    directory("common") { group = "com.hedera.common" }
    directory("cryptography") { group = "com.hedera.cryptography" }
}
