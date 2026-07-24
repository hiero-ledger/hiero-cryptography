// SPDX-License-Identifier: Apache-2.0
pluginManagement { includeBuild("gradle/plugins") }

plugins { id("org.hiero.gradle.build") version "0.7.11" }

rootProject.name = "hedera-cryptography"

javaModules {
    directory("common") { group = "com.hedera.common" }
    directory("cryptography") { group = "com.hedera.cryptography" }
}
