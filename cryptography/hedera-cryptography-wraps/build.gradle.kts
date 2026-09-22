// SPDX-License-Identifier: Apache-2.0
import org.hiero.gradle.extensions.CargoToolchain
import org.hiero.gradle.tasks.CargoBuildTask

plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("org.hiero.gradle.feature.benchmark")
    id("DownloadWrapsArtifactTask")
}

cargo {
    libname = "wraps"
    appname = "ceremony"
}

testModuleInfo { requires("org.junit.jupiter.api") }

jmhModuleInfo {
    requires("com.hedera.cryptography.hints")
    requires("com.hedera.cryptography.wraps")
}

// remove license header check for rust files
spotless { format("rust") { clearSteps() } }

tasks.test {
    jvmArgs(
        "--enable-native-access=com.hedera.common.nativesupport,com.hedera.cryptography.hints,com.hedera.cryptography.wraps"
    )
    environment(
        mapOf(
            // For the TSS lib:
            "TSS_LIB_NUM_OF_CORES" to "10"
        )
    )
}

// Build `ceremony` in the current -wraps module, and make it available for the -ceremony build to
// consume:
tasks.processResources { exclude("com/hedera/nativelib/ceremony/**") }

// export native binaries built with rust as separate artifacts
configurations.consumable("nativeBinElements") {
    attributes.attribute(Usage.USAGE_ATTRIBUTE, objects.named("native-bin"))
    CargoToolchain.entries.forEach { target ->
        // The below if conditions should be added once this is integrated:
        // https://github.com/hiero-ledger/hiero-gradle-conventions/pull/416
        // if (packageAllTargets || (target.os == hostOs() && target.arch == hostArch()))
        outgoing.artifact(
            tasks
                .named<CargoBuildTask>("cargoBuild${target.name.replaceFirstChar(Char::titlecase)}")
                .flatMap { it.destinationDirectory }
        )
    }
}
