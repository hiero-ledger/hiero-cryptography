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
    dependsOn("downloadWrapsArtifactTask")
    jvmArgs(
        "--enable-native-access=com.hedera.common.nativesupport,com.hedera.cryptography.hints,com.hedera.cryptography.wraps"
    )
    environment(
        mapOf(
            // For the TSS lib:
            "TSS_LIB_NUM_OF_CORES" to "10",

            // Path to nova_pp.bin, decider_pp.bin, nova_vp.bin, and decider_vp.bin :
            "TSS_LIB_WRAPS_ARTIFACTS_PATH" to
                (tasks.named("downloadWrapsArtifactTask").get().property("wrapsDir")
                        as DirectoryProperty)
                    .get()
                    .dir("v1.6.0")
                    .asFile
                    .absolutePath,

            // Cache the proving key so we can construct proof multiple times in the same JVM
            // w/o having to reload the proving key, which takes up to 27 minutes.
            "TSS_LIB_WRAPS_ARTIFACTS_CACHE_ENABLED" to "true",

            // Commented-out just to provide an example of how to enable swap for WRAPS 2.0.
            // When not set, the proof construction may require up to ~16GB of RAM.
            // "TSS_LIB_WRAPS_SWAP_FILE" to "/tmp/MemoryMapFile",
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
