// SPDX-License-Identifier: Apache-2.0
import org.gradle.api.file.FileSystemOperations
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

@DisableCachingByDefault(because = "Clones an upstream repository")
abstract class PrepareHalo2curves : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val patchFile: RegularFileProperty

    @get:OutputDirectory abstract val localCloneDirectory: DirectoryProperty

    @get:Inject protected abstract val exec: ExecOperations
    @get:Inject protected abstract val files: FileSystemOperations

    @TaskAction
    fun prepare() {
        val localClone = localCloneDirectory.get().asFile
        files.delete { delete(localClone) }
        exec.exec {
            commandLine(
                "git",
                "clone",
                "--depth=1",
                "--branch=v0.9.0",
                "https://github.com/privacy-ethereum/halo2curves.git",
                localClone.absolutePath,
            )
        }
        exec.exec {
            workingDir = localClone
            commandLine("git", "apply", patchFile.get().asFile.absolutePath)
        }
        // Keep the nested repository until checkout and patching are complete.
        files.delete { delete(localClone.resolve(".git")) }
    }
}

val prepareHalo2curves =
    tasks.register<PrepareHalo2curves>("prepareHalo2curves") {
        patchFile =
            layout.projectDirectory.file("src/main/rust/nova-wraps/halo2curves-v0.9.0.patch")
        localCloneDirectory = layout.projectDirectory.dir("src/main/rust/nova-wraps/halo2curves")
    }

tasks.withType<CargoBuildTask>().configureEach { dependsOn(prepareHalo2curves) }

// The following two are to please Gradle:
tasks.named("spotlessJavaInfoFiles").configure { dependsOn(prepareHalo2curves) }

tasks.named("spotlessRust").configure { dependsOn(prepareHalo2curves) }

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
