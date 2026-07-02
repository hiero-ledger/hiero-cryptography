// SPDX-License-Identifier: Apache-2.0
import org.gradle.api.internal.file.FileOperations
import org.gradle.internal.extensions.stdlib.capitalized
import org.gradle.kotlin.dsl.register
import org.hiero.gradle.services.TaskLockService
import org.hiero.gradle.tasks.GitClone

plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.benchmark")
}

testModuleInfo { requires("org.junit.jupiter.api") }

tasks.test {
    jvmArgs(
        "--enable-native-access=com.hedera.common.nativesupport,com.hedera.cryptography.libsodium"
    )
}

jmhModuleInfo {
    requires("com.hedera.cryptography.libsodium")
    requires("com.goterl.lazysodium")
    requires("com.hedera.pbj.runtime")
}

/// Where we check out the libsodium repo from GitHub into the local build/ directory:
/// Must end with "libsodium" or whatever name the GitHub repo has:
val libRepositoryDir = layout.buildDirectory.dir("libsodium/input/libsodium")
/// Where build tasks write output to:
/// Must be outside of input/ above so that Gradle is happy:
val libOutputDir = layout.buildDirectory.dir("libsodium/output")

tasks.register<GitClone>("cloneLibsodium") {
    localCloneDirectory = libRepositoryDir
    url = "https://github.com/jedisct1/libsodium.git"
    // branch = "master"
    tag = "1.0.22-RELEASE"
}

// We cannot build from a single repo for multiple targets at once. So we limit parallelizm:
gradle.sharedServices.registerIfAbsent("lock", TaskLockService::class) { maxParallelUsages = 1 }

/// Builds a native library via ./configure && make and copies .so/.dylib/.dll to resources.
@CacheableTask
abstract class BuildLibsodiumTask : DefaultTask() {
    @get:ServiceReference("lock") abstract val lock: Property<TaskLockService>

    @get:Inject protected abstract val execOps: ExecOperations
    @get:Inject protected abstract val files: FileOperations

    /// Where the native library repo is checked out via GitClone. Must contain ./configure.
    /// Likely build/third-party/<name>/repository.
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val libraryDir: DirectoryProperty

    /// ./configure --host ... string, or a blank string to omit the --host arg.
    @get:Input abstract val configureHost: Property<String>

    /// To make Gradle Cache happy, we're adding yet another input property that contains "os-arch".
    /// Apparently, the `outputPath` below is insufficient for Gradle Cache to key an entry.
    @get:Input abstract val targetId: Property<String>

    /// Where the binary library to be written.
    /// Likely build/third-party/<name>/output/<os>-<arch>.
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    /// Path under the outputDir
    // Likely com/hedera/nativelib/<name>/<os>/<arch>/
    // The os/arch tuple must appear twice in both outputDir and outputPath,
    // because that's how Gradle wants it...
    @get:Input abstract val outputPath: Property<String>

    @TaskAction
    fun action() {
        // Clean everything first. Useful for subsequent cross-platform builds in the same local
        // repo, e.g. in CI.
        val makefileExists = files.file(libraryDir.file("Makefile")).exists()
        if (makefileExists) {
            execOps.exec {
                workingDir(libraryDir)
                commandLine("make", "clean")
            }
        }

        execOps.exec {
            val cmd = mutableListOf("sh", "./configure")
            if (configureHost.get() != "") {
                // ./configure calls target a "host", so:
                cmd.add("--host")
                cmd.add(configureHost.get())
            }

            workingDir(libraryDir)
            commandLine(cmd)
        }

        execOps.exec {
            workingDir(libraryDir)
            commandLine("make")
        }

        // Copy the lib to the resources
        val libExts = listOf("so", "dylib", "dll")
        // libsodium native build adds a "-/.26" suffix/infix to the lib name.
        // It has something to do with ABI version or maybe something else.
        val filename =
            libExts
                .flatMap { libExt -> listOf("libsodium?26.${libExt}", "libsodium.${libExt}.26") }
                .toList()
        val buildDir = libraryDir.get().dir("src/libsodium/.libs")
        val targetDir = outputDir.get().dir(outputPath.get())
        println("Copy $filename from $buildDir/ to $targetDir/")
        files.mkdir(targetDir)
        files.sync {
            from(buildDir)
            into(targetDir)

            include(filename)

            eachFile { println("   Copying: $displayName") }

            // Remove the "-/.26" suffix because we don't need it.
            rename { name -> name.replace(".26", "").replace("-26", "") }
        }
        println("Finished copying files.")
        // The output dir w/o the os/arch/ path to print everything we have so far:
        val resourcesDir = outputDir.get().file("..").asFile.absolutePath
        println("Destination listing so far: $resourcesDir")
        execOps.exec { commandLine("ls", "-lR", resourcesDir) }
        println("-----")
    }
}

/// A descriptor for a native target
data class NativeTarget(val os: String, val arch: String, val configureHost: String) {}

// HIERO_NATIVE_TARGETS env var can be defined to cross-build for different platforms.
// If undefined, only a build for the local host target will be performed.
// Example:
//
// HIERO_NATIVE_TARGETS="darwin-arm64;darwin-amd64,x86_64-apple-darwin;linux-amd64;linux-arm64,aarch64-linux-gnu;windows-amd64,x86_64-w64-mingw32"
//
// This is a semicolon-separated list of target definitions. Each definition starts with a target
// name in the form of os-arch, where os is linux, darwin, or windows, and arch is amd64 or arm64.
// The target definition can optionally be followed by a comma and a ./configure --host ...
// value that will be passed to the ./configure script to use a proper toolchain for cross-
// compilation. If the host value is missing, then ./configure will be invoked w/o any parameters,
// assuming a local host build for the local host target (i.e. no cross-compilation.)
//
// Each defined target will result in creating a :libsodium:buildLibsodium<Os><Arch> Gradle task
// where <Os> and <Arch> will be capitalized versions of the os and arch from the target name.
//
// The :libsodium:compile[Test]Java targets will take a dependency on the local host target build
// task only. This is to ensure that unit tests can access a local host target-built native library.
//
// The jar task takes a dependency on all the buildLibsodium tasks for all targets.
// This is to ensure that the published artifact in CI has native libraries for all supported
// platforms.
//
// Individual GitHub CI runner tasks could build specific targets on specific hosts (e.g. darwin on
// Mac) and the Gradle Cache will take care of aggregating all the results when assembling the final
// artifact to be published to Maven.
val hostOperatingSystem =
    System.getProperty("os.name").lowercase().let {
        if (it.contains("windows")) {
            "windows"
        } else if (it.contains("mac")) {
            "darwin"
        } else {
            "linux"
        }
    }
val hostArchitecture =
    System.getProperty("os.arch").let {
        if (it.contains("x86_64")) {
            "amd64"
        } else if (it.contains("aarch64")) {
            "arm64"
        } else {
            // There's "386" and "armv6l" at https://go.dev/dl/ .
            it
        }
    }

val targets =
    providers
        .environmentVariable("HIERO_NATIVE_TARGETS")
        .map { targetsString ->
            targetsString
                .split(";")
                .map { targetDef ->
                    val targetDefParts = targetDef.split(",")
                    val osArch = targetDefParts[0].split("-")
                    NativeTarget(
                        osArch[0],
                        osArch[1],
                        if (targetDefParts.size > 1) targetDefParts[1] else "",
                    )
                }
                .toList()
        }
        .orElse(listOf(NativeTarget(hostOperatingSystem, hostArchitecture, "")))
        .get()

targets.forEach { target ->
    val name = "buildLibsodium" + target.os.capitalized() + target.arch.capitalized()
    val task =
        tasks.register<BuildLibsodiumTask>(name) {
            libraryDir = tasks.named<GitClone>("cloneLibsodium").flatMap { it.localCloneDirectory }
            configureHost = target.configureHost
            targetId = "${target.os}-${target.arch}"
            outputDir = libOutputDir.get().dir("${target.os}-${target.arch}")
            outputPath = "com/hedera/nativelib/libsodium/${target.os}/${target.arch}"
        }

    // Include all built native libraries into the .jar and mark them as resources for tests to use:
    sourceSets["main"].resources.srcDir(task)
}
