// SPDX-License-Identifier: Apache-2.0
import org.gradle.api.internal.file.FileOperations
import org.gradle.internal.extensions.stdlib.capitalized
import org.gradle.kotlin.dsl.register
import org.hiero.gradle.services.TaskLockService
import org.hiero.gradle.tasks.GitClone

plugins { id("org.hiero.gradle.module.library") }

testModuleInfo { requires("org.junit.jupiter.api") }

tasks.test {
    jvmArgs(
        "--enable-native-access=com.hedera.common.nativesupport,com.hedera.cryptography.libsecp256k1"
    )
}

/// Where we check out the native library repo from GitHub into the local build/ directory:
/// Must end with the name the GitHub repo has:
val libRepositoryDir = layout.buildDirectory.dir("libsecp256k1/input/secp256k1")
/// Where build tasks write output to:
/// Must be outside of input/ above so that Gradle is happy:
val libOutputDir = layout.buildDirectory.dir("libsecp256k1/output")

tasks.register<GitClone>("cloneSecp256k1") {
    localCloneDirectory = libRepositoryDir
    url = "https://github.com/bitcoin-core/secp256k1.git"
    // branch = "master"
    tag = "v0.7.1"
}

// We cannot build from a single repo for multiple targets at once. So we limit parallelizm:
gradle.sharedServices.registerIfAbsent("lock", TaskLockService::class) { maxParallelUsages = 1 }

/// Builds a native library via ./configure && make and copies .so/.dylib/.dll to resources.
@CacheableTask
abstract class BuildSecp256k1Task : DefaultTask() {
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
        } else {
            // Generate the Makefile
            execOps.exec {
                workingDir(libraryDir)
                commandLine("sh", "./autogen.sh")
            }
        }

        execOps.exec {
            // enable ECDSA pubkey recovery module:
            val cmd = mutableListOf("sh", "./configure", "--enable-module-recovery")
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
        // secp256k1 native build adds a "-/.6" suffix/infix to the lib name.
        // It has something to do with ABI version or maybe something else.
        val filename =
            libExts
                .flatMap { libExt ->
                    listOf("libsecp256k1?6.${libExt}", "libsecp256k1.${libExt}.6")
                }
                .toList()
        val buildDir = libraryDir.get().dir(".libs")
        val targetDir = outputDir.get().dir(outputPath.get())
        println("Copy $filename from $buildDir/ to $targetDir/")
        files.mkdir(targetDir)
        files.sync {
            from(buildDir)
            into(targetDir)

            include(filename)

            eachFile { println("   Copying: $displayName") }

            // Remove the "-/.6" suffix because we don't need it.
            rename { name -> name.replace(".6", "").replace("-6", "") }
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
// Each defined target will result in creating a :libsodium:buildSecp256k1<Os><Arch> Gradle task
// where <Os> and <Arch> will be capitalized versions of the os and arch from the target name.
// The output of each task will be added as resources to the main sourceSet.
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
    val name = "buildSecp256k1" + target.os.capitalized() + target.arch.capitalized()
    val task =
        tasks.register<BuildSecp256k1Task>(name) {
            libraryDir = tasks.named<GitClone>("cloneSecp256k1").flatMap { it.localCloneDirectory }
            configureHost = target.configureHost
            targetId = "${target.os}-${target.arch}"
            outputDir = libOutputDir.get().dir("${target.os}-${target.arch}")
            outputPath = "com/hedera/nativelib/libsecp256k1/${target.os}/${target.arch}"
        }

    // Include all built native libraries into the .jar and mark them as resources for tests to use:
    sourceSets["main"].resources.srcDir(task)
}
