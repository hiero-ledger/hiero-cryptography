// SPDX-License-Identifier: Apache-2.0
import org.gradle.api.internal.file.FileOperations
import org.gradle.internal.extensions.stdlib.capitalized
import org.gradle.kotlin.dsl.register
import org.hiero.gradle.services.TaskLockService

plugins { id("org.hiero.gradle.module.library") }

/// Where we check out the XKCP repo from GitHub into the local build/ directory:
/// Must end with "libsodium" or whatever name the GitHub repo has:
val libRepositoryDir = layout.buildDirectory.dir("libxkcp/input/XKCP")
/// Where build tasks write output to:
/// Must be outside of input/ above so that Gradle is happy:
val libOutputDir = layout.buildDirectory.dir("libxkcp/output")

// GitClone in hiero-gradle-conventions can't check out commits (only branches or tags).
// But XKCP doesn't have either, so we can only pin a commit. So we add this custom task.
// Also, there's an XKCP-specific last command to clone a git "submodule".
@DisableCachingByDefault(because = "processes large amount of data")
abstract class GitCloneCommit : DefaultTask() {
    @get:Input abstract val url: Property<String>
    @get:Input @get:Optional abstract val commit: Property<String>

    @get:OutputDirectory abstract val localCloneDirectory: DirectoryProperty

    @get:Inject protected abstract val exec: ExecOperations

    @TaskAction
    fun cloneOrUpdate() {
        if (!commit.isPresent) {
            throw RuntimeException("Must define 'commit'")
        }

        val localClone = localCloneDirectory.get()
        exec.exec {
            if (!localClone.dir(".git").asFile.exists()) {
                workingDir = localClone.asFile.parentFile
                commandLine("git", "clone", url.get(), "-q")
            } else {
                workingDir = localClone.asFile
                commandLine("git", "fetch", "-q")
            }
        }
        exec.exec {
            workingDir = localClone.asFile
            commandLine("git", "checkout", commit.get(), "-q")
        }
        exec.exec {
            workingDir = localClone.asFile
            commandLine("git", "reset", "--hard", commit.get(), "-q")
        }

        // This is very specific to XKCP as its build system is in a separate "submodule":
        exec.exec {
            workingDir = localClone.asFile
            commandLine("git", "submodule", "update", "--init", "-q")
        }
    }
}

tasks.register<GitCloneCommit>("cloneXKCP") {
    localCloneDirectory = libRepositoryDir
    url = "https://github.com/XKCP/XKCP.git"

    // A "random" latest commit on 2026-07-27
    commit = "78477d2e0b980737deaa07b928b29302257055ca"
}

// We cannot build from a single repo for multiple targets at once. So we limit parallelizm:
gradle.sharedServices.registerIfAbsent("lock", TaskLockService::class) { maxParallelUsages = 1 }

/// Builds a native library via make and copies .so/.dylib/.dll to resources.
@CacheableTask
abstract class BuildXKCPTask : DefaultTask() {
    @get:ServiceReference("lock") abstract val lock: Property<TaskLockService>

    @get:Inject protected abstract val execOps: ExecOperations
    @get:Inject protected abstract val files: FileOperations

    /// Where the native library repo is checked out via GitClone. Must contain Makefile.
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val libraryDir: DirectoryProperty

    /// `os` string. Relevant for Windows target to rename .so to .dll
    @get:Input abstract val os: Property<String>

    /// XKCP architecture name
    @get:Input abstract val makeArch: Property<String>

    /// XKCP binary name
    @get:Input abstract val makeBin: Property<String>

    /// Extra args for make, such as CC etc.
    @get:Input abstract val makeArgs: ListProperty<String>

    /// Path under the outputDir
    // Likely com/hedera/nativelib/<name>/<os>/<arch>/
    // The os/arch tuple must appear twice in both outputDir and outputPath,
    // because that's how Gradle wants it...
    @get:Input abstract val outputPath: Property<String>

    /// Where the binary library to be written.
    /// Likely build/third-party/<name>/output/<os>-<arch>.
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun action() {
        // Clean everything first. Useful for subsequent cross-platform builds in the same local
        // repo, e.g. in CI.
        execOps.exec {
            workingDir(libraryDir)
            commandLine("make", "clean")
        }

        // Tested (on Mac aarch64 laptop) and not-yet-tested invocations:
        // make ARMv8ASHA3x4/libXKCP.dylib
        //    -> bin/ARMv8ASHA3x4/libXKCP.dylib
        // make x86-64/libXKCP.dylib CC="clang -target x86_64-apple-darwin" EXTRA_CFLAGS="-arch
        // x86_64" EXTRA_LDFLAGS="-arch x86_64"
        //    -> bin/x86-64/libXKCP.dylib
        // make x86-64/libXKCP.so CC=x86_64-w64-mingw32-gcc
        //    -> bin/x86-64/libXKCP.so
        //    RENAME to .dll
        // ? make x86-64/libXKCP.so
        //    -> bin/x86-64/libXKCP.so
        // ? make aarch64/libXKCP.so CC=aarch64-linux-gnu-gcc
        //    -> bin/aarch64/libXKCP.so
        execOps.exec {
            workingDir(libraryDir)

            val cmd = mutableListOf("make", "${makeArch.get()}/${makeBin.get()}")
            makeArgs.get().forEach { cmd.add(it) }
            commandLine(cmd)
        }

        // Copy the lib to the resources
        val libExts = listOf("so", "dylib")
        val filename = libExts.flatMap { libExt -> listOf("libXKCP.${libExt}") }.toList()
        val buildDir = libraryDir.get().dir("bin/${makeArch.get()}")
        val targetDir = outputDir.get().dir(outputPath.get())
        println("Copy $filename from $buildDir/ to $targetDir/")
        files.mkdir(targetDir)
        files.sync {
            from(buildDir)
            into(targetDir)

            include(filename)

            eachFile { println("   Copying: $displayName") }

            // mingw ends up writing a .dll binary into a .so file, so we rename it:
            rename { name -> if (os.get() == "windows") name.replace(".so", ".dll") else name }
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
data class NativeTarget(
    val os: String,
    val arch: String,
    val makeArch: String,
    val makeBin: String,
    val makeArgs: List<String>,
) {}

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

// The targets definition must be the same for all CI runs in order to produce all the necessary
// binaries. However, GitHub makes it excessivley difficult to share a value accross multiple
// GitHub scripts w/o duplicating a lot of code. So we define them here:
val targets =
    if (providers.environmentVariable("CI").getOrElse("false").toBoolean())
        listOf(
            NativeTarget("darwin", "arm64", "ARMv8ASHA3x4", "libXKCP.dylib", listOf()),
            NativeTarget(
                "darwin",
                "amd64",
                "x86-64",
                "libXKCP.dylib",
                listOf(
                    "CC=clang -target x86_64-apple-darwin",
                    "EXTRA_CFLAGS=-arch x86_64",
                    "EXTRA_LDFLAGS=-arch x86_64",
                ),
            ),
            NativeTarget(
                "windows",
                "amd64",
                "x86-64",
                "libXKCP.so",
                listOf("CC=x86_64-w64-mingw32-gcc"),
            ),
            NativeTarget("linux", "amd64", "x86-64", "libXKCP.so", listOf()),
            NativeTarget(
                "linux",
                "arm64",
                "aarch64",
                "libXKCP.so",
                listOf("CC=aarch64-linux-gnu-gcc"),
            ),
        )
    else
        listOf(
            NativeTarget(
                hostOperatingSystem,
                hostArchitecture,
                when (hostOperatingSystem) {
                    "darwin" ->
                        when (hostArchitecture) {
                            "arm64" -> "ARMv8ASHA3x4"
                            "amd64" -> "x86-64"
                            else -> "" // shouldn't happen
                        }
                    "linux" ->
                        when (hostArchitecture) {
                            "amd64" -> "x86-64"
                            "arm64" -> "aarch64"
                            else -> "" // shouldn't happen
                        }
                    else -> hostArchitecture // We don't really support local Windows builds
                },
                when (hostOperatingSystem) {
                    "darwin" -> "libXKCP.dylib"
                    "linux" -> "libXKCP.so"
                    else -> "libXKCP.so" // We don't really support local Windows builds
                },
                listOf(), // local native builds shouldn't require extra args
            )
        )

targets.forEach { target ->
    val name = "buildXKCP" + target.os.capitalized() + target.arch.capitalized()
    val task =
        tasks.register<BuildXKCPTask>(name) {
            libraryDir = tasks.named<GitCloneCommit>("cloneXKCP").flatMap { it.localCloneDirectory }
            os = target.os
            makeArch = target.makeArch
            makeBin = target.makeBin
            makeArgs = target.makeArgs
            outputDir = libOutputDir.get().dir("${target.os}-${target.arch}")
            outputPath = "com/hedera/nativelib/libxkcp/${target.os}/${target.arch}"
        }

    // Include all built native libraries into the .jar and mark them as resources for tests to use:
    sourceSets["main"].resources.srcDir(task)
}
