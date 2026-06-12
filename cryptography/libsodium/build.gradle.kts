// SPDX-License-Identifier: Apache-2.0
import java.util.regex.Pattern
import org.gradle.api.internal.file.FileOperations
import org.hiero.gradle.tasks.GitClone

plugins { id("org.hiero.gradle.module.library") }

val libDir = layout.buildDirectory.dir("libsodium")

tasks.register<GitClone>("cloneLibsodium") {
    localCloneDirectory = libDir
    url = "https://github.com/jedisct1/libsodium.git"
    // branch = "master"
    tag = "1.0.22-RELEASE"
}

interface Injected {
    @get:Inject val execOps: ExecOperations
    @get:Inject val files: FileOperations
}

tasks.assemble {
    val injected = objects.newInstance(Injected::class.java)

    val srcDir = libDir.get()
    val makefileExists = file(srcDir.file("Makefile")).exists()
    val buildDir = libDir.get().dir("src/libsodium/.libs")
    val dstDir = layout.buildDirectory.dir("resources/main/com/hedera/nativelib/libsodium")

    dependsOn("cloneLibsodium")

    // HIERO_LIBSODIUM_TARGET=os-arch
    // where os is linux, darwin, or windows, and arch is amd64 or arm64
    // Example: HIERO_LIBSODIUM_TARGET=darwin-amd64
    // By default, assume we build for the host target and infer the value of HIERO_LIBSODIUM_TARGET
    // accordingly. If HIERO_LIBSODIUM_TARGET env var is defined explicitly, then the caller should
    // probably also define HIERO_LIBSODIUM_CONFIGURE_HOST to let ./configure --host ... choose the
    // correct toolchain. The caller may also define CFLAGS, CC, AR, and whatever else if needed.
    // For example, to build for Windows target (e.g. on a Mac host) run:
    // HIERO_LIBSODIUM_TARGET=windows-amd64 HIERO_LIBSODIUM_CONFIGURE_HOST=x86_64-w64-mingw32
    // ./gradlew assemble
    val target =
        providers
            .environmentVariable("HIERO_LIBSODIUM_TARGET")
            .orElse(
                providers.provider {
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

                    "${hostOperatingSystem}-${hostArchitecture}"
                }
            )
            .get()
    val targetOsArch = target.split(Pattern.compile("-"), 2)

    val hieroLibsodiumConfigureHost =
        providers.environmentVariable("HIERO_LIBSODIUM_CONFIGURE_HOST").orElse("").get()

    doFirst {
        // Clean everything first. Useful for subsequent cross-platform builds in the same local
        // repo, e.g. in CI.
        if (makefileExists) {
            injected.execOps.exec {
                workingDir(srcDir)
                commandLine("make", "clean")
            }
        }

        injected.execOps.exec {
            val cmd = mutableListOf("sh", "./configure")
            if (hieroLibsodiumConfigureHost != "") {
                // ./configure calls target a "host", so:
                cmd.add("--host")
                cmd.add(hieroLibsodiumConfigureHost)
            }

            workingDir(srcDir)
            commandLine(cmd)
        }

        injected.execOps.exec {
            workingDir(srcDir)
            commandLine("make")
        }

        // Copy the lib to the resources
        val targetDir = dstDir.get().dir(targetOsArch[0]).dir(targetOsArch[1])
        val libExt =
            if (targetOsArch[0].contains("linux")) {
                "so"
            } else if (targetOsArch[0].contains("darwin")) {
                "dylib"
            } else { // Windows
                "dll"
            }
        // libsodium native build adds a "-/.26" suffix/infix to the lib name.
        // It has something to do with ABI version or maybe something else.
        val filename = listOf("libsodium?26.${libExt}", "libsodium.${libExt}.26")
        println("Copy $filename from $buildDir/ to $targetDir/")
        injected.files.mkdir(targetDir)
        injected.files.sync {
            from(buildDir)
            into(targetDir)

            include(filename)

            eachFile { println("   Copying: $displayName") }

            // Remove the "-/.26" suffix because we don't need it.
            rename { name -> name.replace(".26", "").replace("-26", "") }
        }
        println("Finished copying files.")
        println("Destination listing so far: ${dstDir.get().asFile.absolutePath}")
        injected.execOps.exec {
            workingDir(srcDir)
            commandLine("ls", "-lR", dstDir.get().asFile.absolutePath)
        }
        println("-----")
    }
}
