// SPDX-License-Identifier: Apache-2.0
import java.net.URI
import org.gradle.api.internal.file.FileOperations

// Support the proof construction and verification test in WRAPS 2.0 by preparing a large binary artifact:
val wrapsArtifactDir = layout.buildDirectory.dir("wraps-artifact")

abstract class DownloadWrapsArtifactTask : DefaultTask() {
    @get:Inject protected abstract val files: FileOperations

    @get:OutputDirectories abstract val wrapsDir: DirectoryProperty

    @TaskAction
    fun action() {
        // The version, e.g. "v0.2" for https://builds.hedera.com/tss/hiero/wraps/v0.2/wraps-v0.2.0.tar.gz
        val ver = "v1.5"
        val out = wrapsDir.get().dir("${ver}.0")
        files.mkdir(out)

        // This is a 3GB download, so we only do this if we must:
        val filename = "wraps-${ver}.0.tar.gz"
        val uri = "https://builds.hedera.com/tss/hiero/wraps/${ver}/$filename"
        val url = URI(uri).toURL()
        val tarball = wrapsDir.get().file(filename).asFile
        if (!tarball.exists()) {
            println("Downloading $uri to ${tarball.absolutePath}")
            // file.writeBytes(url.readBytes()) runs out of heap space, so we copy streams instead:
            url.openStream().use { input ->
                tarball.outputStream().use { output -> input.copyTo(output) }
            }
        } else {
            println("$uri has already been downloaded as: ${tarball.absolutePath}")
        }
        // Just one of the artifact files, good enough for a quick test:
        val testArtifactFileName = "decider_pp.bin"
        if (!files.file(out.file(testArtifactFileName)).exists()) {
            println("Extracting ${tarball.absolutePath} to ${out.asFile.absolutePath}")
            files.sync {
                from(files.tarTree(tarball))
                into(out)
            }
        } else {
            println(
                "Not extracting Wraps artifact as it already exists: e.g. ${out.file(testArtifactFileName).asFile.absolutePath}"
            )
        }
    }
}

tasks.register<DownloadWrapsArtifactTask>("downloadWrapsArtifactTask") {
    wrapsDir.convention(wrapsArtifactDir)
}
