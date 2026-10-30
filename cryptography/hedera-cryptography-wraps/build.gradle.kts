// SPDX-License-Identifier: Apache-2.0
import com.diffplug.gradle.spotless.SpotlessExtension
import org.hiero.gradle.tasks.CargoBuildTask
import org.hiero.gradle.tasks.GitClone

plugins {
    id("org.hiero.gradle.module.library")
    id("org.hiero.gradle.feature.rust")
    id("org.hiero.gradle.feature.test-multios")
    id("org.hiero.gradle.feature.benchmark")
    id("DownloadWrapsArtifactTask")
}

cargo {
    libname = "wraps"
}

val halo2curvesDir = layout.projectDirectory.dir("src/main/rust/nova-wraps/halo2curves")

val prepareHalo2curves =
    tasks.register<GitClone>("prepareHalo2curves") {
        url = "https://github.com/privacy-ethereum/halo2curves.git"
        // The commit hash corresponding to the v0.9.0 tag as of 2026-10-14:
        tag = "4b7a69e6a3f1878b150c212d73ec82a3210c29f9"
        patches.from(
            layout.projectDirectory.file("src/main/rust/nova-wraps/halo2curves-v0.9.0.patch")
        )
        localCloneDirectory = halo2curvesDir
    }

tasks.withType<CargoBuildTask>().configureEach { dependsOn(prepareHalo2curves) }

// The 'prepareHalo2curves' modifies the 'src/rust' folder, which is normally not modified by tasks.
// Tasks operating on this folder, do not know about this and hence require an explicit 'dependsOn'.
tasks.named("spotlessJavaInfoFiles") { dependsOn(prepareHalo2curves) }

tasks.named("spotlessRust") { dependsOn(prepareHalo2curves) }

// The root project's 'flexmark' and 'misc' spotless formats target the whole repository, which
// includes the cloned 'halo2curves' folder, making Gradle's implicit-dependency validation fail.
// The clone is a third-party artifact that must not be formatted, so exclude it from those formats.
val halo2curvesFromRoot =
    rootProject.layout.projectDirectory.asFile
        .toPath()
        .relativize(halo2curvesDir.asFile.toPath())
        .toString()
        .replace('\\', '/')
val rootSpotless = rootProject.extensions.getByType(SpotlessExtension::class.java)

rootSpotless.flexmark { targetExclude("$halo2curvesFromRoot/**") }

rootSpotless.format("misc") { targetExclude("$halo2curvesFromRoot/**") }

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

// add a feature variant that excludes '*.ptau' files
val verifierSourceSet = sourceSets.create("verifier")

java.registerFeature(verifierSourceSet.name) {
    val variantArtifactName = "${project.name}-${verifierSourceSet.name}"
    usingSourceSet(verifierSourceSet)
    // the 'verifier' variant has the 'main' capability as both are mutually exclusive:
    capability(project.group.toString(), project.name, project.version.toString())
    // the 'verifier' variant can be selected through its own 'capability':
    capability(project.group.toString(), variantArtifactName, project.version.toString())
}

val verifierJarTask = tasks.named<Jar>(verifierSourceSet.jarTaskName)

verifierJarTask {
    from(sourceSets.main.get().output) // same code as 'main' variant...
    exclude("**/*.ptau") // ...but with large 'ptau' file excluded
    manifest {
        attributes["Implementation-Title"] = project.name
        attributes["Implementation-Version"] = project.version
    }
}

configurations {
    // the additional variant has the same dependencies as the 'main' variant
    named(verifierSourceSet.apiElementsConfigurationName) { extendsFrom(apiElements.get()) }
    named(verifierSourceSet.runtimeElementsConfigurationName) { extendsFrom(runtimeElements.get()) }
}

tasks.assemble {
    dependsOn(verifierJarTask)
}
