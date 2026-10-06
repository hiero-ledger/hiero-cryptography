package org.hiero.cryptography.gradle.plugins

import org.gradle.api.Plugin
import org.gradle.api.initialization.Settings

abstract class CryptographyBuildPlugin : Plugin<Settings> {

    override fun apply(settings: Settings) {
        settings.plugins.apply("org.hiero.gradle.build")
        @Suppress("UnstableApiUsage")
        settings.gradle.lifecycle.beforeProject {
            if (parent == null) plugins.apply("org.hiero.cryptography.gradle.feature.rust.root")
        }
    }
}
