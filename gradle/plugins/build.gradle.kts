plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
}

dependencies {
    implementation("org.hiero.gradle:hiero-gradle-conventions:0.7.12")
    implementation("com.diffplug.spotless:spotless-plugin-gradle:8.10.3")
}

gradlePlugin.plugins.register("cryptographyBuildPlugin") {
    // This plugin is in a 'kt' file, and not a 'gradle.kts' file, due to
    // https://github.com/gradle/gradle/issues/39330
    id = "org.hiero.cryptography.gradle.build"
    implementationClass = "org.hiero.cryptography.gradle.plugins.CryptographyBuildPlugin"
}
