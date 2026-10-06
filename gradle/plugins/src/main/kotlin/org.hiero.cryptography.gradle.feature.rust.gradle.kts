// SPDX-License-Identifier: Apache-2.0
import org.hiero.cryptography.gradle.extensions.CargoExtension
import org.hiero.cryptography.gradle.extensions.CargoToolchain

plugins {
    id("java")
    id("org.hiero.cryptography.gradle.check.spotless-rust")
}

val cargo = project.extensions.create<CargoExtension>("cargo")

cargo.targets(*CargoToolchain.entries.toTypedArray())
