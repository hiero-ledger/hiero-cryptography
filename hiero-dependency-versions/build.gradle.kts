// SPDX-License-Identifier: Apache-2.0
val junit5 = "6.1.0"
val mockito = "5.23.0"
val bouncycastle = "1.84"

dependencies.constraints {
    api("org.junit.jupiter:junit-jupiter-api:$junit5") { because("org.junit.jupiter.api") }
    api("org.junit.jupiter:junit-jupiter-engine:$junit5") { because("org.junit.jupiter.engine") }
    api("org.mockito:mockito-core:$mockito") { because("org.mockito") }
    api("org.mockito:mockito-junit-jupiter:$mockito") { because("org.mockito.junit.jupiter") }
    api("org.bouncycastle:bcpkix-jdk18on:$bouncycastle") { because("org.bouncycastle.pkix") }
    api("org.bouncycastle:bcprov-jdk18on:$bouncycastle") { because("org.bouncycastle.provider") }
}
