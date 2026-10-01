plugins {
    kotlin("jvm") version "2.0.21"
    application
}

group = "example.cardkey"
version = "0.1.0"

repositories { mavenCentral() }

dependencies {
    implementation(kotlin("stdlib"))
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("com.cardkey.client.MainKt")
}

tasks.test {
    useJUnitPlatform()
}
