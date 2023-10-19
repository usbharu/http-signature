plugins {
    kotlin("jvm") version "1.9.0"
    id("maven-publish")
}

group = "dev.usbharu"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.8.1")
    testImplementation("org.mockito:mockito-inline:5.2.0")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(11)
}


publishing{
    repositories{
        maven{
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/usbharu/http-signature")
            credentials {
                username = project.findProperty("gpr.user") as String? ?: System.getenv("USERNAME")
                password = project.findProperty("gpr.key") as String? ?: System.getenv("TOKEN")
            }
        }
    }
}
