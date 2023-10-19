import org.apache.tools.ant.taskdefs.email.Header

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
    repositories {
        maven {
            name = "Gitea"
            url = uri("https://git.usbharu.dev/api/packages/usbharu/maven")

            credentials(HttpHeaderCredentials::class.java) {
                name = "Authorization"
                value = project.findProperty("gpr.gitea") as String? ?: System.getenv("GITEA")
            }

            authentication{
                create<HttpHeaderAuthentication>("header")
            }
        }
    }
}
