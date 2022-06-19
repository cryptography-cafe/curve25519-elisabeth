plugins {
    `java-library`
    `maven-publish`
    signing
    jacoco
    // 0.6.2 upgrades to JMH 1.28, which has dependencies that only support
    // Java 8+. Once we've migrated to Gradle Toolchains, we can just use the
    // latest Java for running benchmarks.
    id("me.champeau.jmh") version "0.6.1"
}

apply(from = "jdks.gradle.kts")

repositories {
    jcenter()
}

sourceSets {
    main {
        java {
            exclude("module-info.java")
        }
    }
    create("moduleInfo") {
        java {
            // We need the entire source directory here, otherwise we get a
            // "package is empty or does not exist" error during compilation.
            srcDir("src/main/java")
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2") {
        exclude("org.hamcrest")
    }
    testImplementation("org.hamcrest:hamcrest:2.2")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

tasks.named<JavaCompile>("compileModuleInfoJava") {
    sourceCompatibility = "9"
    targetCompatibility = "9"

    doLast {
        // Leave only the module-info.class
        delete("$destinationDir/cafe")
    }
}

tasks.jar {
    // Add the Java 9+ module-info.class to the Java 7+ classes
    from(sourceSets["moduleInfo"].output)
}

group = "cafe.cryptography"
version = "0.1.0"

tasks.register<Jar>("sourcesJar") {
    from(sourceSets.main.get().allJava)
    archiveClassifier.set("sources")
}

tasks.register<Jar>("javadocJar") {
    from(tasks.javadoc)
    archiveClassifier.set("javadoc")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set("curve25519-elisabeth")
                description.set("Pure Java implementation of group operations on Curve25519")
                url.set("https://cryptography.cafe")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("str4d")
                        name.set("Jack Grigg")
                        email.set("thestr4d@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/cryptography-cafe/curve25519-elisabeth.git")
                    developerConnection.set("scm:git:ssh://github.com:cryptography-cafe/curve25519-elisabeth.git")
                    url.set("https://github.com/cryptography-cafe/curve25519-elisabeth/tree/master")
                }
            }
        }
    }
    repositories {
        maven {
            val releasesRepoUrl = "https://oss.sonatype.org/service/local/staging/deploy/maven2/"
            val snapshotRepoUrl = "https://oss.sonatype.org/content/repositories/snapshots/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotRepoUrl else releasesRepoUrl)
            credentials {
                val NEXUS_USERNAME: String? by project
                val NEXUS_PASSWORD: String? by project
                username = NEXUS_USERNAME ?: ""
                password = NEXUS_PASSWORD ?: ""
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.jacocoTestReport {
    reports {
        xml.isEnabled = true
        html.isEnabled = false
    }
}
tasks.check {
    dependsOn(tasks.jacocoTestReport)
}

jmh {
    // Uncomment to disable SIMD optimizations
    // jvmArgsAppend = listOf("-XX:-UseSuperWord")
}

apply(from = "javadoc.gradle.kts")
