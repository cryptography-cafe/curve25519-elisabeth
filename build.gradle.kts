plugins {
    `java-library`
    `maven-publish`
    jacoco
    id("me.champeau.gradle.jmh") version "0.4.8"
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
    testImplementation("junit:junit:4.12")
    testImplementation("org.hamcrest:hamcrest-all:1.3")
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
version = "0.0.0"

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
        }
    }
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
