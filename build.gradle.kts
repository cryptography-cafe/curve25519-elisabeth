plugins {
    `java-library`
}

repositories {
    jcenter()
}

dependencies {
    testImplementation("junit:junit:4.12")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

val docsDir: File by project

tasks.register<Javadoc>("internalDocs") {
    source = sourceSets["main"].allJava
    destinationDir = file("${docsDir}/internal")

    // "options" itself is the MinimalJavadocOptions interface.
    // For some reason this is the only way to access the
    // StandardJavadocDocletOptions backend.
    options.header("")
        .addBooleanOption("private", true)
}
