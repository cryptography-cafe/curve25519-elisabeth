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

// Set up Java override if configured (used to test with Java 7).
val javaHome: String by project
val targetJavaHome = if (hasProperty("javaHome")) javaHome else System.getenv("TARGET_JAVA_HOME")
if (targetJavaHome != null) {
    val javaExecutablesPath = File(targetJavaHome, "bin")
    fun javaExecutable(execName: String): String {
        val executable = File(javaExecutablesPath, execName)
        require(executable.exists()) { "There is no ${execName} executable in ${javaExecutablesPath}" }
        return executable.toString()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.apply {
            isFork = true
            forkOptions.javaHome = file(targetJavaHome)
        }
    }

    tasks.withType<Javadoc>().configureEach {
        executable = javaExecutable("javadoc")
    }

    tasks.withType<Test>().configureEach {
        executable = javaExecutable("java")
    }

    tasks.withType<JavaExec>().configureEach {
        executable = javaExecutable("java")
    }
}
