plugins {
    `java-library`
    jacoco
    id("me.champeau.gradle.jmh") version "0.4.8"
}

repositories {
    jcenter()
}

dependencies {
    testImplementation("junit:junit:4.12")
    testImplementation("org.hamcrest:hamcrest-all:1.3")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
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

// Set up bootstrapClasspath for Java 7.
val java7BootClasspath: String by project
val bootClasspath = if (hasProperty("java7BootClasspath")) java7BootClasspath else {
    var java7Home = System.getenv("JAVA7_HOME")
    if (java7Home != null) {
        "${java7Home}/jre/lib/jce.jar:${java7Home}/jre/lib/rt.jar"
    } else null
}
if (bootClasspath != null) {
    tasks.withType<JavaCompile>().configureEach {
        options.apply {
            bootstrapClasspath = files(bootClasspath)
        }
    }
}

// Set up Java override if configured (used to test with Java 7).
val javaHome: String by project
val targetJavaHome = if (hasProperty("javaHome")) javaHome else System.getenv("TARGET_JAVA_HOME")
if (targetJavaHome != null) {
    println("Target Java home set to ${targetJavaHome}")
    println("Configuring Gradle to use forked compilation and testing")

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
