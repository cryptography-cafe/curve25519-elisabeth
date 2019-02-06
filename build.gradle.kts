plugins {
    `java-library`
    jacoco
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

val mathJax = "<script type='text/x-mathjax-config'>MathJax.Hub.Config({ tex2jax: { inlineMath: [ ['$','$'] ], processEscapes: true } });</script><script type='text/javascript' src='https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML'></script>"

tasks.javadoc {
    options.header("")
        .bottom(mathJax)
    // Add --allow-script-in-comments if available (since 1.8.0_121).
    // See https://github.com/gradle/gradle/issues/1393
    try {
        var clazz = Class.forName("com.sun.tools.doclets.formats.html.ConfigurationImpl")
        var optionLength = clazz.getDeclaredMethod("optionLength", String::class.java)
        var result = optionLength.invoke(clazz.newInstance(), "--allow-script-in-comments") as Int
        if (result > 0) {
            options.header("")
                .addBooleanOption("-allow-script-in-comments", true)
        }
    } catch (ignored: ClassNotFoundException) {
    } catch (ignored: NoSuchMethodException) {
    }
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
    options.header("")
        .bottom(mathJax)
    // Add --allow-script-in-comments if available (since 1.8.0_121)
    try {
        var clazz = Class.forName("com.sun.tools.doclets.formats.html.ConfigurationImpl")
        var optionLength = clazz.getDeclaredMethod("optionLength", String::class.java)
        var result = optionLength.invoke(clazz.newInstance(), "--allow-script-in-comments") as Int
        if (result > 0) {
            options.header("")
                .addBooleanOption("-allow-script-in-comments", true)
        }
    } catch (ignored: ClassNotFoundException) {
    } catch (ignored: NoSuchMethodException) {
    }
}

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
