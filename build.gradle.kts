plugins {
    `java-library`
    jacoco
    id("me.champeau.gradle.jmh") version "0.4.8"
}

apply(from = "jdks.gradle.kts")

repositories {
    jcenter()
}

sourceSets {
    create("java9") {
        java.srcDir("src/main/java9")
        compileClasspath += sourceSets.main.get().output
    }
    create("testJar") {
        runtimeClasspath += sourceSets.test.get().output
    }
}

dependencies {
    testImplementation("junit:junit:4.12")
    testImplementation("org.hamcrest:hamcrest-all:1.3")

    "testJarImplementation"(files(tasks.jar.get().archivePath) { builtBy(tasks.jar) })
    "testJarImplementation"("junit:junit:4.12")
    "testJarImplementation"("org.hamcrest:hamcrest-all:1.3")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

tasks.named<JavaCompile>("compileJava9Java") {
    sourceCompatibility = "9"
    targetCompatibility = "9"
}

tasks.jar {
    into("META-INF/versions/9") {
        from(sourceSets["java9"].output)
    }
    manifest {
        attributes(
            "Multi-Release" to "true"
        )
    }
}

tasks.register<Test>("testJar") {
    classpath = sourceSets["testJar"].runtimeClasspath
}
tasks.check {
    dependsOn(tasks["testJar"])
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
