fun compat(src: String): String {
    if (src.contains(".")) {
        return src.substring(src.lastIndexOf(".") + 1)
    } else {
        return src
    }
}

val javaHome: String by project
val targetJavaHome = if (hasProperty("javaHome")) javaHome else System.getenv("TARGET_JAVA_HOME")

if (hasProperty("crossCompile")) {
    project.afterEvaluate {
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

        if (targetJavaHome != null) {
            println("Target Java home set to ${targetJavaHome}")
            println("Configuring Gradle to use forked compilation")

            tasks.withType<JavaCompile>().configureEach {
                options.apply {
                    isFork = true
                    forkOptions.javaHome = file(targetJavaHome)
                }
            }
        }
    }
} else {
    if (!JavaVersion.current().isJava9Compatible()) {
        throw GradleException("You must use -PcrossCompile to enable cross-compilation, or run Gradle with JDK 9+")
    }
    project.afterEvaluate {
        tasks.withType<JavaCompile>().configureEach {
            val version = compat(sourceCompatibility)
            println("Configuring $name to use --release $version")
            options.compilerArgs.addAll(listOf("--release", version))
        }
    }
}
project.afterEvaluate {
    if (targetJavaHome != null) {
        println("Target Java home set to ${targetJavaHome}")
        println("Configuring Gradle to use it for testing")

        val javaExecutablesPath = File(targetJavaHome, "bin")
        fun javaExecutable(execName: String): String {
            val executable = File(javaExecutablesPath, execName)
            require(executable.exists()) { "There is no ${execName} executable in ${javaExecutablesPath}" }
            return executable.toString()
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
}
