fun compat(src: String): String {
    if (src.contains(".")) {
        return src.substring(src.lastIndexOf(".") + 1)
    } else {
        return src
    }
}

val javaHome: String by project
val targetJavaHome = if (hasProperty("javaHome")) javaHome else System.getenv("TARGET_JAVA_HOME")

if (!JavaVersion.current().isJava9Compatible()) {
    throw GradleException("You must run Gradle with JDK 9+. Set -PjavaHome or TARGET_JAVA_HOME to test with an older Java version.")
}
project.afterEvaluate {
    tasks.withType<JavaCompile>().configureEach {
        val version = compat(sourceCompatibility)
        logger.info("Configuring $name to use --release $version")
        options.compilerArgs.addAll(listOf("--release", version))
    }

    // Set up Java override if configured (used to test with Java 7 and 8).
    if (targetJavaHome != null) {
        logger.info("Target Java home set to ${targetJavaHome}")
        logger.info("Configuring Gradle to use it for testing")

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
