val mathJax = "<script type='text/x-mathjax-config'>MathJax.Hub.Config({ tex2jax: { inlineMath: [ ['$','$'] ], processEscapes: true } });</script><script type='text/javascript' src='https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML'></script>"

tasks.named<Javadoc>("javadoc") {
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
    source = project.the<SourceSetContainer>()["main"].allJava
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
