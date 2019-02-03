# curve25519-elisabeth
A pure-Java implementation of group operations on Curve25519.

Requires Java 7 or higher.

# Documentation

To view the public-facing API documentation, first build it:

```sh
./gradlew javadoc
```

Then open `build/docs/javadoc/index.html` in your browser.

## Internal documentation

The unstable internal implementation details are also documented. To build them:

```sh
./gradlew internalDocs
```

Then open `build/docs/internal/index.html` in your browser.

# About

`curve25519-elisabeth` is authored by Jack Grigg.

The field arithmetic was originally extracted from [Jack's Java Ed25519 library](https://github.com/str4d/ed25519-java),
which was in turn a port of the reference `ref10` implementation.

Test vectors were obtained from [`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek),
authored by Isis Agora Lovecruft and Henry de Valence. Their library has also influenced the design
of this one.
