# curve25519-elisabeth [![Maven Central](https://img.shields.io/maven-central/v/cafe.cryptography/curve25519-elisabeth.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22cafe.cryptography%22%20AND%20a:%22curve25519-elisabeth%22) [![Build Status](https://travis-ci.com/cryptography-cafe/curve25519-elisabeth.svg?branch=master)](https://travis-ci.com/cryptography-cafe/curve25519-elisabeth) [![Codecov](https://img.shields.io/codecov/c/gh/cryptography-cafe/curve25519-elisabeth.svg)](https://codecov.io/gh/cryptography-cafe/curve25519-elisabeth)

A pure-Java implementation of group operations on Curve25519.

Requires Java 7 or higher. Requires JDK 10 or higher to build.

# Usage

## Gradle

```
implementation 'cafe.cryptography:curve25519-elisabeth:0.1.0'
```

## Apache Maven

```
<dependency>
  <groupId>cafe.cryptography</groupId>
  <artifactId>curve25519-elisabeth</artifactId>
  <version>0.1.0</version>
</dependency>
```

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

# Safety

The `curve25519-elisabeth` types are designed to make illegal states unrepresentable.
For example, any instance of an `EdwardsPoint` is guaranteed to hold a point on the
Edwards curve, and any instance of a `RistrettoElement` is guaranteed to hold a valid
element in the Ristretto group.

These guarantees only hold if the internal implementation details of the types are opaque.
We use several techniques to achieve this in modern Java environments:

- For all classes that implement `java.io.Serializable`, the serialization APIs are
  overridden to use the encoded form of the respective type, instead of directly
  serializing the internal representation.

- For Java 9 and above, when this library is in the module path, reflection cannot be used
  to access non-public classes or fields.

Usage of Java's reflection APIs on types from this library (in legacy environments or
configurations where it is possible to do so) is **NOT** supported.

All operations are implemented using constant-time logic (no secret-dependent branches, no
secret-dependent memory accesses), unless specifically marked as being variable-time code.
However, while our constant-time logic is lowered to constant-time JVM bytecode, we cannot
guarantee that the JVM will not figure out ways to optimise away constant-time logic.

# About

`curve25519-elisabeth` is authored by Jack Grigg.

The field arithmetic was originally extracted from [Jack's Java Ed25519 library](https://github.com/str4d/ed25519-java),
which was in turn a port of the reference `ref10` implementation.

Test vectors, and the UnpackedScalar arithmetic, were ported from
[`curve25519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek),
authored by isis agora lovecruft and Henry de Valence. Their library has also influenced the design
of this one.

> Elisabeth Pepys was the wife of Samuel Pepys. The Third Doctor remembered her as
> making the best cup of coffee he had ever had.  Shortly thereafter, the Fourth
> Doctor claimed to have met her along with her husband.  In his twelfth
> incarnation, the Doctor still regarded Elisabeth's coffee as the best coffee in
> the universe.

`curve25519-elisabeth` contains an experimental implementation of the
[Ristretto prime-order group](https://ristretto.group).
