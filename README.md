# curve25519-elisabeth [![Maven Central](https://img.shields.io/maven-central/v/cafe.cryptography/curve25519-elisabeth.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22cafe.cryptography%22%20AND%20a:%22curve25519-elisabeth%22) [![Build Status](https://travis-ci.com/cryptography-cafe/curve25519-elisabeth.svg?branch=master)](https://travis-ci.com/cryptography-cafe/curve25519-elisabeth) [![Codecov](https://img.shields.io/codecov/c/gh/cryptography-cafe/curve25519-elisabeth.svg)](https://codecov.io/gh/cryptography-cafe/curve25519-elisabeth)

A pure-Java implementation of group operations on Curve25519.

Requires Java 7 or higher. Requires JDK 9 or higher to build.

# Usage

## Gradle

```
implementation 'cafe.cryptography:curve25519-elisabeth:0.1.0-SNAPSHOT'
```

## Apache Maven

```
<dependency>
  <groupId>cafe.cryptography</groupId>
  <artifactId>curve25519-elisabeth</artifactId>
  <version>0.1.0-SNAPSHOT</version>
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
