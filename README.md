[![Made With](https://img.shields.io/badge/made_with-java-blue)](https://github.com/hashgraph/hedera-cryptography/)
[![Made With](https://img.shields.io/badge/rust-green)](https://github.com/hashgraph/hedera-cryptography)
[![License](https://img.shields.io/badge/license-apache2-blue.svg)](LICENSE)

# Hedera Cryptography

## Description

This section is a work in progress.

The cryptographic protocol description is contained within [this file](./docs/whitepaper.pdf).

The repository includes the following projects:
* **cryptography/hedera-cryptography-hints**: HinTS API that allows participants to calculate their hints, generate keys, and produce and verify aggregate signatures.
* **cryptography/hedera-cryptography-wraps**: WRAPS 2.0 library that allows participants to generate and verify recursive proofs for AddressBooks.
* **common/hedera-common-nativesupport**: A Helper library providing support for working with jni and external libraries.

For the proposal that originated the work in this repository see:
[Tss-Library](https://github.com/hashgraph/hedera-services/blob/develop/platform-sdk/docs/proposals/TSS-Library/TSS-Library.md)

## Build

The project is built with Gradle.

### Prerequisites

The project requires **LLVM** (in particular `clang-cl` and `llvm-lib`) to be installed on the host machine to perform cross-compilation of Rust code.
If you do not have it available already, you can install it as follows:

- Download distribution that matches your platform: [github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
- Extract the downloaded archive
- Add `<extracted-location>/bin` to your `PATH`

### Build the project

```
./gradlew build
```

More details on the build setup and project structure can be found in the
[documentation of the Hiero Gradle Conventions](https://github.com/hiero-ledger/hiero-gradle-conventions#build)
which this project uses.

## Release Process

There are two release workflows in use by this project. When releasing a new official version, you would use the Publish Release one:

### [Publish Release](.github/workflows/publish_release.yml)

This is the official release workflow. It has to be triggered manually from the Actions page after which, it will do the following:
- Calculate the next version by analyzing the commit messages of the commits pushed since the last version and update the version.txt file.
- Compile the code to make sure there aren't any issues
- Publish to Maven Central using the new version
- Create a Tag and Official Release in GitHub

**It can also be run with the `Dry Run` flag enabled which would just calculate the next expected release version by analyzing the commits since the last release and output the version in the workflow run logs.**

### [Publish Snapshot Release](.github/workflows/publish_snapshot_release.yml)

This workflow runs automatically on a push to main and creates a new `-SNAPSHOT` release of the current version (sourced from the [version.txt](./version.txt) file) and publishes it to Maven Central.

## Support

If you have a question on how to use the product, please see our
[support guide](https://github.com/hashgraph/.github/blob/main/SUPPORT.md).

## Contributing

Contributions are welcome. Please see the
[contributing guide](https://github.com/hashgraph/.github/blob/main/CONTRIBUTING.md) to see how you
can get involved.

## Code of Conduct

This project is governed by the
[Contributor Covenant Code of Conduct](https://github.com/hashgraph/.github/blob/main/CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code of conduct.

## License

[Apache License 2.0](LICENSE)
