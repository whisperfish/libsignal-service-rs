# libsignal-service-rs

[![Build Status](https://github.com/whisperfish/libsignal-service-rs/workflows/CI/badge.svg?branch=main)][ci_workflow]
[![API Docs](https://img.shields.io/badge/docs-libsignal--service-blue)][rustdocs]

A Rust version of the [libsignal-service-java][lsj] library which implements the core functionality to communicate with [Signal][signal] servers. It is based on the official Rust version of [libsignal][lsg]

## Usage

Usage of this library is not as straight-forward as with any other Rust library as it only provides some primitives.

For a higher-level library that helps you immediately get started with implementing a [Signal][signal] client in Rust, you might want to have a look at [Presage][presage],  which implements the traits of this library as well as local storage.

### Working around the issue with `curve25519-dalek`

`libsignal-service` depends on a forked version of `curve25519-dalek`,
which might conflict with other instances/forks of the library.

We advise you override all instances of said library through a `patch`-section.

The example below serves as an example of how this library can be included in `Cargo.toml`:

```toml
[dependencies]
libsignal-service = { git = "https://github.com/whisperfish/libsignal-service-rs", branch = "main" }
libsignal-service-actix = { git = "https://github.com/whisperfish/libsignal-service-rs", branch = "main" }

libsignal-protocol = { git = "https://github.com/signalapp/libsignal-client", branch = "main" }
zkgroup = { version = "0.9.0", git = "https://github.com/signalapp/libsignal-client", branch = "main" }

[patch.crates-io]
"curve25519-dalek" = { git = "https://github.com/signalapp/curve25519-dalek", branch = "lizard2" }
```

If you're using a Cargo workspace, you should add the `[patch.crates.io]` section in the root `Cargo.toml` file instead.

### Note on supported Rust versions

`libsignal-service-rs` is the at the core of [Whisperfish][whisperfish], a SailfishOS application. The SailfishOS Rust compiler is relatively old, and therefore the MSRV for `libsignal-service-actix` maps on the compiler for that operating system, including some lag. At moment of writing, this is **Rust 1.61**.

For other platforms, we don't mandate MSRV.

## Contributing

We're actively trying to make `libsignal-service-rs` fully functional.

If you're looking to contribute or want to ask a question, you're more than welcome to join our development channel on Matrix (#whisperfish:rubdos.be) or Libera.chat (#whisperfish) to get in touch with us!

## Feature flags for libsignal-service

| Feature flag     | Description                                                                                                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unsend-futures` | This feature removes the `Send` requirement on returned futures. Enabling this flag may be necessary for interoperability with other libraries that don't support `Send` such as actix. |

## License

Copyright 2015-2019 Open Whisper Systems
Copyright 2020-2023 Signal Messenger, LLC
Copyright 2019-2021 Michael F Bryan
Copyright 2019-2023 Ruben De Smet
Copyright 2019-2023 Gabriel Féron
Copyright 2019-2023 Whisperfish contributors

Licensed under the AGPLv3: http://www.gnu.org/licenses/agpl-3.0.html

Additional Permissions For Submission to Apple App Store: Provided that you
are otherwise in compliance with the GPLv3 for each covered work you convey
(including without limitation making the Corresponding Source available in
compliance with Section 6 of the GPLv3), Open Whisper Systems also grants you
the additional permission to convey through the Apple App Store non-source
executable versions of the Program as incorporated into each applicable
covered work as Executable Versions only under the Mozilla Public License
version 2.0 (https://www.mozilla.org/en-US/MPL/2.0/).

[lsj]: https://github.com/signalapp/libsignal-service-java
[lsg]: https://github.com/signalapp/libsignal
[signal]: https://signal.org/
[whisperfish]: https://gitlab.com/whisperfish/whisperfish/
[presage]: https://github.com/whisperfish/presage/
[ci_workflow]: https://github.com/whisperfish/libsignal-service-rs/actions/workflows/ci.yaml?query=branch:main
[rustdocs]: https://whisperfish.github.io/libsignal-service-rs/libsignal_service
