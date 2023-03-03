# libsignal-service-rs

[![Build Status](https://github.com/whisperfish/libsignal-service-rs/workflows/CI/badge.svg?branch=main)](https://github.com/whisperfish/libsignal-service-rs/actions/workflows/ci.yaml?query=branch:main)
[![API Docs](https://img.shields.io/badge/docs-libsignal--service-blue)](https://whisperfish.github.io/libsignal-service-rs/libsignal_service)

A Rust version of the [libsignal-service-java][lsj] library for communicating
with Signal servers.

## Supported Rust versions

`libsignal-service-rs` is used mostly by [Whisperfish](https://gitlab.com/whisperfish/whisperfish/),
a SailfishOS application.
The SailfishOS Rust compiler is relatively old, and therefore the MSRV for `libsignal-service-actix` maps on the compiler for that operating system,
including some lag.
At moment of writing, this is **Rust 1.52.1**.
For `libsignal-service-hyper`, we don't mandate MSRV.

## Usage

Usage of this library is not as straight-forward as with any other Rust library.
In particular, `libsignal-service` depends on a forked version of `curve25519-dalek`,
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

## Contributing

We're actively trying to make `libsignal-service-rs` fully functional.

If you're looking to contribute or want to ask a question, you're more than welcome to join our development channel on Matrix (#whisperfish:rubdos.be) or Freenode (#whisperfish) to get in touch with us!

## Feature flags for libsignal-service

| Feature flag     | Description                                                                                                                                                                             |
|------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
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
