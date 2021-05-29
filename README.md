# libsignal-service-rs

![Build Status](https://github.com/whisperfish/libsignal-service-rs/workflows/CI/badge.svg)
[![API Docs](https://img.shields.io/badge/docs-libsignal--service-blue)](https://whisperfish.github.io/libsignal-service-rs/libsignal_service)

A Rust version of the [libsignal-service-java][lsj] library for communicating
with Signal servers.

## Contributing

We're actively trying to make `libsignal-service-rs` fully functional.

If you're looking to contribute or want to ask a question, you're more than welcome to join our development channel on Matrix (#whisperfish:rubdos.be) or Freenode (#whisperfish) to get in touch with us!

## Feature flags for libsignal-service

| Feature flag     | Description                                                                                                                                                                             |
|------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `unsend-futures` | This feature removes the `Send` requirement on returned futures. Enabling this flag may be necessary for interoperability with other libraries that don't support `Send` such as actix. |
| `prefer-e164`    | This is a legacy feature that should not be used in new applications.                                                                                                                   |

## License

Copyright 2015-2019 Open Whisper Systems  
Copyright 2020-2021 Signal Messenger, LLC  
Copyright 2019-2021 Ruben De Smet  
Copyright 2019-2021 Michael F Bryan  
Copyright 2019-2021 Gabriel Féron  
Copyright 2019-2021 Whisperfish contributors  

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
