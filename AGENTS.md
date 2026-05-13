# libsignal service

A Rust crate that implements Signal's API for building Signal clients.

## Repositories and related libraries

- This library is hosted on github.com/whisperfish/libsignal-service-rs
- The main dependency is on github.com/signalapp/libsignal
- Whisperfish and Presage are the main consumers of this library:
  - Whisperfish is on Git*lab*: gitlab.com/whisperfish/whisperfish
  - Presage is on Git*hub*: github.com/whisperfish/presage

## Pull Request Descriptions

Keep them short. One sentence is fine. Say what's missing or not yet implemented;
don't recite the diff — the reviewer reads the code. The maintainers generally
enjoy short PR descriptions; a few lines should suffice.

Brief high-level protocol context is fine (e.g. "Signal moved from direct contact
sync to StorageService"). Link to upstream sources (Signal-Android, Signal-Desktop,
Signal-Server, or Signal's blog) when referencing protocol behaviour.

Avoid:
- file-by-file changelogs, line counts, "what lands here" lists
- protocol tutorials, step-by-step test or code narration, first-person journey notes
- backwards-compat reassurances ("zero behavior change…"), ritual closers ("happy to
discuss", "verified locally")
- ALL-CAPS headers, hardware/platform name-dropping, stacked-PR preambles

Good:

> Implement StorageService read API. Encryption and upload is left unimplemented.
> Signal-Android reference: [StorageServiceService.kt](https://github.com/signalapp/Signal-Android/blob/main/lib/network/...)

Bad:

> This transformative PR unlocks the full potential of our storage layer by leveraging
> synergistic crypto primitives. We introduce a paradigm-shifting module that empowers
> consumers to seamlessly decrypt server-side manifests. The existing `pub fn new()`
> remains untouched — zero behavior change for any existing caller, guaranteed.
>
> WHY THIS MATTERS: On resource-constrained platforms (RISC-V @ 100 MHz), race conditions
> in the keepalive timer can destabilize long-lived WebSockets. Verified locally.
> Happy to discuss. Smallest possible blast radius.
