# deed

**The nostr command line.**

A deed is two things at once: a signed instrument, and a thing done. So is a
nostr event. `deed` makes them, reads them, proves them, moves them, and keeps
them.

> **Status: pre-release (`v0.1.0`).** The skeleton and the first offline verbs
> are in. Nothing here is stable yet.

## Build

```sh
zig build            # build the binary
zig build test       # run the unit tests
zig build run -- --help
```

Uses the Zig version pinned in `.zigversion`.
