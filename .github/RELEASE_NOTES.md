**deed** is a command line for nostr, built in Zig. It runs on macOS and Linux, on both Intel and ARM. The Linux binaries are statically linked, so there is no glibc version to satisfy. The macOS binaries are **ad-hoc signed, not notarized**, which means a download that came through a browser needs `xattr -dr com.apple.quarantine` before it will run.

Every artifact below is published with a `.sha256` beside it, so the download can be checked against a digest that was written by the same job that built it.

### What's new in v0.1.0

The first release. deed does the things that need no network: it makes keys, builds and signs events, reads and writes NIP-19 codes, encrypts and decrypts NIP-44 payloads, and checks signatures. Publishing to relays and fetching from them are deliberately absent, so everything here can be inspected before any of it leaves the machine.

**Verbs compose.** Each one takes its inputs as arguments and, given none, reads them as newline-delimited records on standard input, writing one result per line. `deed event - | deed verify` works because neither side knows the other exists.

**A bad record fails that record alone.** The stream carries on, the reason goes to standard error, and the exit code reports that something in the run failed. A record too long to hold is treated the same way: it is skipped and named, and the records behind it still arrive rather than disappearing with it.

**Exit codes are part of the interface**, so scripts can branch on them. 0 succeeded. 1 means the command ran and failed, which covers a bad signature, an unreadable key and a malformed code. 2 means the command was not understood and nothing was attempted. 141 means the reader on the other end of the pipe went away, which keeps `deed decode … | head -1` quiet, since that is an ordinary thing to type and not a failure.

**Verification recomputes the id** from the event's own fields before it checks the signature, so an event whose id does not describe its contents fails even when the signature over that id is genuine.
