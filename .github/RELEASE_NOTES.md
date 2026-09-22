**deed** is a command line for nostr, built in Zig. It runs on macOS and Linux, on both Intel and ARM. The Linux binaries are statically linked, so there is no glibc version to satisfy. The macOS binaries are **ad-hoc signed, not notarized**, which means a download that came through a browser needs `xattr -dr com.apple.quarantine` before it will run.

Every artifact below is published with a `.sha256` beside it, so the download can be checked against a digest that was written by the same job that built it.

### What's new in v0.2.0

deed reaches relays now, and keeps what it finds.

**Three new verbs.** `req` builds a subscription and runs it. `fetch` gets the events a NIP-19 code names, using the relay hints the code carries. `publish` offers signed events to relays and reports what each one said.

**`--store` is the point of the release.** A run that fetches can keep what it fetched, and a later run can answer the same question from the store without opening a socket:

```sh
deed req -k 1 -l 50 --store ~/.deed/db wss://relay.example
deed req -k 1 -l 50 --store ~/.deed/db --local
```

The second dials nothing. The events are the same events, and they still verify, because what is stored is what was signed. Other nostr command lines do not do this: the one most people use keeps its local database behind a build tag for Linux on x86_64 only, and even there its own query verbs never write to it.

**Events are checked before they are kept or printed.** A relay can send anything. A signature that does not verify is dropped, and so is an event that does not answer the question that was asked. Both are reported rather than silently skipped.

**A query gives up rather than hanging.** Thirty seconds by default, `--timeout` to change it.

**Publishing succeeds when any relay accepts.** An event one relay holds is published, so a partial failure exits 0 with every refusal named on stderr, and only a total failure exits 1. Scripts should not retry something that already happened.

`deed req` with no relay still prints the envelope it would send rather than sending it, so a filter can be read before anybody is asked.

### What's new in v0.1.0

The first release. deed does the things that need no network: it makes keys, builds and signs events, reads and writes NIP-19 codes, encrypts and decrypts NIP-44 payloads, and checks signatures. Publishing to relays and fetching from them are deliberately absent, so everything here can be inspected before any of it leaves the machine.

**Verbs compose.** Each one takes its inputs as arguments and, given none, reads them as newline-delimited records on standard input, writing one result per line. `deed event - | deed verify` works because neither side knows the other exists.

**A bad record fails that record alone.** The stream carries on, the reason goes to standard error, and the exit code reports that something in the run failed. A record too long to hold is treated the same way: it is skipped and named, and the records behind it still arrive rather than disappearing with it.

**Exit codes are part of the interface**, so scripts can branch on them. 0 succeeded. 1 means the command ran and failed, which covers a bad signature, an unreadable key and a malformed code. 2 means the command was not understood and nothing was attempted. 141 means the reader on the other end of the pipe went away, which keeps `deed decode … | head -1` quiet, since that is an ordinary thing to type and not a failure.

**Verification recomputes the id** from the event's own fields before it checks the signature, so an event whose id does not describe its contents fails even when the signature over that id is genuine.
