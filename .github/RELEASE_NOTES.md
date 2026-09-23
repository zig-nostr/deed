**deed** is a command line for nostr, built in Zig. It runs on macOS and Linux, on both Intel and ARM. The Linux binaries are statically linked, so there is no glibc version to satisfy. The macOS binaries are **ad-hoc signed, not notarized**, which means a download that came through a browser needs `xattr -dr com.apple.quarantine` before it will run.

Every artifact below is published with a `.sha256` beside it, so the download can be checked against a digest that was written by the same job that built it.

### What's new in v0.3.1

Faster, smaller, and measured.

**Storing events is about seven times faster.** Events kept with `--store` are written in batches, one transaction each, instead of one transaction per event. Storing 100,000 events from a relay went from about 2,300 a second to about 16,800, each signature still checked, and a batch is still stored before any of it is printed.

**Everything that allocates is faster.** deed now uses a general-purpose allocator instead of mapping pages for every allocation. Decoding a stream of npubs is about eight times faster, and verifying about a fifth faster.

**The Linux downloads are less than half the size.** Release binaries are built without debug information. The Linux ones go from 12 MB to under 3 MB, and every download is now under 2 MB.

**Benchmarks.** [BENCHMARKS.md](https://github.com/zig-nostr/deed/blob/main/BENCHMARKS.md) has the numbers, and `python3 bench/run.py` reproduces them on your machine.

### What's new in v0.3.0

`publish` says what it published.

**What comes out of `publish` is what was published.** Each event that at least one relay accepted is printed once the relays have answered or the deadline has passed, so `deed publish wss://a wss://b < events.jsonl > sent.jsonl` leaves a record of exactly which events a relay accepted in time. Every relay's answer goes to stderr with the event's id on it, including a relay saying it already had the event.

**The exit code covers every event.** `publish` exits 0 only when every event was accepted by at least one relay. An event no relay accepted, a record that is not an event, or an event whose signature does not check out is reported on stderr and makes the run exit 1, and the rest of the stream still goes out. In v0.2.0 one acceptance anywhere in the run was enough to exit 0.

**Events are checked before they are sent.** An event whose id or signature does not match its content is not offered to any relay.

**One deadline per event.** Every relay is sent the event at once, and the relays have ten seconds from then to take it and answer, `--timeout` to change it. Each relay is read on its own for the whole run, so an answer is counted the moment it arrives, a relay that keeps sending notices, pings or messages that cannot be read does not keep the wait going, and a relay that stalls in the middle of a message holds up nobody else. A relay that stops reading what is sent to it is dropped when the deadline passes.

**A relay that never answers the dial no longer holds a run open.** `req`, `fetch` and `publish` dial the relays at once, and a relay that has not accepted the connection within five seconds is named and left out. The name lookup is the one step that cannot be cut short. Before, a relay that accepted the TCP connection and never answered the websocket upgrade held the whole run, and every relay listed after it, forever. A relay that closes the connection while `publish` waits for more input is dialled again for the next event, and an event sent down a connection that closes before answering is offered once more on a fresh one.

**Text from a relay is shown, not obeyed.** Control characters in a relay's refusal or notice are printed as escapes, so a relay cannot write a line of its own into the output or send control sequences to the terminal. Notices are shown up to eight per relay.

**Two fixes from the nostr library, now at 0.14.5.** An event that carries a key NIP-01 does not name is accepted as the event that was signed, and a message from a relay that cannot be read costs that message only, rather than every message after it on that connection.

### What's new in v0.2.0

deed reaches relays now, and keeps what it finds.

**Three new verbs.** `req` builds a subscription and runs it. `fetch` gets the events a NIP-19 code names, using the relay hints the code carries. `publish` offers signed events to relays and reports what each one said.

**`--store` is the point of the release.** A run that fetches can keep what it fetched, and a later run can answer the same question from the store without opening a socket:

```sh
deed req -k 1 -l 50 --store ~/.deed/db wss://relay.example
deed req -k 1 -l 50 --store ~/.deed/db --local
```

The second dials nothing. The events are the same events, and they still verify, because what is stored is what was signed.

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
