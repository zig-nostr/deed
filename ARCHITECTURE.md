# Architecture

How `deed` is put together, and where to look first. For how to use it, read the [README](README.md) and `deed help <command>`. For how to change it, read [`AGENTS.md`](AGENTS.md). The skill in [`skills/deed`](skills/deed/SKILL.md) is for programs that drive deed.

## What it is

A command line for nostr, written in Zig 0.16 on top of the [`nostr`](https://github.com/zig-nostr/nostr) library. It makes keys, builds and signs events, converts NIP-19 codes, encrypts with NIP-44, verifies signatures, asks relays for events, publishes to them, and keeps what it fetches in a local LMDB store.

Everything with real protocol content comes from the library: keys and signatures, the event model, filters, relay connections, the store. deed is the command line around it: argument parsing, reading and writing records, running a query or a publish under a deadline, and deciding what to say and what to exit with. Nothing in `src/` implements cryptography.

deed is one short-lived process per command. There is no daemon, no config file and no default location for the store. State lives in the environment (`NOSTR_SECRET_KEY`), in arguments, and in the store path when one is given.

## Where each command lives

`src/main.zig` reads the arguments, calls the verb, and turns its result into an exit status. Each verb is one file with a `usage` string and a `run` function that takes the allocator, `std.Io`, its arguments, and two writers, one for stdout and one for stderr.

| command | file | what it does |
| --- | --- | --- |
| `key` | `cmd_key.zig` | `generate` a key, or derive the public key from a secret one |
| `event` | `cmd_event.zig` | build one event from flags, or sign drafts read from stdin |
| `decode` | `cmd_decode.zig` | NIP-19 code to a JSON object, one per code |
| `encode` | `cmd_encode.zig` | hex parts to a NIP-19 code |
| `encrypt`, `decrypt` | `cmd_crypt.zig` | NIP-44, both directions in one file |
| `verify` | `cmd_verify.zig` | check signatures, silent on success |
| `req` | `cmd_req.zig` | build a filter and run it against relays or against the store |
| `fetch` | `cmd_fetch.zig` | turn a code into a filter plus relay hints, then run it |
| `publish` | `cmd_publish.zig` | offer signed events to relays and print the accepted ones |

Shared pieces:

- `cli.zig`: the exit code constants, `isOneOf`, and `Input`, the reader every verb uses for its records.
- `relayset.zig`: the query that `req` and `fetch` share.
- `dial.zig`: dialling many relays at once under one deadline.
- `keyinput.zig`: reading a key as `nsec1...`, `npub1...` or hex, and the two helpers every code reader uses to match an entity prefix and strip `nostr:` ignoring ASCII case. Use them and not `startsWith`, or an uppercase code is refused as unknown.
- `storepath.zig`: opening the store a `--store` path names, see the store section.
- `jsonout.zig`: escaping strings for JSON output.
- `console.zig`: Windows only, see Platforms.
- `testrelay.zig`: a websocket relay on loopback, used by tests only.

## How a run flows

The verbs that need no network (`key`, `event`, `decode`, `encode`, `encrypt`, `decrypt`, `verify`) do the same three things: parse arguments, take records from the arguments or from stdin, write one result line per record. `Input` in `cli.zig` is the one place that rule lives. Positional arguments win over stdin, a line ending is removed and nothing else is trimmed, an empty line separates records, and a record too long for the buffer fails alone and does not take the rest of the stream with it. A bad record is reported on stderr, the stream carries on, and the exit code says something failed.

`req` and `fetch` go on to the network:

1. Parse the arguments into a `Filter`. `req` builds it from flags. `fetch` decodes the code, builds the filter it names, and adds the code's relay hints to the relays given on the command line.
2. With no relay named, `req` prints the `REQ` it would send and stops. With `--local` it answers from the store and dials nothing.
3. Open the store if `--store` was given.
4. `relayset.query` dials every relay at once (`dial.all`), subscribes on each one that connected, and reads until every relay has sent EOSE, the deadline passes, or, with `--stream`, until the deadline alone.
5. Each event is checked before anything else happens to it: duplicates by id are dropped, the signature is verified, and the event must match the filter that was asked. What fails is counted on stderr and never printed or stored.
6. What passes is held in a batch of up to 512, written to the store in one transaction, and then printed. It is stored before it is printed, so a run cut short keeps what it already showed. Without a store it is printed straight away.

`publish` runs differently because it answers per event. It reads records, parses and verifies each one before anything is sent, dials the relays when the first valid event arrives, sends the event to every connected relay at once, and waits for their `OK` answers against one deadline. An event is printed to stdout only if at least one relay accepted it, so the output is a record of what was published. A relay that dropped an idle connection is dialled again for the next event.

### Relays, deadlines and cancellation

Name lookup is the one step that cannot be cut short. Every other wait is bounded.

`dial.all` starts one task per relay with `Io.Select`, starts a timer beside them, and cancels whatever is still dialling when the timer fires. The bound is five seconds, or `--timeout` if that is shorter. A relay that does not answer is named on stderr and left out, and the run continues with the others.

`publish` holds one reader task per connected relay for the whole run (`Set` in `cmd_publish.zig`). A reader answers pings and passes `OK` answers and notices to the main task through a queue, and reports the moment its connection goes away. Each message is tagged with the connection it came from, so what a dropped connection left in the queue is recognised and ignored. Sends are concurrent too, so a relay that has stopped reading holds up only its own send, which is cancelled at the deadline.

`req` and `fetch` do not use a reader per relay. `relayset.query` reads from one thread and takes each relay in turn with a 100 ms read timeout, so a quiet relay costs the loop at most that long before it moves to the next one.

Relay text is untrusted. `publish` escapes the notices and refusal reasons a relay sends before they reach a terminal, and an event is never taken on a relay's word: `req` and `fetch` verify it and match it against the filter first.

## The store

`--store <path>` names an LMDB file, opened with `nostr.store.Store`. `req` and `fetch` write to it and `req --local` reads from it. `publish` does not touch it. deed picks no default path. On Windows LMDB sizes the file to its whole map (the library's default, 1 GiB) when it is opened, so a new store takes that much disk at once.

The store comes from the library, along with its indexes, replaceable event rules and deletion handling. deed's part is small: events are handed over in batches already verified, so the store is not asked to verify again, and the open goes through `storepath.zig`.

`storepath.open` takes a mode. A run that writes (`req` and `fetch` with `--store`) uses `create`: it makes the directories above the path first, as `mkdir -p` does, and then lets LMDB make the file and its `-lock` file beside it. `req --local` only reads, so it uses `existing`: with no file there it says "there is no store at" and creates nothing. A leading `~` is read from `HOME`, because a quoted one is not expanded by the shell and would otherwise make a directory named `~`; `~user` is refused, and so is an empty path. LMDB reports every reason an open failed as one status, so when it fails `storepath` looks at the path itself and names the cause: a directory, a part of the path that is a file, no permission to read and write the file or its directory, a read-only file system, or a file that is not a store, which is left as it was. A failed open exits 1.

## Exit codes

They are part of the interface. `cli.zig` defines them.

| | |
| --- | --- |
| `0` | it worked |
| `1` | the command ran and failed: a bad signature, an unreadable key, a malformed code, an event no relay accepted, no relay answering a `req` or `fetch` |
| `2` | the command was not understood: unknown verb or flag, missing argument. Nothing was attempted |
| `141` | the reader on the other end of the pipe went away |

`req` and `fetch` exit 0 when some relay answered, even if nothing matched, because an empty answer is an answer. `publish` exits 0 only when every record was accepted by at least one relay. `main` also turns a failed flush of stdout into a nonzero status, so a result that was lost is never reported as success.

## Platforms

macOS, Linux and Windows, on x86_64 and aarch64. Linux release builds are static (musl). Most of the platform work is in the library. What deed handles itself is small:

- Windows needs an allocator to split the command line into arguments, so `main` uses `Args.Iterator.initAllocator`, which is free elsewhere.
- A Windows console decodes text with its own code page. `console.zig` switches it to UTF-8 for the length of the run, the output page only when stdout is the console and the input page only when stdin is, so the deeds in a pipeline do not switch it back under each other. It puts the pages back before exit and on Ctrl-C. It does nothing on other systems.
- The test relay shrinks a socket's receive window. On Windows std's sockets are AFD handles Winsock does not know, so it sends the option as the same AFD request std uses for its own socket options, and that is best effort.

Building only the executable for a target does not analyse code the executable never reaches. `zig build test -Dtarget=x86_64-windows-gnu` builds the test binary too, which is the check that finds a break in the test relay. The host cannot run the result, so the command ends with an error saying so once the compile has succeeded.

## How it is tested

`zig build test` runs the unit tests, which sit beside the code they test. They cover argument parsing and every verb's output and exit code, the record reader, the dispatcher, and the dial and query logic.

The network tests talk to `testrelay.zig` over real sockets on loopback. It answers the websocket upgrade and then behaves according to a mode: accepting, refusing, serving stored events, going silent, never reading, sending pings or notices without stopping, closing mid-answer, sending hostile text with terminal escapes. Each mode exists for one failure a real relay can cause, and the test that uses it checks that the run ends on time with the right output and exit code. Nothing leaves the machine.

Two details matter when adding a test that dials. Use `testrelay.DialAllocator` and not `std.testing.allocator`, because on macOS a stack-capturing allocator can swallow a cancel and hang the test. And do not take the stdin branch of a verb in a unit test, because it would block on the test runner's own stdin. `zig build test` caches passing runs, so to look for flakiness run the test binary directly several times.

`bench/` is not a test suite. `bench/run.py` measures size, startup, memory, signing and verifying throughput, store speed, and relays over loopback against a build, using `bench/relay.py` as the relay. [`BENCHMARKS.md`](BENCHMARKS.md) has the numbers and how to reproduce them.

CI (`.github/workflows/ci.yml`) builds, tests and checks formatting on Linux and macOS, builds and tests on Windows, checks that the installer scripts are pure ASCII and parse, and installs the latest release and runs it, with install.sh on Linux and macOS and with install.ps1 on Windows under both pwsh and Windows PowerShell 5.1. The release workflow (`release.yml`) builds every target from the tag, publishes each as a draft with a SHA-256 beside it, downloads the artifacts back and runs them on matching runners, and lifts the draft only after every check passes.

## Where to start reading

`src/main.zig` for dispatch and exit codes. `src/cli.zig` for the record contract. Then one small verb such as `cmd_verify.zig`, and after it `relayset.zig` and `dial.zig`, which hold the part of deed that is not argument handling. `cmd_publish.zig` is the largest file because of the reader-per-relay machinery in it.
