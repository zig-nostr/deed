# Architecture

How `deed` is put together, and where to look first. For how to use it, read the [README](README.md) and `deed help <command>`. For how to change it, read [`AGENTS.md`](AGENTS.md). The skill in [`skills/deed`](skills/deed/SKILL.md) is for programs that drive deed.

## What it is

A command line for nostr, written in Zig 0.16 on top of the [`nostr`](https://github.com/zig-nostr/nostr) library. It makes and protects keys, builds and signs events, converts NIP-19 codes, encrypts with NIP-44 and NIP-04, wraps private messages, verifies signatures, asks relays for events and counts them, publishes to them, syncs with them, signs for remote clients, talks to relays and servers over HTTP, and keeps what it fetches in a local LMDB store.

Everything with real protocol content comes from the library: keys and signatures, the event model, filters, relay connections, the store. deed is the command line around it: argument parsing, reading and writing records, running a query or a publish under a deadline, and deciding what to say and what to exit with. Nothing in `src/` implements cryptography.

deed is one short-lived process per command. There is no config file and no default location for the store, and no daemon except the verbs whose job is to keep running (`bunker`, `serve`, and `mcp` while a client is connected). State lives in the environment (`NOSTR_SECRET_KEY`, `NOSTR_PASSWORD`, `DEED_RELAYS`), in arguments, and in the store path when one is given.

## Where each command lives

`src/main.zig` reads the arguments, looks the verb up in the table in `src/verbs.zig`, calls it, and turns its result into an exit status. Each verb is one file with a `summary` and a `usage` string, a `ready` flag, and a `run` function that takes the allocator, `std.Io`, its arguments, and two writers, one for stdout and one for stderr.

`verbs.zig` is the one list of verbs. A row is `fromModule(@import("cmd_<name>.zig"))`, and the top-level `deed help` text, `deed help <verb>`, `<verb> --help` and dispatch are all derived from it, so a verb cannot be listed in one place and missing from another. A row whose module has `ready` false is a stub: it is not listed, and it answers that it is not built yet with exit 2.

| command | file | what it does |
| --- | --- | --- |
| `key` | `cmd_key.zig` | generate, derive, encrypt and decrypt (NIP-49), validate, expand, mnemonics (NIP-06) |
| `event` | `cmd_event.zig` | build one event from flags, or sign drafts read from stdin; optionally publish, with proof of work |
| `decode` | `cmd_decode.zig` | NIP-19 code or NIP-05 identifier to a JSON object, one per input |
| `encode` | `cmd_encode.zig` | hex parts to a NIP-19 code |
| `encrypt`, `decrypt` | `cmd_crypt.zig` | NIP-44 and NIP-04, both directions in one file |
| `verify` | `cmd_verify.zig` | check signatures on every core, silent on success |
| `req` | `cmd_req.zig` | build a filter and run it against relays or against the store |
| `filter` | `cmd_filter.zig` | keep the events on stdin that match a filter |
| `count` | `cmd_count.zig` | NIP-45 counts from relays, or from the store |
| `fetch` | `cmd_fetch.zig` | turn a code into a filter plus relay hints, then run it |
| `publish` | `cmd_publish.zig` | offer signed events to relays and print the accepted ones |
| `kind` | `cmd_kind.zig`, `kinds.zig` | look up a kind by number or name |
| `relay` | `cmd_relay.zig` | NIP-11 documents over HTTP |
| `relays` | `cmd_relays.zig` | a person's NIP-65 relay list, through `outbox.zig` |
| `gift` | `cmd_gift.zig` | NIP-59 wrap and unwrap, NIP-17 messages |
| `bunker` | `cmd_bunker.zig` | a NIP-46 signer that runs until interrupted |
| `sync` | `cmd_sync.zig` | NIP-77 reconciliation between two relays, or a relay and a store |
| `post` | `cmd_post.zig` | a note, a reply or a NIP-22 comment |
| `profile` | `cmd_profile.zig` | show a kind 0, or change your own |
| `store` | `cmd_store.zig` | stats, export, import, prune, delete |
| `curl` | `cmd_curl.zig` | NIP-98 signed requests through the system curl |
| `admin` | `cmd_admin.zig` | NIP-86 relay management |
| `blossom` | `cmd_blossom.zig` | Blossom blobs: list, upload, download, delete, check, mirror |
| `serve` | `cmd_serve.zig`, `relayserver.zig` | a relay on this machine for development and tests, over a local store |
| `spell` | `cmd_spell.zig` | fetch a kind 777 spell and run the subscription its tags describe |
| `mcp` | `cmd_mcp.zig` | deed's tools over the Model Context Protocol on stdio |
| `outbox` | `cmd_outbox.zig` | list, refresh and clear the relay lists cached in a store |
| `nsite` | `cmd_nsite.zig` | static sites (NIP-5A): deploy, download, list |
| `nip` | `cmd_nip.zig` | list the NIPs or print one, cached for a day |
| `group` | `cmd_group.zig` | NIP-29 groups: read, chat, join, moderation |

Shared pieces:

- `cli.zig`: the exit code constants, `isOneOf`, and `Input`, the reader every verb uses for its records.
- `verbs.zig`: the table of verbs, and the dispatch and help derived from it.
- `relayset.zig`: the query that `req`, `fetch`, `count`, `profile` and others share, one reader per relay.
- `dial.zig`: dialling many relays at once under one deadline.
- `filterflags.zig`: the filter flags (`-k -a -i -e -p -t -d -h -T -s -u -l --search`) and the JSON filters, parsed once for `req`, `filter`, `count`, `sync` and `store export`.
- `auth.zig`: NIP-42, see Authentication.
- `http.zig`: a bounded HTTP client for the verbs that talk to a web server, see HTTP.
- `parallel.zig`: an ordered worker pool, see Parallel work.
- `outbox.zig`: finding and checking a person's relay list, and caching it in the store.
- `relayserver.zig`: the relay behind `serve`, see Local relay.
- `negclient.zig`: NIP-77 negentropy against one relay, plus the plain reads around it.
- `password.zig`: reading a password with echo off, or from `NOSTR_PASSWORD`.
- `qr.zig`: a QR encoder for `bunker --qrcode`.
- `keyinput.zig`: reading a secret key as `nsec1...`, `ncryptsec1...` or hex (asking for the password of an ncryptsec through `password.zig`), a public key as `npub1...` or hex, and the two helpers every code reader uses to match an entity prefix and strip `nostr:` ignoring ASCII case. Use them and not `startsWith`, or an uppercase code is refused as unknown.
- `storepath.zig`: opening the store a `--store` path names, see the store section.
- `jsonout.zig`: escaping strings for JSON output.
- `console.zig`: Windows only, see Platforms.
- `testrelay.zig`: a websocket relay on loopback, used by tests only.

## How a run flows

The verbs that need no network (`key`, `event` without relays, `decode` of a NIP-19 code, `encode`, `encrypt`, `decrypt`, `verify`, `filter`, `kind`, `gift wrap` and `unwrap`) do the same three things: parse arguments, take records from the arguments or from stdin, write one result line per record. `Input` in `cli.zig` is the one place that rule lives. Positional arguments win over stdin, a line ending is removed and nothing else is trimmed, an empty line separates records, and a record too long for the buffer fails alone and does not take the rest of the stream with it. A bad record is reported on stderr, the stream carries on, and the exit code says something failed.

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

`relayset.query` uses the same shape. Each relay that answered the dial gets a reader task of its own that sends the subscription, answers pings and NIP-42 challenges, parses what arrives and puts it in one queue. The calling thread dedupes, verifies, stores and prints, tracks EOSE, and a timer task puts the deadline into the same queue. There is no round-robin polling: an event is seen the moment it arrives from whichever relay sends it, and a relay that says nothing costs nothing until the deadline. There is no reconnect or backoff either, because a relay that will not answer inside the deadline is a relay this run does without.

Relay text is untrusted. `publish` escapes the notices and refusal reasons a relay sends before they reach a terminal, and an event is never taken on a relay's word: `req` and `fetch` verify it and match it against the filter first.

## The store

`--store <path>` names an LMDB file, opened with `nostr.store.Store`. `req` and `fetch` write to it and `req --local` reads from it. `publish` does not touch it. deed picks no default path. On Windows LMDB sizes the file to its whole map (the library's default, 1 GiB) when it is opened, so a new store takes that much disk at once.

The store comes from the library, along with its indexes, replaceable event rules and deletion handling. deed's part is small: events are handed over in batches already verified, so the store is not asked to verify again, and the open goes through `storepath.zig`.

`storepath.open` takes a mode. A run that writes (`req` and `fetch` with `--store`) uses `create`: it makes the directories above the path first, as `mkdir -p` does, and then lets LMDB make the file and its `-lock` file beside it. `req --local` only reads, so it uses `existing`: with no file there it says "there is no store at" and creates nothing. A leading `~` is read from `HOME`, because a quoted one is not expanded by the shell and would otherwise make a directory named `~`; `~user` is refused, and so is an empty path. LMDB reports every reason an open failed as one status, so when it fails `storepath` looks at the path itself and names the cause: a directory, a part of the path that is a file, no permission to read and write the file or its directory, a read-only file system, or a file that is not a store, which is left as it was. A failed open exits 1.

## Authentication

`auth.zig` answers NIP-42. A relay that keeps some events behind authentication sends a challenge and refuses what needs it with a reason starting `auth-required:`. With `--auth` on `req`, `fetch` and `publish`, the reader task answers with a kind 22242 event naming the relay and the challenge, then the request is tried once more. `--force-pre-auth` waits for the challenge before asking anything. Without `--auth` nothing is signed that was not asked for, so a key passed to a verb that only reads is not used on its own.

Secret keys all come through `keyinput.zig`, so a form added there (an ncryptsec was the last) is taught to every verb at once. The password for an ncryptsec comes from `password.zig`: the terminal with echo off, restored on every way out including SIGINT, or `NOSTR_PASSWORD`. It is never read from an argument, and it lives in a caller-owned fixed buffer that is wiped after use.

Who signs is `signing.zig`. A `Signer` holds either a key read through `keyinput.zig` or a NIP-46 session opened from a `bunker://` URI, and the verbs sign, encrypt and decrypt through it without knowing which. A session dials the URI's relays, runs one reader per relay, connects with the URI's secret and asks for the user's pubkey; every request after that has its own deadline and is a cancelation point. Library helpers that sign with a key pair (NIP-98, Blossom tokens) build the event with a throwaway key, and `finish` has the remote signer sign the same fields as the user.

## HTTP

`http.zig` wraps `std.http.Client` for the verbs that talk to a web server: `relay`, NIP-05 in `decode`, `curl`, `admin` and `blossom`. std has no overall deadline, so a request runs as a concurrent task beside a timer and whichever finishes first wins. The response size is capped as bytes arrive. Redirects are followed by hand so every hop is checked: a hop never leaves https for http, and a hop to another origin drops the credentials. Plain http is allowed for a loopback host or when the caller passes `allow_http`. The status is returned and not turned into an error, because a 404 with a body is an answer, and `curl` wants it. Errors come in one small set, each with a plain sentence.

NIP-98 and NIP-86 sign a kind 27235 event and send it in an `Authorization: Nostr` header. `curl` builds that header and hands the rest to the system curl. Blossom streams files and checks the sha256 of what it sent or received before it reports success.

## Parallel work

`verify` signs nothing and shares nothing between records, so it uses `parallel.zig`, an ordered worker pool. The caller fills chunks, workers process them, and results come back to the caller's thread in submission order, so output is the same as a single thread would give. A fixed window of chunks is in flight, so memory is bounded however long the input is, and chunks are reused so steady state allocates nothing there. A failing record is recorded in its chunk and reported in order; an error from delivery cancels the run.

## Outbox lookup

`outbox.zig` finds a person's relay list: the newest kind 10002 event, signature checked, taken from a named set of relays and nowhere else. The set is the relays on the command line, an nprofile's hints, and `DEED_RELAYS`. There is no built-in default, so deed never contacts a relay the user did not name. With no list published, the relay hints in their kind 3 are used. `relays` prints the result, and with `--store` caches the list and reads it back first unless `--refresh` is given. The verbs that follow a person to their own relays (`fetch`, `post`, `profile`, `req --outbox` and `spell`) use the same lookup, with bootstrap relays from `-r` / `--relay` and `DEED_RELAYS`, and keep what they fetched in the store named with `--store`. `cmd_outbox.zig` is the command for that cache: `list` shows it, `refresh` asks the named relays again and keeps the newest list, and `clear` removes the cached lists and nothing else in the store.

## Local relay

`relayserver.zig` is a websocket server over a local event store, and `cmd_serve.zig` is the command around it. Each connection gets two tasks. The reader takes frames off the socket, answers them, and is the only code that changes that connection's subscriptions. The writer drains a queue of frames onto the socket, and nothing else writes to one. An event published on another connection is offered to a queue without waiting, and a queue that grows past its limit gets the connection dropped, so a client that stops reading slows nobody but itself. Every way out of a connection goes through the socket, so a slow consumer, a handshake that never finishes and a server that is stopping all wake whichever task is blocked on it.

Every event's id and signature is checked before it is stored. The relay speaks NIP-01, NIP-09, NIP-11, NIP-40, NIP-42, NIP-45, NIP-70 and NIP-77, and holds limits on message size, subscriptions per connection, filters per REQ and events per answer. With `--store` accepted events are written in groups and synced before they are acknowledged. A websocket request that carries an `Origin` header is refused unless `--allow-origin` names it, so a browser page cannot reach a relay on the machine by default. `testrelay.zig` is still the relay the tests use, since it can misbehave on purpose.

## MCP

`cmd_mcp.zig` speaks JSON-RPC 2.0 on stdio, one message per line, with nothing on stdout but protocol messages. Each tool calls the verb of the same name in this process with an argument list built from the tool's structured arguments, so a tool and the command line cannot disagree about what a filter or a code means. Nothing is spawned. Because the arguments are built there, a caller cannot reach an option a tool does not offer: a value that could be read as a flag is refused, a relay must be a ws:// or wss:// URL, and the store a tool reads is the one named when the server started. Every call has a deadline taken from its `timeout_ms` and clamped to 30 seconds, and a result is capped at 256 KiB. The publishing tools exist only with `--allow-publish`, and the key comes from `--sec` or `NOSTR_SECRET_KEY` and never from a tool argument.

## Sync

`negclient.zig` runs one NIP-77 session for a filter against one relay. This side holds a set of (created_at, id) items, the relay holds its own, and the result is the ids only we have and the ids only the relay has, without an event body crossing the wire. A relay that does not speak NIP-77 (a NOTICE about an unknown command, a CLOSED, an unparseable message, or silence) comes back as unsupported, and `cmd_sync.zig` falls back to a plain REQ. A relay that speaks it and then refuses comes back as failed. Every wait is bounded by one absolute deadline for the whole sync. The missing events are fetched in batches and verified before they are published or stored.

## Remote signer

`cmd_bunker.zig` holds a key and answers NIP-46 requests over the relays given, through the same dial and reader machinery. It serves only authorized clients: a pubkey given with `--authorized-keys`, or a client that presents a secret, which is spent on first use and replaced. With `--persist` the state is written to a file that deed refuses to use if anyone but the owner can read it. `qr.zig` is a small encoder for exactly this: byte mode, error correction level M, versions 1 to 40, all eight masks tried, and a terminal rendering.

The other side of NIP-46 is `signing.zig`, described under keys above. Its tests run the library's `signer.serve` on an in-memory relay (`signertest.zig`) behind the real verbs.

## Adding a verb

1. Create `src/cmd_<name>.zig` exporting `summary`, `usage`, `ready` (true) and `run`. Write `usage` as the help a person would want: every flag, the input and output, and the exit codes.
2. Add one `fromModule` row to `verbs.zig`. Nothing else edits that file. Top-level help, `deed help <name>` and dispatch follow from the row.
3. Take records through `cli.Input`, keys through `keyinput`, filter flags through `filterflags`, and a store through `storepath.open`. Write results to stdout one per line and diagnostics to stderr.
4. Keep exit codes to the existing four, and say in `usage` what 0 and 1 mean for this verb.
5. Test it beside the code. A verb that dials gets a `testrelay.zig` mode, and the test uses `testrelay.DialAllocator`. Run one test with `zig build test -Dtest-filter=<text>`.
6. Update the README table, the skill, and this file in the same change.

## Exit codes

They are part of the interface. `cli.zig` defines them.

| | |
| --- | --- |
| `0` | it worked |
| `1` | the command ran and failed: a bad signature, an unreadable key, a malformed code, an event no relay accepted, no relay answering a `req` or `fetch` |
| `2` | the command was not understood: unknown verb or flag, missing argument. Nothing was attempted |
| `141` | the reader on the other end of the pipe went away |

`req`, `fetch` and `count` exit 0 when some relay answered, even if nothing matched, because an empty answer is an answer. `publish`, `event` with relays, and `post` exit 0 only when every record was accepted by at least one relay. `verify` and `key validate` exit 1 when any record is bad, `filter --check` when nothing matched, `sync` when anything missing could not be copied, and `store import` when any line was rejected. `curl` exits with curl's own status. `main` also turns a failed flush of stdout into a nonzero status, so a result that was lost is never reported as success.

## Platforms

macOS, Linux and Windows, on x86_64 and aarch64. Linux release builds are static (musl). Most of the platform work is in the library. What deed handles itself is small:

- Windows needs an allocator to split the command line into arguments, so `main` uses `Args.Iterator.initAllocator`, which is free elsewhere.
- A Windows console decodes text with its own code page. `console.zig` switches it to UTF-8 for the length of the run, the output page only when stdout is the console and the input page only when stdin is, so the deeds in a pipeline do not switch it back under each other. It puts the pages back before exit and on Ctrl-C. It does nothing on other systems.
- The test relay shrinks a socket's receive window. On Windows std's sockets are AFD handles Winsock does not know, so it sends the option as the same AFD request std uses for its own socket options, and that is best effort.

Building only the executable for a target does not analyse code the executable never reaches. `zig build test -Dtarget=x86_64-windows-gnu` builds the test binary too, which is the check that finds a break in the test relay. The host cannot run the result, so the command ends with an error saying so once the compile has succeeded.

## How it is tested

`zig build test` runs the unit tests, which sit beside the code they test. They cover argument parsing and every verb's output and exit code, the record reader, the dispatcher, and the dial and query logic. `-Dtest-filter=<text>` runs only the tests whose name contains the text.

The network tests talk to `testrelay.zig` over real sockets on loopback. It answers the websocket upgrade and then behaves according to a mode: accepting, refusing, serving stored events, going silent, never reading, sending pings or notices without stopping, closing mid-answer, sending hostile text with terminal escapes. Each mode exists for one failure a real relay can cause, and the test that uses it checks that the run ends on time with the right output and exit code. Nothing leaves the machine.

Two details matter when adding a test that dials. Use `testrelay.DialAllocator` and not `std.testing.allocator`, because on macOS a stack-capturing allocator can swallow a cancel and hang the test. And do not take the stdin branch of a verb in a unit test, because it would block on the test runner's own stdin. `zig build test` caches passing runs, so to look for flakiness run the test binary directly several times.

`bench/` is not a test suite. `bench/run.py` measures size, startup, memory, signing and verifying throughput, store speed, and relays over loopback against a build, using `bench/relay.py` as the relay. [`BENCHMARKS.md`](BENCHMARKS.md) has the numbers and how to reproduce them.

CI (`.github/workflows/ci.yml`) builds, tests and checks formatting on Linux and macOS, builds and tests on Windows, checks that the installer scripts are pure ASCII and parse, and installs the latest release and runs it, with install.sh on Linux and macOS and with install.ps1 on Windows under both pwsh and Windows PowerShell 5.1. The release workflow (`release.yml`) builds every target from the tag, publishes each as a draft with a SHA-256 beside it, downloads the artifacts back and runs them on matching runners, and lifts the draft only after every check passes.

## Where to start reading

`src/main.zig` for dispatch and exit codes. `src/cli.zig` for the record contract. Then one small verb such as `cmd_verify.zig`, and after it `relayset.zig` and `dial.zig`, which hold the part of deed that is not argument handling. `relayset.zig` and `cmd_publish.zig` hold the reader-per-relay machinery.
