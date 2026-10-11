**deed** is a command line for nostr, built in Zig. It runs on macOS, Linux and Windows, on both Intel and ARM. The Linux binaries are statically linked, so there is no glibc version to satisfy. The macOS binaries are **ad-hoc signed, not notarized**, which means a download that came through a browser needs `xattr -dr com.apple.quarantine` before it will run. The Windows builds are zips holding `deed.exe`, which is not code-signed.

Every artifact below is published with a `.sha256` beside it, so the download can be checked against a digest that was written by the same job that built it.

### Unreleased

**A native build for Windows on ARM.** Releases now carry a zip for aarch64 Windows, run on a Windows ARM machine before the release is published, and the PowerShell installer puts it in place on an ARM64 machine. It used to crash at startup: a stripped build for that target looked for every thread-local variable in the wrong place, because of a linker bug fixed upstream in llvm/llvm-project#200060. That target is now built without stripping, which costs about 250 KB, since its debug information goes to a separate `.pdb` that is not shipped. For an older release without the ARM64 zip, the installer still installs the x86_64 build, which Windows on ARM runs under emulation.

### What's new in v0.5.0

deed now covers most of what a nostr user does from a shell. Every verb reads records as lines of JSON and writes one result per line, so they pipe into each other.

**Relays and auth.** `--auth` answers a relay's NIP-42 challenge on `req`, `fetch` and `publish`. `req --outbox` asks each author's own write relays, and `fetch`, `post` and `profile` follow a person to their relays when you name none. `relays`, `outbox`, `relay` (NIP-11) and `count` (NIP-45) are new, and `req` takes NIP-50 search, any one-letter tag, JSON filters and pagination. One reader per relay means a slow relay no longer delays the others.

**Proxies.** `--proxy`, `DEED_PROXY` or the usual proxy variables send web requests and relay connections through an HTTP proxy or SOCKS5, including socks5h so a Tor proxy resolves names itself, with `NO_PROXY` respected. When a proxy applies and cannot be used, deed stops with a clear message instead of connecting directly.

**Keys and remote signing.** `key` encrypts a key into an ncryptsec, validates keys and works with BIP-39 mnemonics. A `bunker://` URI works wherever a key does, so `event`, `post`, `profile set`, `group`, `gift`, `curl`, `admin`, `blossom` and the others sign through a NIP-46 remote signer. `deed bunker` runs a signer of your own. `event --pow` mines a NIP-13 nonce.

**Messages and encryption.** `gift dm` writes NIP-17 private messages as NIP-59 gift wraps, `gift unwrap` reads them, `encrypt` and `decrypt` take `--nip04`, and `dekey` sets up a NIP-4E decoupled encryption key.

**Threads and pasted events.** `fetch --thread` returns a whole conversation, root first, following NIP-10 replies and NIP-22 comments, and `--tree` prints the depth of each. Every verb that reads events from stdin takes pretty-printed or concatenated JSON as well as one event per line.

**A local store and a local relay.** `store` has `stats`, `export`, `import`, `prune` and `delete`. `deed serve` runs a relay on your machine for development and tests: it checks every id and signature, can keep events in a store, preload a file, and require NIP-42 sign-in, and it refuses browser pages unless you allow their origin.

**Sync.** `deed sync` copies what one side lacks between relays, or a relay and a store, with NIP-77, so only ids cross the wire to find the difference.

**HTTP verbs.** `curl` adds a NIP-98 header, `admin` calls a relay's NIP-86 management API, `blossom` lists, uploads, downloads, deletes, checks and mirrors blobs, `decode` resolves NIP-05 names, and `nsite` deploys and downloads static sites, and `blossom upload --metadata` publishes NIP-94 file metadata (`--imeta` prints the tag for a note).

**More verbs.** `post`, `profile`, `kind`, `nip`, `spell`, `group`, `git`, `podcast` and `validate` cover posting, profiles, the NIPs, spells, NIP-29 groups, NIP-34 repositories, podcasts and kind schemas.

**Agent support.** `deed mcp` serves deed's tools to an MCP client over stdio. It can read a store and verifies what relays send, and publishing is off unless you start it with `--allow-publish`.

**Faster.** `verify` and `event -` use every core and print in the same order: 10,000 events verify in 32 ms where they took 0.29 s, and 10,000 drafts sign in 32 ms where they took 304 ms (Apple M2 Pro, release builds). Parsing an event is about four times cheaper with nostr 0.15. With a relay that answers 300 ms late among four, the first event now appears in 5.8 ms instead of 306.6 ms.

**Reviewed.** The verbs that read from relays or the network, the signer, `serve` and `mcp` were reviewed adversarially, and the fixes are included. A key behind a password is asked for once per run, and keys are wiped from memory on every path. Hosts that resolve to private addresses are refused where a name comes from someone else's event.

deed builds on nostr 0.15.1. Windows on ARM still runs the x86_64 build under emulation.

### What's new in v0.4.1

**deed runs on Windows.** Each release now carries a zip for x86_64 holding `deed.exe`, with a `.sha256` beside it. Windows on ARM runs it too, under the system's x86_64 emulation; a native ARM build is not shipped yet because it crashes at startup. The nostr library underneath builds and passes its tests on Windows too, including the read deadline that `req` and `fetch --timeout` rely on.

**A new store's directories are made for you, and a store that will not open says why.** `--store ~/.deed/db` used to need `~/.deed` to exist already, and a store that failed to open printed only an error name. deed now creates the missing directories and names the reason: no permission, not a store, or a directory where the file should be. `--local` only reads, so it never creates an empty store at a mistyped path.

**Codes in capitals decode.** An all-uppercase `NPUB1...` or `NEVENT1...` decodes, as BIP-173 allows, and so does a `NOSTR:` scheme in any case, which is what a QR code carries. A code in mixed case is still refused.

### What's new in v0.3.2

**deed works well with AI agents.** A skill in `skills/deed` teaches an agent the commands, working recipes, and the two rules that matter: publishing is public and permanent, so it asks first, and a secret key stays in `NOSTR_SECRET_KEY`. Add it with `npx skills add zig-nostr/deed`, or in Claude Code as a plugin. `AGENTS.md` covers changing deed itself.

**A relay that sends pings and has stopped reading no longer holds `req` or `fetch`.** Answering its pings filled a socket it never read, and the reply waited forever, past `--timeout`. The nostr library now bounds that reply by the read's deadline, and deed moves to that version.

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
