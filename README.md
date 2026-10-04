# deed

**The nostr command line.**

A deed is two things at once: a signed instrument, and a thing done. So is a nostr event. `deed` makes them, reads them and proves them.

## Install

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.sh | bash
```

Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.ps1 | iex
```

Each checks the download against the SHA-256 published beside it, and if the digest does not match it installs nothing and says so. On macOS and Linux deed goes into `~/.local/bin`. On Windows it goes into `%LOCALAPPDATA%\deed`, which is added to your `PATH`, so `deed version` works in a new terminal. Neither needs root or administrator rights.

`--version <tag>` installs a particular release, `--prefix <dir>` puts it somewhere else, and `--archive <file>` installs from an archive you already have, which still wants its `.sha256` beside it. `--help` lists them. On Windows they are `-Version`, `-Prefix`, `-Archive` and `-Help` when you run the script as a file, and `$env:DEED_VERSION`, `$env:DEED_PREFIX` and `$env:DEED_ARCHIVE` for the piped line.

On Windows on ARM the installer puts the x86_64 build in place, which Windows 11 runs under emulation. The Windows binary is not code-signed, so Windows may show a warning the first time it runs. A store made with `--store` takes 1 GiB of disk on Windows from the first run, because LMDB sizes the file to its whole map up front there; on macOS and Linux it grows with what is kept. deed reads a leading `~` in a `--store` path from `HOME`, which Windows does not usually set, so give a full path there.

## What it does

deed reaches relays and keeps what it finds. Every verb that does not need a socket still works without one, so what comes out can be read before any of it leaves the machine.

| verb | |
| --- | --- |
| `key` | make a key, or derive the public one from it |
| `event` | build an event and sign it |
| `decode` | turn a NIP-19 code into the fields it carries |
| `encode` | build a NIP-19 code out of its parts |
| `encrypt` | encrypt a message to someone, with NIP-44 |
| `decrypt` | decrypt a NIP-44 payload from someone |
| `verify` | check that events are correctly signed |
| `req` | build a subscription, and run it |
| `fetch` | get the events a code names |
| `publish` | offer signed events to relays, and print the ones they accepted |

`deed help <command>` explains any of them. Wherever a verb takes an `npub`, `nsec` or `note` it also takes it in upper case, the form a QR code carries, and `decode` and `fetch` take a code with a `nostr:` prefix in either case. A code that mixes cases is refused, as bech32 requires.

## It keeps what it fetches

A run that reaches relays can keep what it received, and a later run can ask the store instead of the network:

```sh
deed req -k 1 -l 50 --store ~/.deed/db wss://relay.example   # once, over the network
deed req -k 1 -l 50 --store ~/.deed/db --local               # again, dialling nothing
```

`--store` creates the store and any directories above it the first time, so the path above works on a machine that has no `~/.deed` yet, and a leading `~` means the home directory even when the shell did not expand it. `--local` only reads: it opens a store that exists, and says there is none rather than leaving an empty one behind a mistyped path. When a store will not open, the message says why: the path is a directory, a part of it is a file, there is no permission, or the file is not a store.

The second command opens no socket. The events came out of a local store that the first command filled, and they are the same events: `deed verify` is as happy with them as it was the first time, because what is stored is what was signed.

Events are checked before they are stored or printed. A relay can send anything, so a signature that does not verify, and an event that does not answer the question that was asked, are both dropped and reported.

## What is missing

**Relay selection.** A code with no relay hints is not looked up: `deed fetch npub1...` asks you to name a relay rather than going to find the author's relay list first. Doing that properly means a second round trip and a cache with its own staleness rules, and doing it badly is worse than saying so.

## How the verbs fit together

Each verb takes its inputs as arguments and, given none, reads them as newline-delimited records on standard input, writing one result per line. That is the whole reason they compose:

```sh
export NOSTR_SECRET_KEY=$(deed key generate)

deed event -c "hello" | deed verify        # builds one, signs it, checks it
cat drafts.jsonl | deed event - | deed verify
cat drafts.jsonl | deed event - | deed publish wss://relay.example > sent.jsonl
```

`publish` prints each event a relay accepted, once the relays have answered or the deadline has passed, so what it writes out is what was published.

A key can be passed with `--sec`, but a key on a command line lands in your shell history and in the process table, so `$NOSTR_SECRET_KEY` is the better habit.

A bad record fails that record alone. The stream carries on, the reason goes to standard error, and the exit code reports that something in the run failed.

## Exit codes

Scripts branch on these, so they are part of the interface and not free to drift.

| | |
| --- | --- |
| `0` | it worked |
| `1` | the command ran and failed: a bad signature, an unreadable key, a malformed code, an event no relay accepted |
| `2` | the command was not understood: unknown verb, unknown flag, missing argument. Nothing was attempted |
| `141` | the reader on the other end of the pipe went away, as in `deed decode … \| head -1` |

## Using deed from an agent

deed is built to be driven by scripts, and that makes it a good tool for AI agents doing nostr work: one result per line on stdout, diagnostics on stderr, exit codes that mean one thing each, and `deed help <command>` for the exact usage of anything.

The skill in [`skills/deed`](skills/deed/SKILL.md) teaches an agent the commands, the recipes, and the two things to get right: publishing is public and permanent, so it asks first, and a secret key stays in `NOSTR_SECRET_KEY` rather than on a command line. Add it to any agent that supports skills:

```sh
npx skills add zig-nostr/deed
```

In Claude Code it also installs as a plugin: `/plugin marketplace add zig-nostr/deed`, then `/plugin install deed@deed`.

## Examples

- [`examples/jev`](examples/jev): fetch the newest thousand notes from five relays and rank them by substance with [Jev](https://docs.typesafe.ai), dropping spam and app data on the way. A real run and what it cost are in its README.

## How fast it is

A one-shot command runs in about 2.3 ms and under 2 MB of memory. deed signs and verifies about 31,000 events a second each, stores 100,000 events from a relay at about 17,000 a second, and answers a lookup from that store in about 3 ms, start to finish. The binaries are 2.3 to 2.7 MB. [BENCHMARKS.md](BENCHMARKS.md) has the full set and how to reproduce every number.

## Build

```sh
zig build            # build the binary
zig build test       # run the unit tests
zig build run -- --help
```

Uses the Zig version pinned in `.zigversion`. The protocol library is pinned by URL and digest in `build.zig.zon`, so a build here and a build in CI are the same build.

[ARCHITECTURE.md](ARCHITECTURE.md) explains how deed is put together: where each command lives, how a run flows, the store, the exit codes and how it is tested.

## License

MIT. See [LICENSE](LICENSE).
