# deed

**The nostr command line.**

A deed is two things at once: a signed instrument, and a thing done. So is a nostr event. `deed` makes them, reads them and proves them.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.sh | bash
```

macOS and Linux, Intel and ARM. It works out which build this machine wants, checks the download against the SHA-256 published beside it, and installs into `~/.local/bin`, so nothing needs root and nothing lands outside your home directory. If the digest does not match, it installs nothing and says so.

`--prefix <dir>` puts it somewhere else, `--version <tag>` installs a particular release, and `--archive <file>` installs from a tarball you already have, which still wants its `.sha256` beside it. Pass `--help` for the list.

### By hand

The script is short and worth reading before you pipe anything into bash. If you would rather do it yourself:

```sh
VERSION=0.1.0
PLATFORM=macos-aarch64   # or macos-x86_64, linux-x86_64, linux-aarch64
BASE=https://github.com/zig-nostr/deed/releases/download/v$VERSION

curl -LO $BASE/deed-$VERSION-$PLATFORM.tar.gz
curl -LO $BASE/deed-$VERSION-$PLATFORM.tar.gz.sha256
shasum -a 256 -c deed-$VERSION-$PLATFORM.tar.gz.sha256   # sha256sum -c on Linux
tar -xzf deed-$VERSION-$PLATFORM.tar.gz
sudo mv deed /usr/local/bin/
```

The Linux builds are statically linked, so there is no glibc version to satisfy.

The macOS builds are ad-hoc signed and not notarized. A copy that arrived through a browser carries a quarantine flag, so clear it once:

```sh
xattr -dr com.apple.quarantine deed
```

## What it does

Everything deed does today is offline. It opens no socket, so what comes out can be inspected before any of it leaves the machine. Reaching relays is not here yet: see [what is missing](#what-is-missing).

| verb | |
| --- | --- |
| `key` | make a key, or derive the public one from it |
| `event` | build an event and sign it |
| `decode` | turn a NIP-19 code into the fields it carries |
| `encode` | build a NIP-19 code out of its parts |
| `encrypt` | encrypt a message to someone, with NIP-44 |
| `decrypt` | decrypt a NIP-44 payload from someone |
| `verify` | check that events are correctly signed |

`deed help <command>` explains any of them.

## What is missing

There is no local store, and no verb that reaches a relay. Those are one piece of work rather than two.

A command line that fetches and keeps nothing asks the same question again the next time it runs, and piping two such verbs together pays for the same answer twice. The store is what makes the network verbs worth having, and it is the reason this tool exists rather than being one more way to do what is already done well: a nostr command line that keeps what it fetches. So `req`, `fetch` and `publish` arrive together with `--store`, or they do not arrive. That is [the next release](https://github.com/zig-nostr/deed/milestone/1).

Windows is not built either. `deed` itself does not compile there yet, and the protocol library cannot resolve a hostname on Windows ([nostr#59](https://github.com/zig-nostr/nostr/issues/59)), so claiming it now would mean losing it again the moment a verb needs a relay.

## How the verbs fit together

Each verb takes its inputs as arguments and, given none, reads them as newline-delimited records on standard input, writing one result per line. That is the whole reason they compose:

```sh
export NOSTR_SECRET_KEY=$(deed key generate)

deed event -c "hello" | deed verify        # builds one, signs it, checks it
cat drafts.jsonl | deed event - | deed verify
```

A key can be passed with `--sec`, but a key on a command line lands in your shell history and in the process table, so `$NOSTR_SECRET_KEY` is the better habit.

A bad record fails that record alone. The stream carries on, the reason goes to standard error, and the exit code reports that something in the run failed.

## Exit codes

Scripts branch on these, so they are part of the interface and not free to drift.

| | |
| --- | --- |
| `0` | it worked |
| `1` | the command ran and failed: a bad signature, an unreadable key, a malformed code |
| `2` | the command was not understood: unknown verb, unknown flag, missing argument. Nothing was attempted |
| `141` | the reader on the other end of the pipe went away, as in `deed decode … \| head -1` |

## Build

```sh
zig build            # build the binary
zig build test       # run the unit tests
zig build run -- --help
```

Uses the Zig version pinned in `.zigversion`. The protocol library is pinned by URL and digest in `build.zig.zon`, so a build here and a build in CI are the same build.

## License

MIT. See [LICENSE](LICENSE).
