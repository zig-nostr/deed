# AGENTS.md

A guide to this repository for anyone changing it, people and coding agents alike. To *use* deed rather than change it, read [`skills/deed/SKILL.md`](skills/deed/SKILL.md).

## What this is

`deed` is a command line for nostr, written in Zig on top of the [`nostr`](https://github.com/zig-nostr/nostr) library. It makes and protects keys, builds and signs events, reads and writes NIP-19 codes, encrypts and decrypts, wraps private messages, checks signatures, asks relays for events, publishes to them, syncs, signs for remote clients, runs a local relay and an MCP server, reads and writes NIP-29 groups and NIP-34 repositories, deploys static sites, talks to relays and servers over HTTP, and keeps what it fetches in a local LMDB store.

## Build and test

```sh
zig build                                        # binary at zig-out/bin/deed
zig build test                                   # unit tests, including real relays on loopback
zig build test -Dtest-filter=<text>              # only the tests whose name contains the text
zig fmt --check .                                # CI fails on unformatted code
zig build -Doptimize=ReleaseSafe -Dstrip=true    # the release build
python3 bench/run.py zig-out/bin/deed            # benchmarks, see BENCHMARKS.md
zig build test -Dtarget=x86_64-windows-gnu       # compile the tests for Windows; the run step then fails, the host cannot run them
```

Use the Zig version in `.zigversion`. Building only the executable for Windows is not enough to catch a break there: code the executable never reaches, the test relay for one, only gets analysed when the test binary is built, which is what the Windows line above does. The `nostr` dependency is pinned by URL and hash in `build.zig.zon`; move it with `zig fetch --save=nostr <tarball url>` and check the diff is only the url and hash lines.

## Layout

[`ARCHITECTURE.md`](ARCHITECTURE.md) explains how the pieces fit: where each command lives, how a run flows, the store, the exit codes and how it is tested. The tree below is the short version.

```
src/
  main.zig        # dispatch, the stdout/stderr writers, exit codes
  cli.zig         # exit code constants, the stdin record reader
  console.zig     # Windows only: UTF-8 console code pages for the length of a run
  verbs.zig       # the table of verbs; dispatch and help derive from it
  cmd_*.zig       # one file per verb, each with summary, usage, ready and run
  keyinput.zig    # reading secret and public keys in every form, ncryptsec included
  filterflags.zig # the filter flags and JSON filters shared by req, filter, count, sync, store
  relayset.zig    # the shared relay query, one reader task per relay
  dial.zig        # dialling every relay at once under one deadline
  auth.zig        # NIP-42 answers for req, fetch and publish
  http.zig        # bounded HTTP client for relay, curl, admin, blossom, NIP-05
  proxy.zig       # proxy settings, NO_PROXY, and CONNECT and SOCKS5 tunnels
  parallel.zig    # ordered worker pool, used by verify
  outbox.zig      # a person's NIP-65 relay list, found, checked and cached in the store
  relayserver.zig # the relay behind `deed serve`
  cmd_mcp.zig     # `deed mcp`: the tools over MCP on stdio
  negclient.zig   # NIP-77 negentropy against one relay
  password.zig    # passwords read with echo off or from NOSTR_PASSWORD
  qr.zig          # QR encoder for bunker --qrcode
  storepath.zig   # opening the store a --store path names, and saying why one will not open
  testrelay.zig   # a websocket relay on loopback, for tests only
bench/            # the benchmark script and its relay
scripts/          # the one-line installers, install.sh and install.ps1 (pure ASCII, CI checks both)
skills/deed/      # the skill for agents that operate deed
```

## Conventions

- Every verb takes its inputs as arguments or, given none, as newline-delimited records on stdin, and writes one result per line on stdout. Diagnostics go to stderr. Keep it that way: it is what makes the verbs compose.
- A new verb is a `cmd_<name>.zig` plus one row in `verbs.zig`; see "Adding a verb" in `ARCHITECTURE.md`. Its `usage` string is the documentation: keep every flag in it, and keep the README table and the skill in step.
- Passwords never come from arguments: use `password.zig`. A secret key is read through `keyinput.zig`, never parsed by hand.
- Exit codes are an interface: 0 success, 1 ran and failed, 2 not understood, 141 the reader went away. Do not add new ones casually.
- Match a NIP-19 prefix with `keyinput.hasPrefix` and strip `nostr:` with `keyinput.stripUri`, never `std.mem.startsWith`: bech32 allows all upper case, and a code in upper case has to reach the decoder.
- Open a `--store` path with `storepath.open`, so a new store's directories are made and a store that will not open says why.
- Anything a relay sends is untrusted: events are verified and matched against the filter before they are printed or stored, and relay text is escaped before it reaches a terminal.
- Tests that dial use `testrelay.DialAllocator`, not `std.testing.allocator`: on macOS a stack-capturing allocator can swallow a cancel and hang the test.
- `zig build test` caches passing runs. To check for flakiness, run the test binary directly (`ls -t .zig-cache/o/*/test | head -1`) several times.
- Conventional Commits. Every PR links its tracking issue.
