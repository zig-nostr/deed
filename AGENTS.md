# AGENTS.md

A guide to this repository for anyone changing it, people and coding agents alike. To *use* deed rather than change it, read [`skills/deed/SKILL.md`](skills/deed/SKILL.md).

## What this is

`deed` is a command line for nostr, written in Zig on top of the [`nostr`](https://github.com/zig-nostr/nostr) library. It makes keys, builds and signs events, reads and writes NIP-19 codes, encrypts and decrypts with NIP-44, checks signatures, asks relays for events, publishes to them, and keeps what it fetches in a local LMDB store.

## Build and test

```sh
zig build                                        # binary at zig-out/bin/deed
zig build test                                   # unit tests, including real relays on loopback
zig fmt --check src build.zig                    # CI fails on unformatted code
zig build -Doptimize=ReleaseSafe -Dstrip=true    # the release build
python3 bench/run.py zig-out/bin/deed            # benchmarks, see BENCHMARKS.md
```

Use the Zig version in `.zigversion`. The `nostr` dependency is pinned by URL and hash in `build.zig.zon`; move it with `zig fetch --save=nostr <tarball url>` and check the diff is only the url and hash lines.

## Layout

```
src/
  main.zig        # dispatch, the stdout/stderr writers, exit codes
  cli.zig         # exit code constants, the stdin record reader
  cmd_*.zig       # one file per verb
  relayset.zig    # the shared relay query behind req and fetch
  dial.zig        # dialling every relay at once under one deadline
  testrelay.zig   # a websocket relay on loopback, for tests only
bench/            # the benchmark script and its relay
scripts/          # the one-line installer (pure ASCII, CI checks it)
skills/deed/      # the skill for agents that operate deed
```

## Conventions

- Every verb takes its inputs as arguments or, given none, as newline-delimited records on stdin, and writes one result per line on stdout. Diagnostics go to stderr. Keep it that way: it is what makes the verbs compose.
- Exit codes are an interface: 0 success, 1 ran and failed, 2 not understood, 141 the reader went away. Do not add new ones casually.
- Anything a relay sends is untrusted: events are verified and matched against the filter before they are printed or stored, and relay text is escaped before it reaches a terminal.
- Tests that dial use `testrelay.DialAllocator`, not `std.testing.allocator`: on macOS a stack-capturing allocator can swallow a cancel and hang the test.
- `zig build test` caches passing runs. To check for flakiness, run the test binary directly (`ls -t .zig-cache/o/*/test | head -1`) several times.
- Conventional Commits. Every PR links its tracking issue.
