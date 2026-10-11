# Benchmarks

## deed and nak

deed 0.5.0 beats nak v0.21.2 on every benchmark run here: faster or smaller on all 53 comparisons where both have the feature, with no ties.

| Benchmark | deed 0.5.0 | nak v0.21.2 | deed is |
| --- | --- | --- | --- |
| startup (`version`) | 1.90 ms | 121 ms | 64x faster |
| peak memory, startup | 2.0 MB | 69.4 MB | 35x smaller |
| peak memory, verifying 10,000 events | 7.9 MB | 116.7 MB | 15x smaller |
| binary (macOS, Apple Silicon) | 5.41 MB | 43.41 MB | 8x smaller |
| download (deed ships a .tar.gz, nak a bare binary) | 2.78 MB | 43.41 MB | 16x smaller |
| key generation | 2.02 ms | 128 ms | 63x faster |
| sign one event | 2.04 ms | 130 ms | 64x faster |
| verify 10,000 events, one process | 31.96 ms | 1967 ms | 62x faster |
| sign 10,000 events from stdin, one process | 32.32 ms | 1414 ms | 44x faster |
| NIP-19 decode an npub | 1.97 ms | 123 ms | 62x faster |
| NIP-19 decode 10,000 npubs from stdin | 11.86 ms | 146 ms | 12x faster |
| NIP-44 encrypt 1 KB | 2.05 ms | 128 ms | 62x faster |
| NIP-04 encrypt 1 KB | 1.96 ms | 127 ms | 65x faster |
| publish 1,000 events to one relay | 338 ms | 464 ms | 1.4x faster |
| publish 100 events to each of four relays | 46.4 ms | 280 ms | 6x faster |
| req, latest 500 notes | 15.94 ms | 226 ms | 14x faster |
| req, one author's notes | 5.66 ms | 149 ms | 26x faster |
| req, paginated read of all 49,500 notes | 1341 ms | 9603 ms | 7x faster |
| count (NIP-45) | 3.94 ms | 127 ms | 32x faster |
| gift wrap 1,000 messages | 123 ms | 601 ms | 4.9x faster |
| gift unwrap 1,000 messages | 115 ms | 761 ms | 6.6x faster |
| ncryptsec encrypt (log_n 16) | 116 ms | 242 ms | 2.1x faster |
| ncryptsec decrypt (log_n 16) | 116 ms | 239 ms | 2.1x faster |
| proof of work, 16 bits (best of 10, luck) | 2.52 ms | 133 ms | 53x faster |
| proof of work, 20 bits (best of 10, luck) | 7.93 ms | 163 ms | 21x faster |
| relay serving, accept 10,000 published events | 1397 ms | 3540 ms | 2.5x faster |
| relay serving, 32 clients each asking for the latest 500 of 10,000 | 16.33 ms | 74.92 ms | 4.6x faster |
| relay serving, 200 requests in a row on one connection | 99.05 ms | 515 ms | 5.2x faster |
| relay serving, 32 clients, 100,000 events stored | 16.90 ms | 68.67 ms | 4.1x faster |
| NIP-77 sync, 50,000 events with 1% missing (nak's relays) | 146 ms | 790 ms | 5.4x faster |
| NIP-77 sync, same (deed's relays) | 108 ms | 243 ms | 2.2x faster |

Proof of work is a geometric draw, so the best of 10 runs depends on luck. deed also mines on several threads and nak on one; with deed limited to one thread the 20-bit run took 61.02 ms, still faster than nak's 163 ms. The relay serving rows compare the two relays, `deed serve` and `nak serve`, with the same client driving both. `nak serve` caps a REQ at 500 events, so every query asks for 500. A single query is bounded by the client rather than the relay (16.09 ms against 16.10 ms), so the query rows put the relay under load instead: 32 clients at once, or 200 requests in a row on one connection. In the sync rows the first line has `nak serve` relays on both ends, and the second has `deed serve`.

### How this was measured

Everything ran on one Apple M2 Pro with macOS 26.6.2, with deed 0.5.0 and nak v0.21.2 as release builds, and every relay was on loopback (127.0.0.1), so no network is involved. Each figure is the minimum over several runs with hyperfine 2.0.0, because on a shared machine noise only adds time. Both tools got the same inputs: the same signed events, keys, filters and messages, and the output of each was checked for equal work (for example 49,500 notes returned by both paginated reads, and each tool unwrapped the other's gift wraps and decrypted the other's NIP-04 and ncryptsec output). Where a row needed a relay, nak's relay (`nak serve`) served both tools, except in the serving rows, which compare the two relays.

Not compared, because the other side has no counterpart: deed's local store reads (nak has no local event store) and `fetch --thread` (nak's fetch has no thread option), and nak's `fs`, which mounts a filesystem and has no deed equivalent.

## deed on its own

What deed costs to run: how big it is, how fast it starts, how much memory it takes, and how fast it signs, verifies, stores and reads events. Every number here comes from [`bench/run.py`](bench/run.py), which you can run against your own build:

```sh
zig build -Doptimize=ReleaseSafe -Dstrip=true
python3 bench/run.py zig-out/bin/deed
```

It needs python3 and [websocat](https://github.com/vi/websocat). Everything happens on your machine: the relay it talks to is [`bench/relay.py`](bench/relay.py) on 127.0.0.1, and nothing is sent anywhere else. Each timing is the best of several runs, because on a shared machine noise only ever adds time.

Measured on an Apple M2 Pro with macOS 26.6.2. The size, one-event and stream figures are deed 0.5.0 (`ReleaseFast`); the local store and relay sections below were measured with the deed 0.3.1 release binary and have not been remeasured.

## Size

| Release | Binary | Download |
| --- | --- | --- |
| macOS, Apple Silicon | 5.4 MB | 2.8 MB |
| macOS, Intel | 2.4 MB | 1.7 MB |
| Linux, x86_64 | 2.7 MB | 1.8 MB |
| Linux, aarch64 | 2.4 MB | 1.8 MB |

The Linux binaries are statically linked, so that is everything they need. The Intel macOS and Linux rows are from 0.3.1.

## Starting, and one event at a time

| | |
| --- | --- |
| starting any process at all (`/usr/bin/true`), for scale | 1.57 ms |
| `deed version` | 1.90 ms |
| `deed key generate` | 2.02 ms |
| `deed decode <npub>` | 1.97 ms |
| `deed event`, signing one | 2.04 ms |
| `deed verify`, one | 2.04 ms |
| peak memory, `deed version` | 2.0 MB |

deed's own share of a one-shot command is under a millisecond; the rest is the operating system starting a process.

## Streams

| 10,000 records through stdin | |
| --- | --- |
| signing (`deed event -`) | 309,449 per second |
| verifying (`deed verify`) | 312,868 per second |
| decoding npubs (`deed decode`) | 843,294 per second |
| peak memory, verifying 10,000 | 7.9 MB |

## The local store

100,000 signed events from 1,000 authors: a profile, a follow list and 98 notes each.

| | |
| --- | --- |
| storing them from a loopback relay (`req --store`), each signature checked first | 17,379 per second |
| the store file for them | 95 MB |
| one event by id (`req --local -i`) | 3.25 ms |
| one profile (`-a <pubkey> -k 0 -l 1`) | 3.21 ms |
| one author's latest 50 notes | 3.50 ms |
| the latest 500 notes (`-k 1 -l 500`) | 5.03 ms |
| every note, 98,000 of them | 286 ms |

The query times are the whole command, starting deed included, so a lookup costs about a millisecond more than `deed version` does. Events are written to the store in batches, in one transaction each, and a batch is stored before any of it is printed.

## Relays, over loopback

| | |
| --- | --- |
| `req` for 500 events | 43.9 ms, of which the test relay starting a Python process is about 20 |
| `publish` 1,000 events, waiting for each one's OK | 6,933 per second |

These leave the network out, so they measure deed and not the distance to a relay. Against a real relay, the round trip to it dominates.
