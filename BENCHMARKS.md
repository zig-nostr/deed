# Benchmarks

What deed costs to run: how big it is, how fast it starts, how much memory it takes, and how fast it signs, verifies, stores and reads events. Every number here comes from [`bench/run.py`](bench/run.py), which you can run against your own build:

```sh
zig build -Doptimize=ReleaseSafe -Dstrip=true
python3 bench/run.py zig-out/bin/deed
```

It needs python3 and [websocat](https://github.com/vi/websocat). Everything happens on your machine: the relay it talks to is [`bench/relay.py`](bench/relay.py) on 127.0.0.1, and nothing is sent anywhere else. Each timing is the best of several runs, because on a shared machine noise only ever adds time.

Measured on an Apple M2 Pro with macOS 26.6, with deed 0.3.1 built as it is released (`ReleaseSafe`, stripped).

## Size

| Release | Binary | Download |
| --- | --- | --- |
| macOS, Apple Silicon | 2.3 MB | 1.6 MB |
| macOS, Intel | 2.4 MB | 1.7 MB |
| Linux, x86_64 | 2.7 MB | 1.8 MB |
| Linux, aarch64 | 2.4 MB | 1.7 MB |

The Linux binaries are statically linked, so that is everything they need.

## Starting, and one event at a time

| | |
| --- | --- |
| starting any process at all (`/usr/bin/true`), for scale | 1.56 ms |
| `deed version` | 2.34 ms |
| `deed key generate` | 2.37 ms |
| `deed decode <npub>` | 2.41 ms |
| `deed event`, signing one | 2.41 ms |
| `deed verify`, one | 3.02 ms |
| peak memory, `deed version` | 1.7 MB |

deed's own share of a one-shot command is under a millisecond; the rest is the operating system starting a process. Verifying one event adds about 0.6 ms to that.

## Streams

| 10,000 records through stdin | |
| --- | --- |
| signing (`deed event -`) | 22,660 per second |
| verifying (`deed verify`) | 33,270 per second |
| decoding npubs (`deed decode`) | 586,718 per second |
| peak memory, verifying 10,000 | 3.8 MB |

## The local store

100,000 signed events from 1,000 authors: a profile, a follow list and 98 notes each.

| | |
| --- | --- |
| storing them from a loopback relay (`req --store`), each signature checked first | 16,864 per second |
| the store file for them | 94 MB |
| one event by id (`req --local -i`) | 3.25 ms |
| one profile (`-a <pubkey> -k 0 -l 1`) | 3.30 ms |
| one author's latest 50 notes | 3.47 ms |
| the latest 500 notes (`-k 1 -l 500`) | 4.94 ms |
| every note, 98,000 of them | 284 ms |

The query times are the whole command, starting deed included, so a lookup costs about a millisecond more than `deed version` does. Events are written to the store in batches, in one transaction each, and a batch is stored before any of it is printed.

## Relays, over loopback

| | |
| --- | --- |
| `req` for 500 events | 44.5 ms, of which the test relay starting a Python process is about 20 |
| `publish` 1,000 events, waiting for each one's OK | 6,884 per second |

These leave the network out, so they measure deed and not the distance to a relay. Against a real relay, the round trip to it dominates.
