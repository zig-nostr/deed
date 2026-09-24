---
name: deed
description: Use deed, the nostr command line, to work with nostr from a shell. Use when generating nostr keys, deriving an npub, building and signing events, checking signatures, encoding or decoding NIP-19 codes (npub, nsec, note, nprofile, nevent, naddr), encrypting or decrypting NIP-44 messages, querying relays with REQ filters, fetching the events a code names, publishing events to relays, or keeping events in a local store to query offline. Also use when writing scripts or pipelines that process nostr events as JSON lines, or when testing a nostr client or relay.
---

# deed

A fast command line for nostr. One binary, macOS and Linux. Every command takes its input as arguments or as newline-delimited records on stdin, and writes one result per line on stdout, so commands pipe into each other and into `jq`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.sh | bash
```

Installs into `~/.local/bin` after checking the download's SHA-256. `deed version` confirms it. `deed help <command>` prints the exact usage of any command; check it before guessing a flag.

## Before you act

- **Publishing is public and permanent.** `deed publish` sends events to relays, where anyone can read them and they cannot be reliably deleted. Confirm with the user before publishing anything to a public relay, and never publish with a key that is not theirs to use.
- **Keep secret keys out of commands and output.** Put the key in `NOSTR_SECRET_KEY`, which `event`, `encrypt` and `decrypt` read when `--sec` is absent. A key passed as `--sec` lands in shell history and the process table. Never print an nsec back to the user unless they asked for it.
- `deed key public` takes a **secret** key. A 64-character hex string is always read as a secret key; passing a public key derives a different, wrong npub without an error.

## Output and exit codes

- stdout: results only, one per line (events as JSON, codes as text or JSON).
- stderr: every diagnostic, each line starting with `deed`.
- Exit codes: `0` success, `1` the command ran and something failed (a bad signature, an event no relay accepted, an unreadable record), `2` the command was not understood, `141` the reader on the other end of the pipe went away. A bad record fails that record alone; the rest of the stream still runs.

## Recipes

```sh
# a key, kept out of history
export NOSTR_SECRET_KEY=$(deed key generate)
deed key public "$NOSTR_SECRET_KEY"          # npub1...

# sign and check
deed event -c "hello" | deed verify           # prints nothing and exits 0 when valid
deed event -k 1 -c "gm" -t t=nostr            # a kind-1 note with a t tag

# sign many: drafts as JSON lines, one event out per line (the `-` is required)
cat drafts.jsonl | deed event - > signed.jsonl

# publish, keeping a record of what went out (ASK THE USER FIRST)
deed publish wss://relay.example < signed.jsonl > published.jsonl
# stdout: each event a relay accepted; stderr: every relay's answer with the event id

# ask relays, and keep what comes back
deed req -k 1 -l 20 -a npub1... --store ~/.deed/db wss://relay.example
deed req -k 1 -l 20 -a npub1... --store ~/.deed/db --local   # again, no network

# see the filter before it is sent: no relay means print, don't send
deed req -k 0 -a npub1...

# get what a code points at (a bare npub fetches the profile)
deed fetch nevent1...
deed fetch npub1... wss://relay.example       # a code with no relay hints needs a relay named

# NIP-19
deed decode nprofile1...                      # {"pubkey":"...","relays":[...]}
deed encode nevent <id-hex> --relay wss://relay.example --kind 1

# NIP-44
deed encrypt --to npub1... "meet at six"
deed decrypt --from npub1... <payload>
```

Filters for `req`: `-k` kind, `-a` author, `-i` id, `-e` / `-p` / `-t` tag values (all repeatable), `-l` limit, `-s` / `-u` since and until in unix seconds, `--stream` to keep reading after stored events, `--timeout <ms>` (default 30000).

## Things that trip people up

- `deed event -` needs the `-` to read drafts from stdin; without it, it signs one empty-content event.
- `deed verify` is silent on success. Check the exit code, not the output.
- Events from relays are verified and matched against the filter before they are printed, so a relay cannot slip in forged or unrelated events. Anything dropped is reported on stderr.
- A relay that does not accept the connection within five seconds (or `--timeout`, if shorter) is named on stderr and left out; the run carries on with the others.
- deed does not yet find an author's relays on its own: name the relays to ask.
- There is no Windows build yet.

## Judging what you fetch

deed's output is one JSON event per line, so it pipes straight into anything that classifies text. [`examples/jev`](https://github.com/zig-nostr/deed/tree/main/examples/jev) ranks a global feed with Jev, TypeSafe's classification model: topic, substance and spam for each note, with the thresholds in the script. Jev is a paid API and needs `TYPESAFE_API_KEY`; run it with `--dry-run` first to see the requests without spending anything, and ask the user before a paid run.

## More

- Source and full reference: https://github.com/zig-nostr/deed
- Benchmarks: https://github.com/zig-nostr/deed/blob/main/BENCHMARKS.md
- The Zig library underneath: https://github.com/zig-nostr/nostr
