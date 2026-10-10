---
name: deed
description: Use deed, the nostr command line, to work with nostr from a shell. Use when generating nostr keys, deriving an npub, building and signing events, checking signatures, encoding or decoding NIP-19 codes (npub, nsec, note, nprofile, nevent, naddr), encrypting or decrypting NIP-44 or NIP-04 messages, querying and counting events on relays with REQ filters, fetching the events a code names, publishing events or notes to relays, finding a person's relays, syncing relays, sending private messages, reading or changing a profile, running a NIP-46 signer, managing a relay (NIP-86), working with Blossom blobs, making NIP-98 signed HTTP requests, or keeping events in a local store to query offline. Also use when writing scripts or pipelines that process nostr events as JSON lines, or when testing a nostr client or relay.
---

# deed

A fast command line for nostr. One binary, on macOS, Linux and Windows. Every command takes its input as arguments or as newline-delimited records on stdin, and writes one result per line on stdout, so commands pipe into each other and into `jq`.

## Install

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.sh | bash
```

Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/zig-nostr/deed/main/scripts/install.ps1 | iex
```

Both check the download's SHA-256 before installing. The first installs into `~/.local/bin`; the second into `%LOCALAPPDATA%\deed`, which it adds to `PATH`, so on Windows the new `deed` is found in a new terminal, not the one that ran the installer. `deed version` confirms it. `deed help <command>` prints the exact usage of any command; check it before guessing a flag.

## Before you act

Ask the user before running any of these, every time. They send something out, change someone's state, or remove data, and most cannot be undone.

- `deed post`, `deed publish`, and `deed event` with a relay URL: publishing is public and permanent. Anyone can read the event and it cannot be reliably deleted. Use `--dry-run` (post, profile set) or leave the relay off `event` to show the user the signed event first, or `--confirm` to make deed ask on the terminal.
- `deed profile set`: it replaces the user's kind 0 on the relays. deed keeps the fields you do not set and refuses to write over a profile it could not read; never add `--force-new` unless the user says so.
- `deed sync` when it pushes (to a relay, or from a store to a relay): it publishes whatever the other side lacked.
- `deed blossom upload`, `delete` and `mirror`: they put files on, or remove them from, a server.
- `deed admin`: it changes a relay's bans, allow lists and settings, and needs the relay owner's key.
- `deed bunker`: it signs for whoever it authorizes, for as long as it runs. Authorize only the clients the user names, and say when it is running.
- `deed store delete` and `deed store prune`: they remove events from the local file.
- `deed gift dm` itself sends nothing, but piping it into `deed publish` does.
- `deed curl` signs a request with the user's key and sends it, so treat it as the action the URL performs.
- Never publish or sign with a key that is not the user's to use.

Keys:

- **Keep secret keys out of commands and output.** Put the key in `NOSTR_SECRET_KEY`, which every verb that signs reads when `--sec` is absent. A key passed as `--sec` lands in shell history and the process table. Never print an nsec back to the user unless they asked for it.
- An `ncryptsec1…` is accepted wherever a secret key is. It asks for its password on the terminal, or reads `NOSTR_PASSWORD`. Never put a password on a command line, and do not set `NOSTR_PASSWORD` for the user.
- `deed key public` takes a **secret** key. A 64-character hex string is always read as a secret key; passing a public key derives a different, wrong npub without an error.
- A relay that asks for authentication is answered only with `--auth` (req, fetch, publish). That signs with the user's key, so it is the user's call.

## Output and exit codes

- stdout: results only, one per line (events as JSON, codes as text or JSON).
- stderr: every diagnostic, each line starting with `deed`.
- Exit codes: `0` success, `1` the command ran and something failed (a bad signature, an event no relay accepted, an unreadable record), `2` the command was not understood, `141` the reader on the other end of the pipe went away. A bad record fails that record alone; the rest of the stream still runs. Per verb: `req`, `fetch` and `count` exit 0 when some relay answered even if nothing matched; `publish`, `post` and `event` with relays exit 0 only when every event was accepted somewhere; `verify` and `key validate` exit 1 on any bad record; `filter --check` exits 1 when nothing matched; `curl` returns curl's status.

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
deed decode NOSTR:NPUB1...                    # upper case and a nostr: prefix are both fine
deed encode nevent <id-hex> --relay wss://relay.example --kind 1

# NIP-44
deed encrypt --to npub1... "meet at six"
deed decrypt --from npub1... <payload>
```

```sh
# more of req: search, any tag, JSON, ids only, every page
deed req -k 1 --search "zig" -s 2d -l 50 wss://relay.example
deed req -T x=value -k 1 wss://relay.example
deed req '{"kinds":[1],"#t":["nostr"]}' wss://relay.example
deed req -k 1 -l 500 --paginate wss://relay.example         # -l is the total across pages
deed req -k 1 -l 100 --ids-only wss://relay.example

# filter a stream, count, and look up a kind
deed req -k 1 -l 100 wss://relay.example | deed filter -t nostr --check
deed count -k 1 -a npub1... wss://relay.example             # NIP-45, one line per relay
deed kind reaction                                          # {"kind":7,...}

# find a person's relays (deed only asks relays you name, or DEED_RELAYS)
export DEED_RELAYS=wss://purplepag.es
deed relays --outbox npub1...                               # where they write
deed req -k 1 -l 20 -a npub1... $(deed relays --outbox npub1...)

# keys
deed key encrypt "$NOSTR_SECRET_KEY" > me.ncryptsec         # NIP-49, asks for a password
deed key validate npub1... nsec1...                         # exit 1 if any is invalid
deed key mnemonic                                           # a new BIP-39 phrase (secret: do not echo it back)
deed key from-mnemonic --public                             # reads the phrase from the terminal

# event extras
deed event -k reaction -e <id> -p <pubkey> -c "+"           # tag shortcuts; kinds by name
deed event -c @note.txt --pow 20 --pow-timeout 60           # content from a file, NIP-13
deed event -c "gm" --envelope                               # prints ["EVENT",{...}]

# NIP-05 and relay information
deed decode bob@example.com
deed relay wss://relay.example                              # NIP-11 document

# private messages (ASK FIRST before the publish)
deed gift dm --to npub1... "see you at six" > wraps.jsonl  # sends nothing
deed req -k 1059 -p npub1... wss://relay.example | deed gift unwrap --json

# NIP-04, only for older clients
deed encrypt --nip04 --to npub1... "hi"

# sync with NIP-77 (a push is a publish: ASK FIRST)
deed sync -k 1 -a npub1... wss://from.example --store ~/.deed/db      # pull into the store
deed sync -k 1 -a npub1... wss://from.example wss://to.example         # relay to relay

# the store
deed store stats --store ~/.deed/db --json
deed store export --store ~/.deed/db -k 1 -l 100
deed store import --store ~/.deed/db < events.jsonl

# post and profile (ASK FIRST; --dry-run shows the signed event and sends nothing)
deed post --dry-run "hello" wss://relay.example
deed post --reply nevent1... "agreed" wss://relay.example
deed profile npub1... wss://relay.example                   # show, read-only
deed profile set --about "hello" --dry-run wss://relay.example

# HTTP verbs (ASK FIRST for admin, upload, delete, mirror)
deed curl https://example.com/api/me                        # NIP-98 header added
deed admin relay.example.com supportedmethods               # read-only call
deed blossom check <sha256> -s cdn.example.com
deed blossom download <sha256> -s cdn.example.com -o file
deed blossom upload photo.jpg -s cdn.example.com

# a signer others connect to (ASK FIRST)
deed bunker --persist ~/.config/deed/bunker.json --qrcode wss://relay.example
```

`req`, `filter`, `count`, `sync` and `store export` share the filter flags: `-k` kind, `-a` author, `-i` id, `-e` / `-p` / `-t` / `-d` / `-h` tag values, `-T x=value` for any one-letter tag, `--search`, `-l` limit, `-s` / `-u` since and until (unix seconds, `2h`, `3d` or `2026-10-01`). `req` adds `--stream`, `--paginate`, `--ids-only`, `--bare`, `--timeout <ms>` (default 30000).

## Things that trip people up

- `deed event -` needs the `-` to read drafts from stdin; without it, it signs one empty-content event.
- `--store` creates the file and any directories above it, so `~/.deed/db` works on a fresh machine. `--local` only reads: with no store at the path it says so and exits 1.
- `deed verify` is silent on success. Check the exit code, not the output.
- Events from relays are verified and matched against the filter before they are printed, so a relay cannot slip in forged or unrelated events. Anything dropped is reported on stderr.
- A relay that does not accept the connection within five seconds (or `--timeout`, if shorter) is named on stderr and left out; the run carries on with the others.
- deed does not find an author's relays on its own in `req`, `fetch` or `post`: use `deed relays` and name them.
- `deed serve` and using a bunker:// URI as a key are not finished; do not rely on them. <!-- TODO serve --> <!-- TODO remote signer -->
- `deed post` and `deed profile set` need a relay URL; without one they do nothing useful. `deed profile set` is not a way to start a profile from scratch: an unreadable profile is never overwritten.
- `deed event -` reads drafts; `deed event -c ... wss://relay` also publishes. Check which you mean.

## Judging what you fetch

deed's output is one JSON event per line, so it pipes straight into anything that classifies text. [`examples/jev`](https://github.com/zig-nostr/deed/tree/main/examples/jev) ranks a global feed with Jev, TypeSafe's classification model: topic, substance and spam for each note, with the thresholds in the script. Jev is a paid API and needs `TYPESAFE_API_KEY`; run it with `--dry-run` first to see the requests without spending anything, and ask the user before a paid run.

## More

- Source and full reference: https://github.com/zig-nostr/deed
- Benchmarks: https://github.com/zig-nostr/deed/blob/main/BENCHMARKS.md
- The Zig library underneath: https://github.com/zig-nostr/nostr
