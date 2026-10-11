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
| `key` | make a key, derive the public one, protect it as an ncryptsec (NIP-49), check keys, and work with BIP-39 mnemonics (NIP-06) |
| `event` | build an event and sign it, and optionally publish it, with tag shortcuts, `@file` content, proof of work (NIP-13) and the `["EVENT",…]` envelope |
| `decode` | turn a NIP-19 code, or a NIP-05 identifier, into the fields it carries |
| `encode` | build a NIP-19 code out of its parts |
| `encrypt` | encrypt a message to someone, with NIP-44 (or legacy NIP-04) |
| `decrypt` | decrypt a NIP-44 (or NIP-04) payload from someone |
| `req` | build a subscription from flags or JSON, and run it: search, any tag, pagination, ids only |
| `fetch` | get the events a code names |
| `publish` | offer signed events to relays, and print the ones they accepted |
| `verify` | check that events are correctly signed, on every core |
| `filter` | keep the events on stdin that match a filter |
| `count` | count the events that match a filter (NIP-45) |
| `kind` | look up an event kind by number or name |
| `relay` | fetch relays' NIP-11 information documents |
| `relays` | show the relays a person reads from and writes to (NIP-65) |
| `gift` | wrap, unwrap and send private messages (NIP-59, NIP-17) |
| `bunker` | run a NIP-46 remote signer |
| `sync` | copy what is missing between relays or a store, with NIP-77 |
| `post` | publish a note, a reply or a comment |
| `profile` | show a profile, or change your own |
| `store` | inspect, export, import and trim a local event store |
| `curl` | run curl with a NIP-98 signed Authorization header |
| `admin` | manage a relay with the NIP-86 management API |
| `blossom` | list, upload, download, delete, check and mirror blobs on a Blossom server |
| `serve` | run a relay on this machine, for development and tests |
| `spell` | fetch a spell and run the subscription it holds |
| `mcp` | serve deed's tools to MCP clients over stdio |
| `outbox` | list, refresh and clear the cached relay lists in a store |
| `nsite` | deploy, download and list static sites (NIP-5A) |
| `nip` | list the NIPs, or print one by number |
| `group` | read and write NIP-29 groups: info, chat, join, moderation |
| `podcast` | list the episodes of a podcast published on Nostr |
| `validate` | check events against a registry-of-kinds schema |
| `dekey` | set up and share a NIP-4E decoupled encryption key |
| `git` | NIP-34 repositories, patches and issues: read them, announce, send patches |

`deed help <command>` explains any of them, and so does `deed <command> --help`. Wherever a verb takes an `npub`, `nsec` or `note` it also takes it in upper case, the form a QR code carries, and `decode` and `fetch` take a code with a `nostr:` prefix in either case. A code that mixes cases is refused, as bech32 requires.

## Authentication

Keys come from `--sec` or from `$NOSTR_SECRET_KEY`. A key on a command line lands in your shell history and in the process table, so the variable is the better habit. Wherever a verb reads a secret key it takes `nsec1…`, 64 hex characters or an `ncryptsec1…`. An ncryptsec asks for its password on the terminal with echo off, or reads it from `$NOSTR_PASSWORD`; a password is never taken from an argument.

deed zeroes the keys and passwords it holds when a run ends, on every path. It cannot zero what the operating system owns: a key given with `--sec` lives in the process's argument block, and one in `$NOSTR_SECRET_KEY` in its environment, for as long as the process runs. For that reason the variable, or better a `bunker://` signer, is preferred to a key on the command line.

A remote signer works there too: give a `bunker://` URI in place of the key, and every verb that signs or encrypts as you (`event`, `post`, `profile set`, `group`, `encrypt`, `decrypt`, `gift`, `curl`, `admin`, `blossom`, and the answers `--auth` gives a relay that asks who you are) asks the signer over NIP-46 instead. Each request waits up to 60 seconds for an answer, since someone may be approving it on another device. When the signer asks for approval at a link, the link is shown on stderr if it is a plain https URL, and not shown otherwise. deed makes a fresh client key for each run, so a signer that asks before trusting a new client asks every time; set `DEED_BUNKER_CLIENT_KEYS` to a file path to keep one client key per signer there (the file is created readable only by you). The verbs that need the key itself (`key public`, `key encrypt`, `bunker`, `nsite deploy`, `mcp`) refuse a `bunker://` URI.

```sh
NOSTR_SECRET_KEY='bunker://…' deed post "hello" wss://relay.example   # the signer approves, up to 60 seconds
deed key encrypt "$NOSTR_SECRET_KEY" > me.ncryptsec                # asks for a password
deed key public "$(cat me.ncryptsec)"                               # asks for it again
deed key mnemonic                                                   # a BIP-39 phrase
deed key from-mnemonic --public                                     # the npub at m/44'/1237'/0'/0/0
deed key validate npub1… nsec1…                                     # exit 1 if any is not valid
deed key expand 1f                                                  # left-pad a short hex key to 64 characters
```

A relay that keeps some events behind authentication (NIP-42) is answered with `--auth` on `req`, `fetch` and `publish`. Without it deed signs nothing it was not asked to sign. `--force-pre-auth` waits for the challenge and answers it before asking anything.

```sh
deed req --auth -k 4 -p npub1… wss://relay.example
```

## Finding a person's relays

deed has no built-in relay list: it contacts only relays you name. A relay list is looked up through the relays you give with `-r` / `--relay` or in `DEED_RELAYS`, and nowhere else. `deed relays` reads a person's relay list (kind 10002), checks its signature, and prints where they read and where they write. `DEED_RELAYS` (comma or space separated) names the relays to ask for every run, and `--relay` adds to it.

```sh
export DEED_RELAYS=wss://purplepag.es
deed relays npub1…                    # url, a tab, then read, write or read,write
deed relays --outbox npub1…           # where they publish: read their notes there
deed relays --inbox npub1…            # where they read: send them something there
deed relays --store ~/.deed/db npub1… # use a cached list first, and keep what is fetched
deed req -k 1 -l 20 -a npub1… $(deed relays --outbox npub1…)
```

With no relay list published, the relay hints in their kind 3 follow list are used instead.

### Following people to their relays

`fetch`, `post`, `profile` and `req --outbox` use those lists for you. They need at least one bootstrap relay, from `-r` or `DEED_RELAYS`, to find the lists, and then they go to the relays the person writes to. A relay you never named is never contacted for anything but that.

```sh
export DEED_RELAYS=wss://purplepag.es
deed fetch npub1…                      # a code with no hints: the author's own write relays
deed profile npub1…                    # the same for a profile
deed post "hello"                      # no relay named: the relays you write to
deed req -k 1 -l 20 --outbox -a npub1… -a npub1…   # each author's write relays
deed req -k 1 --outbox -n 2 -a npub1…              # ask 2 of each author's relays, not 3
```

With `--outbox` on `req`, each author in the filter is asked at their own write relays. `-n` / `--outbox-relays-per-pubkey` sets how many of an author's relays are asked (default 3). It cannot be combined with `--stream`, `--paginate` or `--local`. A note or event id with no hints has no author to follow, so it still needs a relay named. A filter is given to `req` as flags or JSON, and stdin is read only when a lone `-` is given.

With `--store` the relay lists are kept in the store, and `deed outbox` manages that cache:

```sh
deed outbox list    --store ~/.deed/db [npub1…] [--json]   # pubkey, relay, read/write, tab separated
deed outbox refresh npub1… --store ~/.deed/db -r wss://purplepag.es   # ask again, keep the newest
deed outbox clear   --store ~/.deed/db npub1…               # or --all
```

`refresh` keeps the cached copy for a person the relays have no list for. `clear` removes cached relay lists and leaves every other event in the store alone.

## It keeps what it fetches

A run that reaches relays can keep what it received, and a later run can ask the store instead of the network:

```sh
deed req -k 1 -l 50 --store ~/.deed/db wss://relay.example   # once, over the network
deed req -k 1 -l 50 --store ~/.deed/db --local               # again, dialling nothing
```

`--store` creates the store and any directories above it the first time, so the path above works on a machine that has no `~/.deed` yet, and a leading `~` means the home directory even when the shell did not expand it. `--local` only reads: it opens a store that exists, and says there is none rather than leaving an empty one behind a mistyped path. When a store will not open, the message says why: the path is a directory, a part of it is a file, there is no permission, or the file is not a store.

The second command opens no socket. The events came out of a local store that the first command filled, and they are the same events: `deed verify` is as happy with them as it was the first time, because what is stored is what was signed.

Events are checked before they are stored or printed. A relay can send anything, so a signature that does not verify, and an event that does not answer the question that was asked, are both dropped and reported.

### The store verbs

`deed store` works on a store that already exists (only `import` creates one):

```sh
deed store stats  --store ~/.deed/db [--top 5] [--json]   # counts per kind, oldest and newest, size on disk
deed store export --store ~/.deed/db -k 1 -l 100          # matching events, newest first, one per line
deed store import --store ~/.deed/db < events.jsonl       # each event is verified first
deed store prune  --store ~/.deed/db --max 10000          # keep the newest 10000, remove the rest
deed store delete <id> --store ~/.deed/db                 # remove one event
```

`prune` and `delete` remove events from the local file and nothing else. `count --local` and `profile --store` read the same store.

## Subscriptions and filters

`req` takes a filter as flags, as JSON, or both. A JSON object (an argument that starts with `{`, or one or more objects or an array on stdin) is laid under the flags, and several filters make one subscription. `-k -a -i -e -p -t -d -h` cover the common fields, `-T x=value` any one-letter tag, `--search` a NIP-50 search, and `-s` / `-u` take unix seconds, `2h`, `3d` or `2026-10-01`.

```sh
deed req -k 1 --search "zig" -s 2d -l 50 wss://relay.example
deed req '{"kinds":[1],"#t":["nostr"]}' -l 20 wss://relay.example
deed req -k 1 -l 500 --paginate --paginate-interval 500ms wss://relay.example
deed req -k 1 -l 100 --ids-only wss://relay.example
deed req -k 0 -a npub1…                         # no relay: print the REQ, send nothing
```

With `--paginate`, `--limit` is the total across all pages. `deed filter` applies the same filter to events on stdin, and `--check` makes it exit 1 when nothing matched. `deed count` asks relays how many events match (NIP-45), or counts a store with `--local`.

## Syncing

`deed sync` copies what one side lacks, using NIP-77 so that only ids cross the wire to find the difference. A relay that does not support it is named on stderr and asked with a plain REQ instead.

```sh
deed sync -k 1 -a npub1… wss://from.example wss://to.example        # relay to relay
deed sync -k 1 -a npub1… wss://relay.example --store ~/.deed/db     # pull into the store
deed sync -k 1 -a npub1… --store ~/.deed/db wss://relay.example     # push from the store
```

Each event that lands is printed as a line of JSON. `--quiet` prints one line of counts instead, and `--direction pull|push|both` overrides the order of the arguments when a store is involved.

## Posting and profiles

```sh
deed post "hello" wss://relay.example
deed post --reply nevent1… "agreed" wss://relay.example         # NIP-10 root and reply tags
deed post --comment naddr1… "nice piece" wss://relay.example    # NIP-22 kind 1111
deed post --dry-run "hello" wss://relay.example                   # print the signed event, send nothing
deed profile npub1… wss://relay.example                          # show the verified kind 0 fields
deed profile set --about "hello" --confirm wss://relay.example   # change your own
```

`--confirm` shows what would be published and asks on the terminal first. `profile set` reads your current profile from the relays, changes only the fields given, and publishes the result. A profile that could not be read back is never written over: `--force-new` is the explicit way to publish one built from the flags alone.

## Specs and spells

`deed nip` lists the NIPs, one per line with its title, and `deed nip 29` prints one. The text comes from the NIPs repository, is kept in the user cache directory for a day, and an older copy is used, with a note on stderr, if the site cannot be reached. `--refresh` fetches it again.

`deed spell` fetches a kind 777 event, checks its signature, and runs the subscription its tags describe, as `req` would. `$me` and `$contacts` stand for you and the people you follow; say who you are with `--pub` or `--sec`. A spell that lists no relays, or lists `$outbox`, asks each author's own write relays, and `-n` sets how many. A spell ends once the relays have sent what they hold unless you give `--stream`.

The relays a spell lists are its author's choice, so they are printed on stderr before anything is asked of them. A listed relay at a loopback or private address (localhost, 127.x, 10.x, 192.168.x, a name with no dot) is refused unless `--allow-local` is given or the address was also named on your command line. NIP-42 challenges (`--auth`, which needs `--sec`) are answered only at relays named on your command line, never at relays that came from the spell or from `$outbox`.

```sh
deed nip 44 | less
deed spell nevent1… -r wss://relay.example --pub npub1…
```

## Groups

`deed group` reads and writes NIP-29 groups. A group is written `relay'group-id`, as in `wss://groups.example'pizza`. Reading prints events whose signatures were checked.

```sh
deed group info 'wss://groups.example'pizza                 # metadata, admins and members as one object
deed group chat 'wss://groups.example'pizza --limit 20      # newest kind 9 messages, oldest first
deed group chat 'wss://groups.example'pizza --send "hello"  # signed with your key
deed group join 'wss://groups.example'pizza --code abc123
```

The group's state (kinds 39000, 39001 and 39002) counts only when the relay's own key signed it: the `self` field of its NIP-11 document, or its `pubkey` field when `self` is absent. Events from any other key are dropped. A relay that states neither, or whose document cannot be read, is still read, with a warning, and `info` then carries `"verified":false`. `info`, `members`, `admins` and `chat` read. `chat --send`, `join`, `leave` and the moderation commands (`put-user`, `remove-user`, `delete-event`, `create-group`, `delete-group`, `create-invite`) write: each is signed with `--sec` or `$NOSTR_SECRET_KEY`, offered to the group's relay, and printed only if the relay accepted it. The relay decides who may moderate.

## Static sites

`deed nsite` publishes a folder as a static site (NIP-5A): a manifest event that maps paths to the sha256 of each file, and the files themselves on Blossom servers.

```sh
deed nsite deploy ./public --server cdn.example.com wss://relay.example
deed nsite list npub1… --sites -r wss://relay.example       # root and named sites
deed nsite list npub1… -r wss://relay.example               # path, a tab, sha256
deed nsite download npub1… ./copy -r wss://relay.example    # into an empty directory
```

`deploy` hashes every regular file under the folder. Dot-files and dot-directories (`.git`, `.env`, `.DS_Store`) are skipped by default and the skipped paths are named on stderr, because a published file cannot be taken back; `--include-hidden` opts in. Symbolic links are skipped. It uploads only the files the published manifest does not already name, asks every named server with a HEAD request whether it holds each file, and lists in the manifest only the servers that hold every file. It publishes nothing if a file reached no server, and nothing when nothing changed unless you give `--force`. It also refuses to replace a manifest it could not read, or to publish when no relay finished answering, unless you give `--force`. `--name` picks a named site instead of the root site. `download` writes a file only when its bytes hash to the name in the manifest. It refuses a server that resolves to a loopback, private or link-local address unless you give `--allow-local`, and refuses a manifest whose names collide on a case-insensitive disk. With no relay named, the person's relays are found through `DEED_RELAYS`.

## A local relay

`deed serve` runs a relay on this machine, for development and tests. It prints its URL on stdout once it is listening, and logs connections on stderr.

```sh
deed serve --port 0 | head -1                         # a free port; the URL is the first line
deed serve --store ~/.deed/relay --events seed.jsonl  # keep events on disk, load some first
deed serve --auth-required                            # a NIP-42 challenge before anything is answered
```

It listens on 127.0.0.1 by default (`--hostname`, `--port`). Without `--store` it keeps events in a temporary directory that is removed when it stops. `--events` loads a file of events first, verifying each one and skipping bad lines. It speaks NIP-01, NIP-09, NIP-11, NIP-40, NIP-42, NIP-45, NIP-70 and NIP-77, and checks every event's id and signature before storing it. With `--store`, accepted events are written to disk in groups and synced before they are acknowledged.

A browser page cannot reach it by default: a websocket request that carries an `Origin` header is refused, so a page you happen to have open cannot talk to a relay on your machine. `--allow-origin http://localhost:3000` lets a page from that origin in, and may be repeated. `--allow-origin '*'` lets any page in. Clients that are not browsers send no `Origin` and are not affected. Binding to an address other than loopback with `--hostname` makes the relay reachable from other machines, so do that on purpose.

## Private messages

`deed gift` wraps events as NIP-59 gift wraps and sends NIP-17 direct messages. Nothing is sent by `gift` itself: it prints wraps, one per line, for `deed publish`.

```sh
deed gift dm --to npub1… "see you at six" | deed publish wss://relay.example
deed req -k 1059 -p npub1… wss://relay.example | deed gift unwrap --json
```

`dm` adds a copy for you so your other clients can show the message. `unwrap` prints the rumor inside each wrap, and says which check failed (the wrap, the seal, the rumor or the sender) when one does. `encrypt` and `decrypt` take `--nip04` for older clients; NIP-04 has no authentication, so use it only where you must.

## Git repositories

`deed git` reads and writes NIP-34 repositories, patches and issues. A repository is an `naddr1` code, `<npub>/<identifier>`, or a `nostr://` address.

```sh
deed git repo npub1…/deed wss://relay.example            # the announcement
deed git state npub1…/deed                               # HEAD and the refs, from the newest kind 30618
deed git patches naddr1… --apply-ready 1a2b3c4d | git am  # a patch, or a whole series, as an mbox
deed git issues naddr1… --json
deed git announce --dry-run wss://relay.example          # sign the announcement, send nothing
deed git send-patch --repo naddr1… HEAD~2..HEAD --dry-run
```

`repo`, `state`, `patches`, `issues` and `pulls` read, and print events whose signatures were checked. `announce` publishes a kind 30617 for the repository in the current directory (or `-C`), built from its name, remotes and root commit. It never writes over an announcement that exists unless `--replace` is given, which replaces the whole of it. `send-patch` runs `git format-patch` on a commit range and publishes one kind 1617 per commit to the relays the announcement lists. The first carries a root tag and each later one replies to the one before. A patch of 60 kB or more is refused, because NIP-34 asks for a pull request then. `--dry-run` prints the signed events and publishes nothing.

## Podcasts

`deed podcast` lists a podcast's episodes, newest first, one line each: the first eight characters of the event id, the date, the title and the media URL, separated by tabs. The person may be the podcast itself (kind 10154 metadata) or someone who lists podcasts they make (kind 10064 or 10164). It only reads: it does not play or download audio. `-l` limits the episodes per podcast and `-r` names where to look.

```sh
deed podcast npub1… -r wss://relay.example
deed podcast show@example.com -l 10
```

## Checking events against a schema

`deed validate` checks events against the registry-of-kinds schema: each kind's content type, its tags and the tags it requires. An event that passes is printed as given; one that fails is not, its reason goes to stderr as `line N: <reason>`, and the exit status is 1. `--schema` takes an http(s) URL or a file, and a file needs no network. A schema fetched from a URL is kept for 24 hours, and `--refresh` fetches it again. It does not check ids or signatures: `deed verify` does that. A kind the schema does not list passes.

```sh
deed event -k 1 -p not_a_pubkey | deed validate
deed validate --schema ./schema.yaml < events.jsonl
```

## A decoupled encryption key

`deed dekey` sets up and shares a NIP-4E decoupled encryption key. With none announced it makes one, keeps it in `--dir` (default `~/.config/deed/dekey`, files readable only by you) and announces its public key as kind 10044. On a machine that lacks an announced key it announces itself as a device (kind 4454) and looks for a key message (kind 4455) another device sent it. When it holds the key it lists the devices waiting for it. Nothing is sent to them unless you give `--authorize-all`, which sends the key to every waiting device, encrypted to it with NIP-44. `--reject-all`, or neither flag, sends it to none, and the verb never asks a question. `--rotate` makes a new key even though one is announced, and devices then have to be sent the new one. It prints the key's public key as 64 hex characters once this machine holds the secret half.

```sh
deed dekey -r wss://relay.example                    # set up, or look for a key; share with nobody
deed dekey -r wss://relay.example --authorize-all    # send the key to every device waiting for it
```

## Running a signer

`deed bunker` holds a key and signs for the clients it trusts (NIP-46), over the relays you give it. It prints a `bunker://` URI for a client to connect with, and `--qrcode` prints the same URI as a QR code on stderr.

```sh
deed bunker --qrcode wss://relay.example
deed bunker --persist ~/.config/deed/bunker.json wss://relay.example
deed bunker connect 'nostrconnect://…' wss://relay.example
```

Only authorized clients are served: those whose pubkey was given with `--authorized-keys`, and the one that presents the URI's secret (a secret is good for one client; once used it is replaced and a new URI is printed). Nothing is asked interactively. With `--persist` the key, relays and authorized clients survive a restart, in a file only its owner may read; give it an ncryptsec to keep the key encrypted there. Requests are logged to stderr as the method and the client's pubkey, never the content.

## MCP

`deed mcp` serves deed's tools to an MCP client over stdio, for the client to start as a subprocess. Register it in the client's MCP server configuration:

```json
{"mcpServers":{"deed":{"command":"deed","args":["mcp"]}}}
```

The server speaks both generations of the protocol. The older one opens with an `initialize` handshake and is served for the 2024-11-05, 2025-03-26, 2025-06-18 and 2025-11-25 revisions; a handshake that names no known version is answered with 2025-11-25. The 2026-07-28 revision has no handshake: each request carries its protocol version in its metadata, and `server/discover` reports the supported versions, capabilities and server identity.

The tools that are always there are `decode`, `encode`, `verify`, `req`, `fetch`, `count`, `relay_info`, `relays` and `kind`. Relays are named by the caller as `ws://` or `wss://` URLs, and `relay_info` takes nothing else. It also refuses a loopback or private address, unless the server was started with `--allow-local`, for a relay on this machine or network. Events that arrive from relays are checked before they are returned. `encode` never builds an nsec and `decode` refuses one. Every call has a deadline of at most 30 seconds, and results are capped at 256 KiB, with a note saying so.

`--store <path>` adds `store_query`, which reads that store and nothing else. Publishing is off: the `publish_note` and `publish_event` tools are neither listed nor callable unless you start the server with `--allow-publish`, which also needs a signing key from `--sec` or `$NOSTR_SECRET_KEY`. The key is never accepted as a tool argument and never returned. Only kinds 1 (note), 6 and 16 (reposts), 7 (reaction), 1111 (comment) and 9802 (highlight) are signed, `created_at` must be within 300 seconds of now, and `challenge`, `relay`, `u`, `method` and `payload` tags are refused, so a client cannot use the key to answer a relay's authentication or to sign an HTTP request. Anything published this way is public, so enable it only for a client you trust to publish.

```json
{"mcpServers":{"deed":{"command":"deed","args":["mcp","--store","/home/me/.deed/db"]}}}
```

## HTTP verbs

Four verbs talk to a web server rather than a relay, each with a deadline and a cap on how much it will read.

```sh
deed relay wss://relay.example                                   # the NIP-11 document, one JSON line per relay
deed decode bob@example.com                                      # NIP-05: the pubkey and relays the domain lists
deed curl -X PUT -d '{"a":1}' https://example.com/api/thing      # curl with a NIP-98 Authorization header
deed admin relay.example.com banpubkey npub1… "spam"             # a NIP-86 call to a relay
deed blossom upload photo.jpg -s cdn.example.com                 # a blob, by its sha256
```

A NIP-05 name is looked up over https and a redirect is an error. A domain on this machine, or one that resolves to a private or link-local address, is refused, because a name read from an event could otherwise point deed at the local network; `decode --allow-local` permits it, over plain http for localhost. `relay` takes `--pretty`, `--timeout <secs>` and `--allow-http` for plain http to a host that is not local.

`curl` signs a kind 27235 event for the request and hands the rest to the system curl, whose exit status becomes its own. `admin` signs each call with your key and prints the relay's result. `blossom` has `list`, `upload`, `download`, `delete`, `check` and `mirror`; an upload is confirmed only when the server's sha256 and size match the file, and a download is written only when its sha256 matches. Plain http is used only for a host on this machine, or with `--allow-http` where the verb has it.

Web requests and relay connections can go through a proxy: `deed --proxy socks5h://127.0.0.1:9050 req -k 1 wss://relay.example` reads from the relay over Tor, and `deed --proxy socks5h://127.0.0.1:9050 relay wss://relay.example` sends the NIP-11 request the same way. Without `--proxy`, deed reads `DEED_PROXY`, then `HTTPS_PROXY` (for https and wss), `HTTP_PROXY` (for http and ws) and `ALL_PROXY` (lowercase too), skipping hosts listed in `NO_PROXY`. A host on this machine skips the last three, but not `--proxy` or `DEED_PROXY`. `http://` proxies tunnel with CONNECT, `socks5h://` has the proxy resolve names (so `.onion` works and nothing is looked up locally), `socks5://` resolves here, and `user:pass@` in the URL is sent to the proxy. For a `wss://` relay, TLS runs inside the tunnel and the certificate is checked against the relay's name. A relay dial through a proxy has the same deadline as a direct one, and a proxy that is set and cannot be reached fails the connection: deed never goes around it. List a host in `NO_PROXY` to reach it directly.

## What is missing

deed has no daemon and no config file, so the relays you want on every run go in `DEED_RELAYS`.

## How the verbs fit together

Each verb takes its inputs as arguments and, given none, reads them as newline-delimited records on standard input, writing one result per line. That is the whole reason they compose:

```sh
export NOSTR_SECRET_KEY=$(deed key generate)

deed event -c "hello" | deed verify        # builds one, signs it, checks it
cat drafts.jsonl | deed event - | deed verify
cat drafts.jsonl | deed event - | deed publish wss://relay.example > sent.jsonl
deed event -c "hello" wss://relay.example  # signs it and publishes it in one step
```

`publish` prints each event a relay accepted, once the relays have answered or the deadline has passed, so what it writes out is what was published. `event` takes tag shortcuts (`-e`, `-p`, `-d`, `-h`, `-a`), `-t name=value` for the rest, `-c @file` to read content from a file, `--nevent` to print an nevent beside each event, and `--envelope` to print `["EVENT",{…}]`. `--pow <bits>` searches for a nonce (NIP-13) and `--pow-timeout` gives up. With relays named, `--confirm` asks on the terminal before anything is published. A kind may be given by name: `deed kind` lists the names.

A bad record fails that record alone. The stream carries on, the reason goes to standard error, and the exit code reports that something in the run failed.

## Exit codes

Scripts branch on these, so they are part of the interface and not free to drift.

| | |
| --- | --- |
| `0` | it worked |
| `1` | the command ran and failed: a bad signature, an unreadable key, a malformed code, an event no relay accepted |
| `2` | the command was not understood: unknown verb, unknown flag, missing argument. Nothing was attempted |
| `141` | the reader on the other end of the pipe went away, as in `deed decode … \| head -1` |

What a verb counts as failure varies a little, and `deed help <command>` ends with it. `req`, `fetch` and `count` exit 0 when some relay answered, even with nothing matching. `publish`, `event` with relays, and `post` exit 0 when every event was accepted by at least one relay. `verify` and `key validate` exit 1 when any record is bad. `filter --check` exits 1 when nothing matched. `sync` exits 1 when anything missing could not be copied. `store import` exits 1 when any line was rejected. `curl` exits with curl's own status.

## Using deed from an agent

deed is built to be driven by scripts, which suits coding agents doing nostr work: one result per line on stdout, diagnostics on stderr, exit codes that mean one thing each, and `deed help <command>` for the exact usage of anything.

The skill in [`skills/deed`](skills/deed/SKILL.md) teaches an agent the commands, the recipes, and what to confirm with you first: anything that publishes, changes a profile, uploads, deletes or administers is public or permanent, so it asks, and a secret key stays in `NOSTR_SECRET_KEY` rather than on a command line. Add it to any agent that supports skills:

```sh
npx skills add zig-nostr/deed
```

An MCP client can run deed directly with `deed mcp`, see above. In Claude Code the skill also installs as a plugin: `/plugin marketplace add zig-nostr/deed`, then `/plugin install deed@deed`.

## Examples

- [`examples/jev`](examples/jev): fetch the newest thousand notes from five relays and rank them by substance with [Jev](https://docs.typesafe.ai), dropping spam and app data on the way. A real run and what it cost are in its README.

## How fast it is

deed beats nak on every benchmark run: faster or smaller on 50 of 51 comparisons, with one tie and none slower. Startup is 1.9 ms against 121 ms, verifying 10,000 events is 32 ms against 1,967 ms, and memory at startup is 2 MB against 69 MB (deed 0.5.0 and nak v0.21.2, release builds on an Apple M2 Pro, relays on loopback). [BENCHMARKS.md](BENCHMARKS.md) has the full table, how each number was measured and how to reproduce the deed figures.

deed covers every nak command except `fs`, and adds a local event store that `req`, `fetch` and `count` read offline, the `store` verb to manage it, and `fetch --thread` for whole conversations.

A one-shot command runs in about 2 ms and 2 MB of memory. deed signs and verifies about 310,000 events a second each, stores 100,000 events from a relay at about 17,000 a second, and answers a lookup from that store in about 3 ms, start to finish. The macOS binary is 5.4 MB.

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
