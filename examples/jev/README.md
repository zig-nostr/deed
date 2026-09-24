# Ranking a nostr feed with Jev

[`rank-notes.sh`](rank-notes.sh) fetches a global feed of notes with deed and has [Jev](https://docs.typesafe.ai), TypeSafe's classification model, judge every one: what it is about, how much substance it carries, and whether it is spam. Then it prints the notes that are not spam, most substance first.

The two halves do different jobs. deed does the nostr part: it asks the relays, checks every signature, and keeps the notes in a local store, so each note is judged once however many relays sent it. Jev answers typed questions and returns numbers with probabilities and a confidence, not prose, so the decisions (what counts as spam, when a topic is too uncertain to use) are plain thresholds at the top of the script, where you can read and change them.

## Run it

It needs deed, `jq`, `curl`, and a TypeSafe API key from the [console](https://console.typesafe.ai/keys). Jev is paid per input token.

```sh
export TYPESAFE_API_KEY=...
examples/jev/rank-notes.sh 1000 > ranked.jsonl
```

The first argument is how many notes to judge (default 1000); any after it are the relays to ask (default: five large public relays). `--dry-run` fetches the notes and prints the requests it would send, without calling Jev or spending anything.

Each line of output is one note:

```json
{"id":"…","pubkey":"…","topic":"tech","topic_confidence":0.9,"substance":2.78,"spam":0.13,"reply":false,"tokens":638,"text":"ESP32-P4 running Linux is a sovereignty win. …"}
```

`substance` runs from 0 (a greeting, a reaction, an empty link) to 3 (an argument or a finding worth reading). `spam` is the probability Jev gives that the note is spam, a scam or automated promotion. `reply` says whether the note answers another one, which matters below. A summary goes to stderr.

## What a run looks like

One run over the newest 1,000 notes from five relays, on 24 September 2026, with `jev-1.13.0`:

| | |
| --- | --- |
| notes fetched | 1,000 |
| app data posted as notes, dropped before Jev | 371 |
| notes judged | 629 |
| dropped as spam (probability 0.5 or more) | 157 |
| topics of the rest | news 118, personal 110, tech 61, media 44, bitcoin 43, art 13, nostr 11, other 1, unsure 71 |
| input tokens | 539,784 |
| cost | about $0.023 |

Reading the output: the top of the ranking was notes with information in them (market readouts from bitcoin bots, a note on bond yields, a French regional budget story, a line of Spanish prose, a reply thread on how discoveries get made), and the bottom was "GM ☕" and its relatives. In a separate sample of 100 notes that I read by hand, what Jev scored as spam was drug and weapon adverts, cult recruitment, leaked account credentials, and self-promotion, plus the automated news posts below.

## Things to know

- **A lot of kind:1 is not text.** 371 of the 1,000 notes were JSON objects that some client publishes as notes for its own use. The script drops them in code before anything is sent, because they cost tokens and carry nothing to judge.
- **Automated news posts sit near the spam line.** Accounts that repost headlines with a link scored between about 0.6 and 0.85, which is fair ("automated promotion") but may not be what you want. Raise `SPAM_AT` to keep them.
- **Replies are judged without their parent.** "Spot on, and I've found…" has no topic on its own, and Jev often says so: those come back with low confidence, and the script labels them `unsure` rather than guessing. To judge a reply properly, fetch its parent (`deed req -i <id from its e tag> <relay>`) and put both in the state.
- **English works best.** Jev reads other languages, including Japanese and Chinese, but its documentation says accuracy is lower there; the confidence field is the thing to watch.
- **The model can change.** `jev-latest` moves when TypeSafe ships a new version. Pin a version such as `jev-1.13.0` if you tune the thresholds against it.
- **Long notes are cut.** A note longer than `MAX_CHARS` (8,000) is judged on its opening, because a request has a size limit and the opening says what a note is about.

## Changing it

The questions are in the `request` function, as JSON. Add a topic by adding a line to the `criteria` of the `topic` question; ask something new by adding a question beside the other three, since the note is sent once however many questions ask about it. TypeSafe's [primitives](https://docs.typesafe.ai/primitives.md) page describes the three question types, and their [agent skill](https://docs.typesafe.ai/agent-skill.md) teaches a coding agent the API.
