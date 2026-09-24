#!/usr/bin/env bash
# Rank a global nostr feed by how much there is to read in each note.
#
# deed fetches the notes, checks every signature, and keeps them in a local
# store. Jev, TypeSafe's classification model, then answers three typed
# questions about each note: what it is about, how much substance it carries,
# and whether it is spam. The decisions stay in this script: the thresholds
# below say what counts as spam and when a topic is too uncertain to use.
#
#   TYPESAFE_API_KEY=... examples/jev/rank-notes.sh [limit] [relay...]
#   examples/jev/rank-notes.sh --dry-run [limit] [relay...]
#
# Prints one JSON object per note, most substance first, and a summary with
# the token count and what the run cost on stderr. --dry-run fetches the notes
# and prints the requests it would send, without calling Jev.
#
# Needs deed, jq and curl. Jev is a paid API, charged per input token; see
# https://docs.typesafe.ai/models for the current price.
set -euo pipefail

# A note Jev calls spam with at least this probability is dropped.
SPAM_AT=0.5
# A topic answered with less confidence than this is reported as "unsure".
SURE_AT=0.6
# Requests in flight at once. Jev's limits are per minute and per second.
JOBS="${JOBS:-8}"
# The most of a note Jev is shown, in characters. A few notes run to tens of
# thousands of characters, past what one request may carry, and the opening
# says what a note is about.
MAX_CHARS=8000
# What one million input tokens costs, in US dollars, for the summary line.
PRICE_PER_MTOK="${PRICE_PER_MTOK:-0.042}"

dry_run=0
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=1
  shift
fi
limit="${1:-1000}"
shift || true
if [ "$#" -gt 0 ]; then
  relays=("$@")
else
  relays=(wss://relay.damus.io wss://nos.lol wss://relay.primal.net wss://offchain.pub wss://nostr.mom)
fi

if [ "$dry_run" = 0 ] && [ -z "${TYPESAFE_API_KEY:-}" ]; then
  echo "TYPESAFE_API_KEY is not set (or pass --dry-run to see the requests)" >&2
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
store="${DEED_STORE:-$work/db}"

# The nostr half. The first run asks every relay and keeps what comes back;
# the second answers from the store alone, so a note two relays both sent is
# judged once.
deed req -k 1 -l "$limit" --store "$store" "${relays[@]}" >/dev/null
deed req -k 1 -l "$limit" --store "$store" --local >"$work/notes"

# Some clients publish their own app data as kind:1 notes, as a JSON object or
# array. That is not text anybody reads, so it is dropped here, in code, rather
# than paid for and judged.
jq -c 'select(.content | test("\\S"))
  | select((.content | try (fromjson | type) catch "text") as $t
      | $t != "object" and $t != "array")' "$work/notes" >"$work/text"

fetched="$(wc -l <"$work/notes" | tr -d ' ')"
readable="$(wc -l <"$work/text" | tr -d ' ')"
echo "fetched $fetched notes, $readable of them text" >&2

# One request per note, the three questions together.
request() {
  jq -c --argjson max "$MAX_CHARS" '{
    state: .content[0:$max],
    model: "jev-latest",
    questions: {
      topic: {
        type: "choice",
        instructions: "What is this nostr note mainly about?",
        criteria: {
          bitcoin: "Bitcoin, Lightning, zaps, money",
          nostr: "Nostr itself: clients, relays, NIPs, the network",
          tech: "Software, hardware or science other than nostr and bitcoin",
          news: "Current events, politics, society",
          art: "Art, music, photography, writing, culture",
          personal: "Daily life, greetings, feelings, jokes",
          media: "Mostly a link, image or video with little text",
          other: null
        }
      },
      substance: {
        type: "score",
        instructions: "How much substance does this note carry for a reader who does not know the author?",
        criteria: [
          "Nothing: a greeting, a reaction, or an empty link",
          "A little: a passing remark",
          "Some: a real point or a piece of information",
          "A lot: an argument, an explanation or a finding worth reading"
        ]
      },
      spam: {
        type: "noul",
        instructions: "Is this note spam, a scam, or automated promotion?"
      }
    }
  }'
}

# Sends one note and prints its answers beside its id. A rate limit or a
# server error is retried with a growing pause; anything else is reported and
# the note skipped, so one bad request does not end the run.
judge() {
  local note="$1" body answer status attempt=0
  body="$(printf '%s' "$note" | request)"
  while :; do
    answer="$(curl -sS --max-time 60 -w '\n%{http_code}' \
      https://api.typesafe.ai/v1/systemone \
      -H "Authorization: Bearer $TYPESAFE_API_KEY" \
      -H "Content-Type: application/json" \
      -d "$body")" || answer=$'\n000'
    status="${answer##*$'\n'}"
    answer="${answer%$'\n'*}"
    [ "$status" = 200 ] && break
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 5 ] || { [ "$status" != 429 ] && [ "$status" != 000 ] && [ "$status" -lt 500 ]; }; then
      echo "skipped $(printf '%s' "$note" | jq -r .id): HTTP $status $answer" >&2
      return 0
    fi
    sleep $((1 << attempt))
  done
  jq -cn --argjson note "$note" --argjson a "$answer" '{
    id: $note.id,
    pubkey: $note.pubkey,
    topic: $a.answers.topic.choice,
    topic_confidence: $a.answers.topic.confidence,
    substance: $a.answers.substance.score,
    spam: $a.answers.spam.noul,
    reply: ($note.tags | any(.[0] == "e")),
    tokens: $a.usage.input_tokens,
    text: ($note.content | gsub("\\s+"; " ") | .[0:120])
  }'
}
export MAX_CHARS
export -f request judge

if [ "$dry_run" = 1 ]; then
  while IFS= read -r note; do printf '%s' "$note" | request; done <"$work/text"
  exit 0
fi

# The single quotes are deliberate: "$1" is expanded by the bash that xargs
# starts, once per note.
# shellcheck disable=SC2016
tr '\n' '\0' <"$work/text" \
  | xargs -0 -n 1 -P "$JOBS" "$BASH" -c 'judge "$1"' _ >"$work/judged"

# The decisions, in code.
jq -c --argjson spam_at "$SPAM_AT" --argjson sure_at "$SURE_AT" '
  select(.spam < $spam_at)
  | if .topic_confidence < $sure_at then .topic = "unsure" else . end' \
  "$work/judged" | jq -sc 'sort_by(-.substance) | .[]'

jq -rs --argjson spam_at "$SPAM_AT" --argjson sure_at "$SURE_AT" \
  --argjson price "$PRICE_PER_MTOK" '
  (map(.tokens) | add // 0) as $tokens
  | map(select(.spam < $spam_at)) as $kept
  | "judged \(length) notes, dropped \(length - ($kept | length)) as spam",
    "topics: \($kept
      | map(if .topic_confidence < $sure_at then "unsure" else .topic end)
      | group_by(.) | map("\(.[0]) \(length)") | join(", "))",
    "\($tokens) input tokens, about $\($tokens * $price / 1000000 * 10000 | round / 10000)"' \
  "$work/judged" >&2
