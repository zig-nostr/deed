"""A relay for benchmarking deed, on loopback only.

websocat runs one of these per connection and hands it each websocket message
as a line. On REQ it sends every event in the corpus, then EOSE; on EVENT it
answers OK true. It ignores the filter, which is why the benchmark asks for
every kind the corpus holds.
"""
import json
import sys

corpus = sys.argv[1]
out = sys.stdout
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg[0] == "REQ":
        sub = json.dumps(msg[1])
        with open(corpus) as f:
            for ev in f:
                out.write('["EVENT",' + sub + "," + ev.rstrip("\n") + "]\n")
        out.write(json.dumps(["EOSE", msg[1]]) + "\n")
        out.flush()
    elif msg[0] == "EVENT":
        out.write(json.dumps(["OK", msg[1]["id"], True, ""]) + "\n")
        out.flush()
