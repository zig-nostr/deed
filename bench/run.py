"""Benchmarks for deed: startup, memory, bulk throughput, the local store,
and relays over loopback.

    python3 bench/run.py [path/to/deed]

Needs python3 and websocat. Everything runs on this machine: the relay is
bench/relay.py on 127.0.0.1, and nothing is sent anywhere else. Each timing is
the best of several runs, because on a shared machine noise only ever adds.
"""
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

DEED = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "zig-out/bin/deed")
HERE = os.path.dirname(os.path.abspath(__file__))
AUTHORS = 1000
NOTES_PER_AUTHOR = 98  # plus a profile and a follow list: 100,000 events in all
PORTS = (47460, 47461)


def run(args, data=None):
    r = subprocess.run([DEED] + args, input=data, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"deed {' '.join(args[:3])} failed: {r.stderr.decode()[:300]}")
    return r.stdout


def timed(argv, data=None, runs=5):
    """Best and median wall time in milliseconds."""
    ts = []
    for _ in range(runs):
        t = time.perf_counter()
        r = subprocess.run(argv, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ts.append((time.perf_counter() - t) * 1000)
        if r.returncode != 0:
            sys.exit(f"{' '.join(argv[:3])} exited {r.returncode}")
    return min(ts), statistics.median(ts)


def peak_mb(args, data=None):
    """Peak resident memory, from /usr/bin/time."""
    flag = "-l" if sys.platform == "darwin" else "-v"
    r = subprocess.run(["/usr/bin/time", flag, DEED] + args, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for line in r.stderr.decode().splitlines():
        if "maximum resident set size" in line.lower():
            n = int(line.split()[0] if sys.platform == "darwin" else line.split()[-1])
            return n / 1048576 if sys.platform == "darwin" else n / 1024
    return float("nan")


def row(label, value):
    print(f"| {label} | {value} |")


def main():
    work = tempfile.mkdtemp(prefix="deed-bench-")
    relays = []
    try:
        print(f"deed: {DEED} ({run(['version']).decode().strip()}), {os.path.getsize(DEED):,} bytes\n")
        print("| | |\n| --- | --- |")

        key = run(["key", "generate"]).decode().strip()
        npub = run(["key", "public", key]).decode().strip()
        one = run(["event", "-c", "hello", "--sec", key]).decode().strip()
        floor, _ = timed(["/usr/bin/true"], runs=200)
        row("starting any process at all (`/usr/bin/true`)", f"{floor:.2f} ms")
        for label, args in [
            ("`deed version`", ["version"]),
            ("`deed key generate`", ["key", "generate"]),
            ("`deed decode <npub>`", ["decode", npub]),
            ("`deed event` (sign one)", ["event", "-c", "hello", "--sec", key]),
            ("`deed verify` (one)", ["verify", one]),
        ]:
            best, _ = timed([DEED] + args, runs=200)
            row(label, f"{best:.2f} ms")
        row("peak memory, `deed version`", f"{peak_mb(['version']):.1f} MB")

        n = 10000
        drafts = "".join(json.dumps({"kind": 1, "content": f"note {i}, a few words of ordinary length"}) + "\n" for i in range(n)).encode()
        signed = run(["event", "-", "--sec", key], drafts)
        npubs = ((npub + "\n") * n).encode()
        for label, args, data in [("sign", ["event", "-", "--sec", key], drafts), ("verify", ["verify"], signed), ("decode", ["decode"], npubs)]:
            best, _ = timed([DEED] + args, data)
            row(f"{label} 10,000 through stdin", f"{n / best * 1000:,.0f} per second")
        row("peak memory, verifying 10,000", f"{peak_mb(['verify'], signed):.1f} MB")

        corpus = os.path.join(work, "corpus.jsonl")
        with open(corpus, "wb") as f:
            for a in range(AUTHORS):
                k = run(["key", "generate"]).decode().strip()
                d = [{"kind": 0, "content": json.dumps({"name": f"author {a}"}), "created_at": 1700000000 + a},
                     {"kind": 3, "content": "", "created_at": 1700000001 + a}]
                d += [{"kind": 1, "content": f"note {i} by author {a}, a few words of ordinary length", "created_at": 1700000000 + a * 100 + i} for i in range(NOTES_PER_AUTHOR)]
                f.write(run(["event", "-", "--sec", k], "".join(json.dumps(x) + "\n" for x in d).encode()))
        total = AUTHORS * (NOTES_PER_AUTHOR + 2)
        with open(corpus) as f:
            lines = f.readlines()
        author = json.loads(lines[AUTHORS * 50])["pubkey"]
        event_id = json.loads(lines[total // 2])["id"]
        with open(os.path.join(work, "small.jsonl"), "w") as f:
            f.writelines([l for l in lines if '"kind":1,' in l][:500])

        websocat = shutil.which("websocat") or sys.exit("websocat is needed for the relay benchmarks")
        for port, name in zip(PORTS, ("corpus.jsonl", "small.jsonl")):
            relays.append(subprocess.Popen([websocat, "-t", f"ws-l:127.0.0.1:{port}", f"sh-c:exec python3 {HERE}/relay.py {work}/{name}"], stderr=subprocess.DEVNULL))
        time.sleep(1)
        big, small = (f"ws://127.0.0.1:{p}" for p in PORTS)

        store = os.path.join(work, "store")
        ingest = ["req", "--store", store, "-k", "0", "-k", "1", "-k", "3", "-l", str(total), "--timeout", "600000", big]
        best = float("inf")
        for _ in range(3):
            for p in (store, store + "-lock"):
                if os.path.exists(p):
                    os.remove(p)
            t = time.perf_counter()
            run(ingest)
            best = min(best, time.perf_counter() - t)
        row(f"store {total:,} events from a loopback relay, each checked", f"{total / best:,.0f} per second")
        row("store file for them", f"{os.path.getsize(store) / 1048576:.0f} MB")
        local = ["req", "--store", store, "--local"]
        for label, args in [
            ("`--local`: one event by id", ["-i", event_id]),
            ("`--local`: one profile", ["-a", author, "-k", "0", "-l", "1"]),
            ("`--local`: one author's latest 50 notes", ["-a", author, "-k", "1", "-l", "50"]),
            ("`--local`: latest 500 notes", ["-k", "1", "-l", "500"]),
        ]:
            best, _ = timed([DEED] + local + args, runs=30)
            row(label, f"{best:.2f} ms")
        best, _ = timed([DEED] + local + ["-k", "1", "-l", str(total)])
        row(f"`--local`: every note, {AUTHORS * NOTES_PER_AUTHOR:,}", f"{best:.0f} ms")

        best, _ = timed([DEED, "req", "-k", "1", "-l", "500", small], runs=20)
        row("`req` 500 events from a loopback relay", f"{best:.1f} ms, of which the test relay starting Python is about 20")
        pub = b"".join(signed.splitlines(keepends=True)[:1000])
        best, _ = timed([DEED, "publish", big], pub, runs=3)
        row("`publish` 1,000 events to a loopback relay, each OK awaited", f"{1000 / best * 1000:,.0f} per second")
    finally:
        for r in relays:
            r.kill()
        shutil.rmtree(work, ignore_errors=True)


main()
