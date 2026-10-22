"""Reads run.sh's output on stdin and prints, per mode and configuration,
each figure's median and its range over the runs, as Markdown rows."""
import sys
from collections import defaultdict
from statistics import median

MEMORY = ["heap_per_conn", "mmap_per_conn", "rss_per_conn"]
METRICS = {
    "empty": MEMORY,
    "idle": MEMORY,
    "inflight": MEMORY,
    "queued": MEMORY,
    "peak": ["peak_mean", "peak_max"],
    "churn": ["heap_kept", "rss_kept"],
    "hs": ["server_us_per_hs", "server_hs_per_s", "wall_hs_per_s"],
    "resume": ["server_us_per_hs", "server_hs_per_s", "wall_hs_per_s"],
    "enc": ["mib_per_s"],
    "dec": ["mib_per_s"],
    "json": ["server_us_per_req", "server_req_per_s"],
}

rows = defaultdict(lambda: defaultdict(list))
for line in sys.stdin:
    if not line.startswith("run="):
        if line.startswith("#"):
            print(line.rstrip())
        continue
    kv = dict(p.split("=", 1) for p in line.split() if "=" in p)
    key = (kv["mode"], kv.get("n", kv.get("mib", "")), kv["provider"], kv["groups"])
    # Spike 01's runs have no mmap_per_conn.
    for m in METRICS[kv["mode"]]:
        if m in kv:
            rows[key][m].append(float(kv[m]))

last = None
for key in sorted(rows, key=lambda k: (list(METRICS).index(k[0]), int(k[1]))):
    mode, n = key[0], key[1]
    shown = [m for m in METRICS[mode] if any(rows[k][m] for k in rows if k[:2] == key[:2])]
    if (mode, n) != last:
        print(f"\n{mode} {n}\n| provider | groups | " + " | ".join(shown) + " |")
        last = (mode, n)
    cells = []
    for m in shown:
        v = rows[key][m]
        cells.append(f"{median(v):,.1f} ({min(v):,.1f}-{max(v):,.1f}, {len(v)} runs)" if v else "")
    print(f"| {key[2]} | {key[3]} | " + " | ".join(cells) + " |")
