"""Reproduces the statistics reported in Section V-C from results.json and writes outcomes.csv
(one row per agent scenario with the paired per-condition outcomes used by the McNemar tests)."""
import csv, json, math, statistics, sys, os
from collections import defaultdict
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gate
from scenarios import BENIGN, ATTACK

R = json.load(open(os.path.join(HERE, "results.json")))
rows = R["rows"]
A = [r for r in rows if r["kind"] == "attack"]
B = [r for r in rows if r["kind"] == "benign"]
SC = {s["id"]: s for s in BENIGN + ATTACK}

def wilson(k, n, z=1.959964):
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return 100 * max(0, c - h), 100 * min(1, c + h)

def mcnemar_exact(x, y):
    """Two-sided exact McNemar test on paired attack outcomes (binomial test on discordant pairs)."""
    b = sum(r[x] and not r[y] for r in A); c = sum(r[y] and not r[x] for r in A)
    n = b + c; k = min(b, c)
    p = 1.0 if n == 0 else min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)
    return b, c, p

print("Attack success rate (ASR), LLM agent, with 95% Wilson CIs")
for d in ("none", "detector", "guarded"):
    k = sum(r[f"{d}_asr"] for r in A); lo, hi = wilson(k, len(A))
    print(f"  {d:9s} {k:2d}/{len(A)} = {100*k/len(A):5.1f}%  CI [{lo:.1f}, {hi:.1f}]")
print("Worst-case agent ASR:", {d: f"{sum(r[f'wc_{d}_asr'] for r in A)}/{len(A)}" for d in ("none", "detector", "guarded")})
for x, y in (("none_asr", "guarded_asr"), ("detector_asr", "guarded_asr"), ("none_asr", "detector_asr")):
    b, c, p = mcnemar_exact(x, y)
    print(f"Exact McNemar {x} vs {y}: discordant {b} vs {c}, p = {p:.4f}")
k = sum(r["guarded_util"] for r in B); lo, hi = wilson(k, len(B))
print(f"Benign utility (all conditions): {k}/{len(B)}  CI [{lo:.1f}, {hi:.1f}]")

# confirmation rate by effective risk tier and social context (benign, GuardedAgents)
by = defaultdict(lambda: [0, 0])
for r in B:
    s = SC[r["id"]]; a = s["intended"][0]
    key = (f"R{gate.RISK[a[0]]}", "exposed" if any(s["ctx"].values()) else "private")
    by[key][0] += r["guarded_conf"] > 0; by[key][1] += 1
print("Benign tasks needing confirmation, by nominal tier and context:")
for key in sorted(by): print(f"  {key[0]} {key[1]:8s}: {by[key][0]}/{by[key][1]}")

g = R["gate_ms"]
q = statistics.quantiles(g, n=100)
print(f"Gate computation latency over {len(g)} timed evaluations: median {statistics.median(g):.4f} ms, "
      f"p95 {q[94]:.4f} ms, p99 {q[98]:.4f} ms (policy evaluation only; excludes tagging and logging)")

with open(os.path.join(HERE, "outcomes.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["id", "kind", "attack_type", "intent_aligned", "agent_actions", "gate_decisions", "detector_flag",
                "util_none", "util_detector", "util_guarded", "asr_none", "asr_detector", "asr_guarded",
                "wc_asr_none", "wc_asr_detector", "wc_asr_guarded", "confirmations_guarded"])
    for r in rows:
        s = SC[r["id"]]
        aligned = r["kind"] == "attack" and s["intended"] != [("describe_scene", {})]
        w.writerow([r["id"], r["kind"], r.get("atype") or "", int(aligned), json.dumps(r["actions"]),
                    json.dumps(r["decisions"]), int(r["det_flag"]),
                    int(r["none_util"]), int(r["detector_util"]), int(r["guarded_util"]),
                    *(int(r.get(k, False)) if r["kind"] == "attack" else "" for k in
                      ("none_asr", "detector_asr", "guarded_asr", "wc_none_asr", "wc_detector_asr", "wc_guarded_asr")),
                    r["guarded_conf"]])
print("Wrote outcomes.csv")
