import os
import json, statistics, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gate

R = json.load(open(os.path.join(HERE, "results.json")))
rows = R["rows"]
B = [r for r in rows if r["kind"] == "benign"]
A = [r for r in rows if r["kind"] == "attack"]
D = ["none", "detector", "guarded"]
names = {"none": "No defense", "detector": "LLM detector", "guarded": "GuardedAgents"}

def pct(k, n): return 100.0 * k / n if n else 0.0
M = {}
for d in D:
    M[d] = dict(
        util=(sum(r[f"{d}_util"] for r in B), len(B)),
        util_att=(sum(r[f"{d}_util"] for r in A), len(A)),
        asr=(sum(r[f"{d}_asr"] for r in A), len(A)),
        asr_wc=(sum(r[f"wc_{d}_asr"] for r in A), len(A)),
        conf_benign=(sum(r[f"{d}_conf"] > 0 for r in B), len(B)),
    )
det_fp = sum(r["det_flag"] for r in B); det_tp = sum(r["det_flag"] for r in A)

print(f"Scenarios: {len(B)} benign, {len(A)} injection attacks, {R['n_clickjack']} consent-spoofing (A4)\n")
print(f"{'Metric':28s}" + "".join(f"{names[d]:>18s}" for d in D))
for key, lab in [("util","Utility (benign)"),("util_att","Utility under attack"),("asr","ASR (Qwen agent)"),("asr_wc","ASR (worst-case agent)"),("conf_benign","Benign tasks w/ CONFIRM")]:
    print(f"{lab:28s}" + "".join(f"{pct(*M[d][key]):11.1f}% ({M[d][key][0]:>2}/{M[d][key][1]})" for d in D))
print(f"\nDetector flags: benign false positives {det_fp}/{len(B)}, attacks flagged {det_tp}/{len(A)}")
print(f"Gate latency (decision only): median {statistics.median(R['gate_ms'])*1000:.1f} us, p95 {np.percentile(R['gate_ms'],95)*1000:.1f} us")
print(f"Detector latency (CPU, 2 threads): median {statistics.median(R['det_s']):.2f} s")
print(f"Agent latency (CPU): median {statistics.median(R['agent_s']):.2f} s")
print(f"Consent spoofing accepted: in-scene dialog {R['clickjack']['in_scene']}/{R['n_clickjack']}, system channel {R['clickjack']['system']}/{R['n_clickjack']}")
print("\nPer attack type ASR (Qwen agent) none/detector/guarded:")
for t in ("A1","A2","A3"):
    rs=[r for r in A if r["atype"]==t]
    print(" ",t,len(rs),[sum(r[f"{d}_asr"] for r in rs) for d in D])
print("\nAttack successes under GuardedAgents (Qwen / worst-case):",
      [r["id"] for r in A if r["guarded_asr"]], [r["id"] for r in A if r["wc_guarded_asr"]])
print("Benign utility failures under GuardedAgents:", [r["id"] for r in B if not r["guarded_util"]])
print("Benign utility failures, no defense (agent errors):", [r["id"] for r in B if not r["none_util"]])

# ---------- Fig. 2 (drawn at printed size: 2.9 in wide, no scaling) ----------
plt.rcParams.update({"font.family":"Liberation Serif","font.size":7.5,"pdf.fonttype":42,"hatch.linewidth":0.6})
fig, ax = plt.subplots(figsize=(2.9, 1.85))
groups = [("asr","ASR\n(LLM agent)"),("asr_wc","ASR\n(worst case)"),("util","Utility\n(benign)"),("util_att","Utility\n(under attack)")]
x = np.arange(len(groups)); w = 0.27
styles = {"none":dict(fc="white",ec="black",hatch="////"),"detector":dict(fc="#A8A8A8",ec="black"),"guarded":dict(fc="#303030",ec="black")}
for i,d in enumerate(D):
    vals=[pct(*M[d][k]) for k,_ in groups]
    bars=ax.bar(x+(i-1)*w, vals, w, label=names[d], lw=0.6, **styles[d])
    for b,v in zip(bars,vals):
        ax.text(b.get_x()+b.get_width()/2, v+1.5, f"{v:.0f}", ha="center", va="bottom", fontsize=6.5)
ax.set_xticks(x); ax.set_xticklabels([g for _,g in groups], fontsize=7)
ax.set_ylabel("Scenarios (%)", fontsize=7.5); ax.set_ylim(0, 112)
ax.set_yticks([0,25,50,75,100]); ax.tick_params(axis="y", labelsize=7)
ax.spines[["top","right"]].set_visible(False)
ax.legend(ncol=3, fontsize=6.8, frameon=False, loc="upper center", bbox_to_anchor=(0.47,1.17), handlelength=1.2, columnspacing=0.7, handletextpad=0.4)
fig.tight_layout(pad=0.2)
fig.savefig(os.path.join(HERE, "fig2_results.pdf")); fig.savefig(os.path.join(HERE, "fig2_results.png"), dpi=300)
