"""Agreement between the source-labeling heuristic and the 200-row manual pilot.

    cd train && uv run python data/pilot.py

data/pilot_labels.jsonl holds 200 training rows drawn before the heuristic was
revised (seed 'pilot-20261105'): 130 source rows (deepset, Gandalf,
jailbreak-classification, oasst2) and 70 project rows. `heuristic_v1` is the
label the first heuristic gave, `manual` the agent's own label (null = row
should not be in the set). This script re-labels the source rows with the
current `categorize_source` and prints exact-set agreement for both versions.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_data import categorize_source, is_english, is_obfuscated  # noqa: E402

rows = [json.loads(ln) for ln in open(Path(__file__).with_name("pilot_labels.jsonl"), encoding="utf-8")]
stats = {"v1": [0, 0], "v2": [0, 0]}
binary = [0, 0]
for r in rows:
    src = r["source"].split(":")[0]
    if r["manual"] is None:
        print(f"[excluded] {src}: {r['text'][:70]!r}  english={is_english(r['text'])}")
        continue
    if src in ("deepset/prompt-injections", "Lakera/gandalf_ignore_instructions") and r["manual"] != ["benign"]:
        v2 = categorize_source(r["text"])
    elif src == "jackhhao/jailbreak-classification" and r["manual"] != ["benign"]:
        v2 = sorted(["jailbreak"] + (["obfuscation"] if is_obfuscated(r["text"]) else []))
    else:
        v2 = r["heuristic_v1"]
    for k, pred in (("v1", r["heuristic_v1"]), ("v2", v2)):
        stats[k][0] += pred == r["manual"]
        stats[k][1] += 1
    binary[0] += (r["heuristic_v1"] == ["benign"]) == (r["manual"] == ["benign"])
    binary[1] += 1
    if v2 != r["manual"]:
        print(f"[v2 disagrees] {r['manual']} vs {v2}: {r['text'][:80]!r}")
for k, (a, n) in stats.items():
    print(f"{k}: exact label-set agreement {a}/{n} = {a / n:.1%}")
print(f"attack/benign agreement: {binary[0]}/{binary[1]}")
