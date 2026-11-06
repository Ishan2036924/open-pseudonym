"""Runs the benchmark.

  python bench/run.py offline            detection, leaks, round trips and speed; needs no model, costs nothing
  python bench/run.py model --base-url https://api.openai.com/v1 --model gpt-x --key-env OPENAI_API_KEY --limit 40

The model run sends each task three or four ways (clear, all-tags, redacted, our profile) and scores the restored
answers by exact match, so no judge model is needed. It spends model tokens: check --limit before you start. The
API key is read from the environment variable you name and is never printed or written anywhere.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sdk/python/src"))
sys.path.insert(0, str(HERE))

from dataset import load_handwritten, make  # noqa: E402

from open_pseudonym import Policy, Session, Source, Vault, load_profile  # noqa: E402

PROFILES = ["strict", "draft_reply", "summarize", "secrets_only"]


def overlap(a, b):
    return a[0] < b[1] and b[0] < a[1]


def gold_spans(text, gold):
    """Place each gold value in the text. Gold values are listed in text order, so each search starts where the
    previous one ended; that keeps a sign-off "Ana" from being pinned to the "Ana" inside an earlier full name."""
    spans, cursor = [], 0
    for type_, value in gold:
        start = text.find(value, cursor)
        if start < 0:  # out of order in a hand-written item; fall back to the first occurrence
            start = text.find(value)
        spans.append((start, start + len(value), type_, value))
        cursor = max(cursor, start + len(value))
    return spans


def detection(items):
    per = {}
    for it in items:
        s = Session("strict", Vault(seed=bytes(32)), known=it.get("known") or {})
        found = [(sp.start, sp.end, sp.type) for sp in s.detect(it["text"])]
        gold = gold_spans(it["text"], it["gold"])
        for g in gold:
            row = per.setdefault(g[2], {"gold": 0, "hit": 0, "found": 0, "right": 0})
            row["gold"] += 1
            row["hit"] += any(overlap(g, f) and f[2] == g[2] for f in found)
        for f in found:
            row = per.setdefault(f[2], {"gold": 0, "hit": 0, "found": 0, "right": 0})
            row["found"] += 1
            row["right"] += any(overlap(g, f) and f[2] == g[2] for g in gold)
    return per


def leaks(items, profile, contacts=False):
    """Share of planted values the profile is meant to hide that still appear in what the model would see.

    With contacts=True the app passes the people it already knows (its address book), as a mail app would.
    """
    policy = load_profile(profile)
    hidden = leaked = 0
    for it in items:
        known = dict(it.get("known") or {})
        if contacts:
            known["PERSON"] = [v for t, v in it["gold"] if t == "PERSON"]
        s = Session(policy, Vault(seed=bytes(32)), known=known)
        masked = s.mask(it["text"], Source(sender="no-reply@example.org")).text
        for type_, value in it["gold"]:
            if policy.rule_for(type_).action == "keep":
                continue
            hidden += 1
            if re.search(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])", masked):
                leaked += 1
    return hidden, leaked


def round_trips(items):
    ok = stream_ok = 0
    times_mask, times_restore = [], []
    for it in items:
        s = Session("strict", Vault(seed=bytes(32)), known=it.get("known") or {})
        t0 = time.perf_counter()
        masked = s.mask(it["text"]).text
        t1 = time.perf_counter()
        back = s.restore(masked, reveal_handles=True)
        t2 = time.perf_counter()
        times_mask.append((t1 - t0) * 1000)
        times_restore.append((t2 - t1) * 1000)
        ok += back == it["text"]
        st = s.stream(reveal_handles=True)
        streamed = "".join(st.feed(masked[i:i + 7]) for i in range(0, len(masked), 7)) + st.flush()
        stream_ok += streamed == back
    return ok, stream_ok, times_mask, times_restore


def offline(out: Path | None):
    gen, hand = make(), load_handwritten()
    lines = ["# Offline benchmark", "", f"Items: {len(gen)} generated (seed 20261105), {len(hand)} hand-written.",
             "Profile for detection: strict. No model involved; costs nothing.", ""]
    for name, items in [("generated", gen), ("hand-written", hand)]:
        per = detection(items)
        lines += [f"## Detection, {name} set", "", "| Type | Gold | Recall | Found | Precision |", "|---|---|---|---|---|"]
        for t, r in sorted(per.items()):
            rec = f"{r['hit'] / r['gold']:.0%}" if r["gold"] else "n/a"
            prec = f"{r['right'] / r['found']:.0%}" if r["found"] else "n/a"
            lines.append(f"| {t} | {r['gold']} | {rec} | {r['found']} | {prec} |")
        lines.append("")
    lines += ["## Leak rate (planted values the profile should hide that still reach the model)", "",
              "| Profile | Generated | Hand-written |", "|---|---|---|"]
    for p in PROFILES:
        h1, l1 = leaks(gen, p)
        h2, l2 = leaks(hand, p)
        lines.append(f"| {p} | {l1}/{h1} ({l1 / max(h1, 1):.1%}) | {l2}/{h2} ({l2 / max(h2, 1):.1%}) |")
    h1, l1 = leaks(gen, "strict", contacts=True)
    h2, l2 = leaks(hand, "strict", contacts=True)
    lines.append(f"| strict + the app's contacts | {l1}/{h1} ({l1 / max(h1, 1):.1%}) | {l2}/{h2} ({l2 / max(h2, 1):.1%}) |")
    ok, sok, tm, tr = round_trips(gen + hand)
    n = len(gen) + len(hand)
    lines += ["", "## Round trip and speed", "",
              f"- restore(mask(x)) == x: {ok}/{n}", f"- streamed restore == whole restore: {sok}/{n}",
              f"- mask: median {statistics.median(tm):.2f} ms, p95 {sorted(tm)[int(0.95 * len(tm))]:.2f} ms per item",
              f"- restore: median {statistics.median(tr):.2f} ms per item", ""]
    report = "\n".join(lines)
    print(report)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report)


# The model run

def ask(base_url, model, key, prompt):
    import httpx

    r = httpx.post(base_url.rstrip("/") + "/chat/completions", timeout=120,
                   headers={"authorization": f"Bearer {key}"},
                   json={"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


def score(answer, task):
    a = answer.strip().strip(".").lower()
    want = task["answer"].lower()
    if task["scored_as"] == "money":
        nums = re.findall(r"[0-9][0-9,]*(?:\.[0-9]+)?", a)
        return bool(nums) and float(nums[-1].replace(",", "")) == float(want)
    return a == want or a.endswith(want)


ALL_TAG = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "all_tags", "rules": {}, "default": {"action": "tag"}})
REDACT = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "redact", "rules": {},
                           "default": {"action": "drop"}})


def model_run(args):
    key = os.environ.get(args.key_env)
    if not key:
        sys.exit(f"set {args.key_env} first (the key is read from the environment only)")
    items = [it for it in make() if it["task"]][: args.limit]
    conditions = {"clear": None, "all_tags": ALL_TAG, "redact": REDACT, "ours": None}
    results = {c: 0 for c in conditions}
    for it in items:
        prompt = it["text"] + "\n\n" + it["task"]["q"]
        for cond, policy in conditions.items():
            if cond == "clear":
                answer = ask(args.base_url, args.model, key, prompt)
            else:
                pol = policy or load_profile("money_math" if it["kind"] == "chat" else
                                             "schedule" if it["kind"] == "email" else "draft_reply")
                s = Session(pol, Vault(), known=it.get("known") or {})
                m = s.mask(it["text"])
                answer = s.restore(ask(args.base_url, args.model, key, m.text + "\n\n" + it["task"]["q"]))
            results[cond] += score(answer, it["task"])
    n = len(items)
    print(json.dumps({"model": args.model, "items": n, "accuracy": {c: round(v / n, 3) for c, v in results.items()}},
                     indent=1))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("offline")
    o.add_argument("--out", type=Path, default=HERE / "results" / "offline.md")
    m = sub.add_parser("model")
    m.add_argument("--base-url", required=True)
    m.add_argument("--model", required=True)
    m.add_argument("--key-env", required=True)
    m.add_argument("--limit", type=int, default=20)
    args = p.parse_args()
    if args.cmd == "offline":
        offline(args.out)
    else:
        model_run(args)


if __name__ == "__main__":
    main()
