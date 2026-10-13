"""Deterministic sampling of AgentDojo runs and case assembly."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from tests.eval.convert import agentdojo_cases as cases
from tests.eval.convert import agentdojo_runs as runs
from tests.eval.convert.agentdojo_tasks import GETTERS

SEED = "agentdojo-v1"
PER_GROUP = 2


@dataclass
class Cand:
    """A usable run and the pieces needed to build its cases."""

    path: str
    model: str
    task: str
    group: tuple[str, ...]
    rank: int
    data: tuple[Any, ...]


def _digest(path: str) -> str:
    return hashlib.sha256(f"{SEED}|{path}".encode()).hexdigest()


def _jkey(*parts: Any) -> str:
    return json.dumps(parts, sort_keys=True, ensure_ascii=False)


def sample(
    cands: list[Cand], key_of: Callable[[Cand], list[str]], seen: set[str]
) -> list[Cand]:
    """Pick up to PER_GROUP candidates per group, deterministically.

    Candidates are ordered by (rank, SHA-256 of seed and path); each pick
    prefers a model, then a user task, not yet chosen in the group. A
    candidate whose dedup keys were already seen is dropped.
    """
    groups: dict[tuple[str, ...], list[Cand]] = defaultdict(list)
    for cand in cands:
        groups[cand.group].append(cand)
    out: list[Cand] = []
    for group in sorted(groups):
        pool = sorted(groups[group], key=lambda c: (c.rank, _digest(c.path)))
        chosen: list[Cand] = []
        while pool and len(chosen) < PER_GROUP:
            best = min(
                pool,
                key=lambda c: (
                    any(c.model == x.model for x in chosen),
                    any(c.task == x.task for x in chosen),
                ),
            )
            pool.remove(best)
            keys = key_of(best)
            if any(k in seen for k in keys):
                continue
            seen.update(keys)
            chosen.append(best)
        out.extend(chosen)
    return out


def normal_call(run: dict[str, Any]) -> dict[str, Any] | None:
    """First non-getter call with arguments, else first call with arguments."""
    calls = [
        c for m in run["messages"] for c in (m.get("tool_calls") or []) if c.get("args")
    ]
    for call in calls:
        if not call["function"].startswith(GETTERS):
            return call
    return calls[0] if calls else None


def benign_result(run: dict[str, Any]) -> tuple[str, str] | None:
    """First tool result of 20+ chars, preferring hard-negative wording."""
    found = []
    for m in run["messages"]:
        text = runs.text_of(m.get("content")) if m.get("role") == "tool" else None
        if text and len(text) >= 20:
            found.append((runs.tool_name(m), text))
    hard = [f for f in found if cases.HARD_NEG.search(f[1])]
    return (hard or found or [None])[0]


def _attack_keys(c: Cand) -> list[str]:
    msg, hit, call = c.data[:3]
    return [
        _jkey("a", call["function"], call["args"], msg, hit.injected),
        _jkey("s", hit.tool, hit.output, msg),
    ]


def _normal_keys(c: Cand) -> list[str]:
    return [_jkey(c.data[1], normal_call(c.data[0]))]


def _result_keys(c: Cand) -> list[str]:
    return [_jkey(c.data[1], benign_result(c.data[0]))]


def build(attack: list[Cand], benign: list[Cand]) -> list[dict[str, Any]]:
    """Sample candidates and build all cases with ids and splits.

    Args:
        attack: Candidates from obeyed attacked runs.
        benign: Candidates from benign runs (data = (run, first user message)).

    Returns:
        Cases ordered attack, harmful scan, normal, harmless scan.
    """
    atk, scn, nrm, neg = [], [], [], []
    for c in sample(attack, _attack_keys, set()):
        a, s = cases.attack_cases(*c.data)
        atk.append(a)
        scn.append(s)
    with_call = [c for c in benign if normal_call(c.data[0])]
    for c in sample(with_call, _normal_keys, set()):
        run, msg = c.data
        prov = f"agentdojo {c.model} {c.group[0]}/{c.task}/none"
        nrm.append(cases.normal_case(msg, normal_call(run), c.group[0], prov))
    with_result = [c for c in benign if benign_result(c.data[0])]
    for c in sample(with_result, _result_keys, set()):
        tool, text = benign_result(c.data[0])  # type: ignore[misc]
        neg.append(cases.harmless_scan(c.data[1], tool, text))
    out = []
    for prefix, items in (("atk", atk), ("scn", scn), ("nrm", nrm), ("neg", neg)):
        for i, case in enumerate(items, 1):
            case["id"] = f"adj-{prefix}-{i:04d}"
            case["split"] = cases.split_of(case["id"])
            out.append(case)
    return out
