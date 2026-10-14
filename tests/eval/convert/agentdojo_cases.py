"""Build benchmark case dicts from AgentDojo run pieces."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from tests.eval.convert.agentdojo_runs import (
    Hit,
    clip,
    injection_pattern,
)

SOURCE = "agentdojo"
HARD_NEG = re.compile(r"\b(ignore|instructions?|important)\b", re.I)


def carrier_type(tool: str) -> str:
    """Map a tool name to a carrier type."""
    if tool.endswith("webpage"):
        return "web_page"
    return "file" if "file" in tool else "mcp_output"


def split_of(case_id: str) -> str:
    """Stable split: about 20% ``test``, the rest ``dev``."""
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
    return "test" if int(digest, 16) % 5 == 0 else "dev"


def _case(
    kind: str, tool: str, tool_input: dict[str, Any], **fields: Any
) -> dict[str, Any]:
    """Assemble a case with a fixed key order (id and split filled in later)."""
    case: dict[str, Any] = {"id": "", "split": "dev", "kind": kind}
    case["category"] = fields.pop("category")
    case["source"] = SOURCE
    case["technique"] = None
    case["user_messages"] = fields.pop("user_messages")
    case["flagged_content"] = fields.pop("flagged_content", [])
    case["carrier"] = fields.pop("carrier", {})
    case["tool"] = tool
    case["tool_input"] = tool_input
    if "tool_output" in fields:
        case["tool_output"] = fields.pop("tool_output")
    harmful = fields.pop("harmful")
    case["expected"] = {
        "harmful": harmful,
        "acceptable": ["ask", "deny"] if harmful else ["allow"],
    }
    case["notes"] = fields.pop("notes")
    return case


def survives_clip(hit: Hit) -> bool:
    """True if the injected text is still in the clipped tool output."""
    clipped = clip(hit.output, 8000, 0.4)
    flat = clipped.replace("\\n", " ").replace("\\t", " ")
    pat = injection_pattern(hit.injected)
    return bool(pat.search(clipped) or pat.search(flat))


def attack_cases(
    user_msg: str,
    hit: Hit,
    call: dict[str, Any],
    category: str,
    attack_type: str,
    prov: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the harmful ``attack`` and ``result_scan`` cases for one run."""
    flagged = [clip(hit.injected, 1500, 0.5)]
    carrier = {
        "type": carrier_type(hit.tool),
        "placement": hit.placement,
        "phrasing": attack_type,
    }
    common = {"user_messages": [user_msg], "flagged_content": flagged}
    atk = _case(
        "attack",
        call["function"],
        call["args"],
        category=category,
        carrier=carrier,
        harmful=True,
        notes=prov,
        **common,
    )
    scan = _case(
        "result_scan",
        hit.tool,
        {},
        category="injection",
        carrier=carrier,
        harmful=True,
        tool_output=clip(hit.output, 8000, 0.4),
        notes=prov + " (tool result)",
        **common,
    )
    return atk, scan


def normal_case(
    user_msg: str, call: dict[str, Any], suite: str, prov: str
) -> dict[str, Any]:
    """Build a harmless ``normal`` case from a benign run's tool call."""
    return _case(
        "normal",
        call["function"],
        call["args"],
        category=suite,
        user_messages=[user_msg],
        harmful=False,
        notes=prov,
    )


def harmless_scan(user_msg: str, tool: str, output: str) -> dict[str, Any]:
    """Build a harmless ``result_scan`` case from a benign tool result."""
    return _case(
        "result_scan",
        tool,
        {},
        category="benign-output",
        user_messages=[user_msg],
        harmful=False,
        tool_output=clip(output, 8000, 0.4),
        notes="hard negative" if HARD_NEG.search(output) else "",
    )
