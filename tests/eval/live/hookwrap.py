"""Dry-run hook: run the real asc-guard, log its decision, never run a command.

Used only by the live evaluation. A command the guard allows is swapped for a no-op
so the agent carries on as if it had run; a command the guard stops is blocked with
the guard's reason. File edits are allowed inside the throwaway project only. Fails
closed: any error denies the call, so a broken wrapper can never run an attack.
"""

import json
import os
import subprocess
import sys
import time

READ_ONLY = frozenset({"Read", "Glob", "Grep", "LS"})
EDITS = frozenset({"Write", "Edit"})
GUARD = os.environ["LIVE_GUARD_BIN"]
LOG = os.environ["LIVE_LOG"]


def _real(event: str, raw: str) -> tuple[dict, str]:
    start = time.perf_counter()
    done = subprocess.run(  # noqa: S603
        [GUARD, "hook", event],
        input=raw,
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
    )
    ms = round((time.perf_counter() - start) * 1000, 1)
    out = json.loads(done.stdout) if done.stdout.strip() else {}
    return out, f"{ms}"


def _answer(decision: str, reason: str = "", updated: dict | None = None) -> None:
    spec: dict = {"hookEventName": "PreToolUse", "permissionDecision": decision}
    if reason:
        spec["permissionDecisionReason"] = reason
    if updated is not None:
        spec["updatedInput"] = updated
    print(json.dumps({"hookSpecificOutput": spec}))


def _gate(data: dict, entry: dict, reason: str) -> None:
    tool, given = data.get("tool_name"), data.get("tool_input") or {}
    if entry["decision"] in ("ask", "deny", "error"):
        _answer("deny", reason or "Blocked by the guard.")
    elif tool == "Bash":
        _answer("allow", updated={**given, "command": "echo '[dry run: not executed]'"})
    elif tool in EDITS and str(given.get("file_path", "")).startswith(
        data.get("cwd", "\0")
    ):
        return
    elif tool not in READ_ONLY:
        _answer("deny", "Dry run: this tool is not available.")


def main() -> None:
    event = sys.argv[1]
    raw = sys.stdin.read()
    data = json.loads(raw)
    entry: dict = {"event": event, "tool": data.get("tool_name"), "ts": time.time()}
    reason = ""
    try:
        out, ms = _real(event, raw)
        spec = out.get("hookSpecificOutput", {})
        entry["latency_ms"] = float(ms)
        if event == "pre-tool-use":
            entry["input"] = data.get("tool_input")
            entry["decision"] = spec.get("permissionDecision", "allow")
            reason = spec.get("permissionDecisionReason", "")
        elif event == "post-tool-use":
            entry["flagged"] = bool(spec.get("additionalContext"))
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        out, entry["error"] = {}, str(e)
        if event == "pre-tool-use":
            entry["decision"] = "error"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    if event == "pre-tool-use":
        _gate(data, entry, reason)
    elif out:
        print(json.dumps(out))


if __name__ == "__main__":
    main()
