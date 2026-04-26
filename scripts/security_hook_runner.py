#!/usr/bin/env python3
"""Standalone runner for SecurityAssessment — called by security_hook.sh (State 2)."""
import sys

from mcp_security_review.security import SecurityAssessment


def main() -> None:
    prompt = sys.stdin.read().strip()
    if not prompt:
        sys.exit(0)

    try:
        assessment = SecurityAssessment()
        requirements = assessment.assess_ticket({
            "summary": prompt,
            "description": prompt,
            "fields": {"issuetype": {"name": "Story"}, "labels": []},
            "comments": [],
        })
    except Exception as exc:
        print(f"Security assessment unavailable: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Risk Level   : {requirements.risk_level}")
    print(f"Categories   : {', '.join(requirements.security_categories)}")
    print()
    print(requirements.prompt_injection)
    print()
    print("Apply ALL requirements above to every line of code you generate. This is mandatory.")


if __name__ == "__main__":
    main()
