---
name: security-review
description: >
  Pre-coding security review for a development task: which parts of the system it touches,
  the threats to guard against, and the countermeasures to build in. Use before coding a
  feature, or when the user asks about security requirements, risks, or how to build
  something safely (login, payments, file upload, APIs, agents, MCP servers, and so on).
argument-hint: "[task description or ticket link]"
---

Run a pre-coding security review for this task:

$ARGUMENTS

If no task was given, ask the user what they are building. If the task is a ticket or page link (Jira, Confluence, Linear, GitHub issue, Notion, and so on), fetch it first with the matching MCP server you have connected and use its summary, description and acceptance criteria as the task.

## With the security review tools (preferred)

The plugin's `sec-review` MCP server provides these tools. Use them when they are available.

1. **Get the menu.** Call `general_lightweight_security_review` with `task_description`. It returns a menu of components (file upload, database, login, LLM agent, and so on), each with when it applies.
2. **Pick components.** Choose the ids of the components this change adds or directly modifies, usually 2 to 5. Do not pick generously: every extra component adds threats that do not apply.
3. **Get threats.** Call the tool again with the same `task_description`, `components` set to those ids, and `data_handled` if the task touches credentials, payments or personal data. It returns the risk level, the threats (with CWE and STRIDE) and the countermeasures (with how-to and ASVS ids).
4. **Dependencies.** If the task adds packages, call `sca_verify_packages` first and fix any invalid names. Then call `sca_scan_dependencies`. For each finding, answer its `reachability_check` from the code: if the affected symbols are used, or you cannot tell, upgrade to the fixed version or avoid the symbol.
5. **Big features.** For auth, file handling or external integrations, offer a threat model (the `threat-model` skill) with the same components.

If a tool returns `"success": false`, follow the error's `hint`. Do not report a failed scan as clean.

## Without the tools

Do the same reasoning yourself: list the components the change touches, then for each one the concrete ways it can be attacked and the countermeasure for each. The risk level is the highest severity among those threats, raised one step when the task handles credentials, payments or personal data.

## Output

```
## Pre-Coding Security Review

**Task:** ...
**Risk level:** low | medium | high | critical
**Components:** ids picked, one line each on why

### Threats to guard against
- <threat> (<CWE>): one line on how it happens here

### Build these in
- <countermeasure>: what to do, concretely, for this task

### Dependencies
<results of the package checks, or "no new packages">

### Instructions for the code generator
<5 to 7 direct instructions, specific to this task, that the user can paste into a coding prompt>
```

Keep it specific to the task. After the code is written, suggest the `verify-code` skill with the same components.
