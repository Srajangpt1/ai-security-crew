---
name: verify-code
description: >
  Security review of code that was just written or changed. Use after generating code, or when
  the user asks whether code is secure, to check for vulnerabilities, or to audit a file before
  shipping (especially auth, APIs, file handling, database queries, agents or anything that
  handles user input).
argument-hint: "[file paths, or a description of what changed]"
---

Review the security of this code:

$ARGUMENTS

If nothing was given, review the files changed in this task (for example from `git diff`). If the user pasted code, review that. Read every file you review in full.

## With the security review tools (preferred)

The plugin's `sec-review` MCP server provides these tools. Use them when they are available.

1. **Components.** Use the components picked during the pre-coding review if there was one. Otherwise call `general_lightweight_security_review` with a short description of what the code does, then pick the 2 to 5 component ids the code implements.
2. **Get the checklist.** Call `general_verify_code_security` with `components` (and `data_handled` if relevant) and `file_path` for each file. Do not paste the code into the call: the tool never receives code. It returns a checklist aimed at those components' threats, plus a short baseline, and a `review_prompt`.
3. **Review.** Follow the `review_prompt`: go through every checklist item against the code you read, and decide pass, fail or not applicable with evidence (file and line).
4. **Dependencies.** If the change added or upgraded packages, call `sca_verify_packages`, then `sca_scan_dependencies`, and answer each finding's `reachability_check` from the code.

If a tool returns `"success": false`, follow the error's `hint`.

## Without the tools

Build the checklist yourself: list the components the code implements, the threats each one faces, and the countermeasure that would stop each threat. Add a baseline: input validation, authorization on every request, no secrets in code or logs, safe error messages, and pinned, known-good dependencies. Then review the code against that list.

## Output

```
## Code Security Review

**Files:** ...
**Components:** ...

### Findings
| Severity | Issue | Where | Fix |
|---|---|---|---|
| high | <what is wrong and how it can be exploited> | file.py:42 | <concrete change> |

### Checklist
- [x] <item>: passes, with evidence
- [ ] <item>: fails, see findings
- n/a <item>: why it does not apply

### Dependencies
<findings with reachability verdicts, or "no new packages">
```

Order findings by severity. Offer to apply the fixes.
