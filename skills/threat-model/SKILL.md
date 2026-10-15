---
name: threat-model
description: >
  Developer-focused threat model for a feature, component or system: what can go wrong,
  how likely, and the concrete fix for each threat, with an optional threat-model.md file.
  Use when the user asks to threat model something, what attacks to worry about, the attack
  surface, a security design review, or is designing a feature involving auth, payments,
  file handling, multi-tenancy, external APIs, agents, MCP servers or sensitive data.
argument-hint: "[feature description or ticket link]"
---

Build a threat model for:

$ARGUMENTS

If nothing was given, ask what is being built, the tech stack, and whether there are code, data flows or architecture notes to look at. If it is a ticket or page link, fetch it first with the matching MCP server you have connected. If earlier threat models or design pages exist in a wiki or docs tool you have connected, fetch them too.

Write threats as concrete attack scenarios a developer would recognise, each tied to evidence in the description, code or architecture.

## With the security review tools (preferred)

The plugin's `sec-review` MCP server provides these tools. Use them when they are available.

1. **Components.** Call `general_lightweight_security_review` with the description to get the component menu, and pick the 2 to 5 ids the feature adds or directly modifies (reuse them if a pre-coding review already picked them).
2. **Threat model.** Call `threatmodel_perform_threat_model` with `title`, `description`, `components`, and whatever you have: `data_flows`, `tech_stack`, `architecture_notes`, `data_handled`, and `previous_models_json` (a JSON array of earlier models you fetched). It starts the model from the library's known threats and countermeasures for those components.
3. **Make it specific.** Keep the library threats that apply, drop the ones that do not, and add threats that come from this feature's own design. Every threat needs evidence.
4. **Save.** Ask whether to save it. If yes, call `threatmodel_update_threat_model_file` (it writes `threat-model.md`, appending or replacing as the user prefers).

If a tool returns `"success": false`, follow the error's `hint`.

## Without the tools

Identify the components, data, trust boundaries and actors yourself. For each component, walk through spoofing, tampering, repudiation, information disclosure, denial of service and elevation of privilege, and keep only the threats that fit this feature. Write the file yourself if the user wants it saved.

## Output

```
## Threat Model: <feature>

**Created:** <YYYY-MM-DD>
**Components:** ...
**Data it touches:** be specific (for example "password hashes in the users table")

### What can go wrong

#### TM-1: <plain-language threat>
- **Impact:** <business consequence>
- **Likelihood:** high | medium | low
- **Data affected:** ...
- **Mitigation:** <specific fix: library, setting or code pattern>
- **Evidence:** <what in the description or code makes this credible>
- **Status:** open

### Summary
<overall risk, the most critical threats, and which mitigations come first>
```

After presenting it, ask whether to save it to `threat-model.md`, and whether to append or replace if the file exists.
