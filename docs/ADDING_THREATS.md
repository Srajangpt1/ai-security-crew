# Adding components, threats, and countermeasures

`lightweight_security_review` is driven by a threat library. The built-in library lives in
`src/mcp_security_review/library/` (`components.yaml`, `threats.yaml`,
`countermeasures.yaml`). To add your own, put YAML files in
`.ai-security-crew/library/` in your project. Every `*.yaml` file in that folder is read,
and the server reloads them on each review.

## How the pieces connect

```
component  ->  threats against it  ->  countermeasures that mitigate each threat
```

- A **component** is a building block of a feature (database, file upload, webhook).
  The agent picks the ones that apply from a menu.
- A **threat** says what an attacker does to one or more components. It lists the
  countermeasures that mitigate it.
- A **countermeasure** says what the developer does about it.

Threats attach to components, and countermeasures attach to threats, so adding a
threat is a one-place edit.

## File format

```yaml
components:
  - id: internal-sso          # lowercase slug, never renamed or reused
    name: Company SSO         # shown in the menu
    applies_when: The feature signs users in through our SSO.   # the agent reads this
    implies: [web-endpoint]   # optional: components that always come with this one

threats:
  - id: sso-token-reuse
    name: A token for one app is reused on another
    components: [internal-sso]          # must exist (built-in or yours)
    severity: high                      # critical | high | medium | low
    stride: [spoofing]                  # optional
    cwe: [CWE-345]                      # optional, format CWE-<number>
    countermeasures: [check-sso-audience, validate-token-claims]

countermeasures:
  - id: check-sso-audience
    name: Check the SSO audience
    how_to: Reject tokens whose audience is not this app.
    effort: low                         # low | medium | high
    asvs: []                            # optional, format v5.0.0-<chapter>.<section>.<item>

languages:                              # optional: hints for code review
  - id: kotlin
    name: Kotlin
    extensions: [.kt]                   # selects the language from a file path
    focus: [Unsafe WebView JavaScript bridges]   # what to look for
    checks: [JavaScript interfaces expose only the methods the page needs]

disable: [open-redirect]                # optional: hide built-in entries by id
```

## Rules

- Ids are lowercase slugs (`file-upload`). They are unique across your files and the
  built-ins.
- To change a built-in entry, reuse its id and add `override: true`. Without it the
  loader reports the clash.
- `disable` removes built-in entries. Threats left without any component or
  countermeasure are dropped too.
- Every reference must exist. Unknown fields, bad severities, and malformed CWE or ASVS
  ids are reported together, and the tool returns that list instead of a review.
- A countermeasure with `baseline: true` is added to every code review checklist.
- `verify_code_security` chooses a language from the `language` argument or the file
  extension in `languages`. It never guesses from the code itself.
- The risk level of a review is the highest severity among the threats on the components
  the agent picked. Sensitive data (`data_handled`) raises it one step.

## Checking your files

Ask your agent for a review. If a file is invalid, the tool returns every problem found.
For the built-in library, `tests/unit/library/` checks references, uniqueness, and that
every cited ASVS id exists in ASVS 5.0.0.
