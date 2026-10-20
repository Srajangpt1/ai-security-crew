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
    # deprecated_alias_for: [a, b]   # optional: a retired id that stands for these

threats:
  - id: sso-token-reuse
    name: A token for one app is reused on another
    components: [internal-sso]          # must exist (built-in or yours)
    severity: high                      # critical | high | medium | low
    stride: [spoofing]                  # optional
    cwe: [CWE-345]                      # optional, format CWE-<number>
    mcp_top10: ["MCP06:2025"]           # optional, OWASP MCP Top 10 2025 id
    attack: [T1550.001]                 # optional, MITRE ATT&CK technique ids
    countermeasures: [check-sso-audience, validate-token-claims]

countermeasures:
  - id: check-sso-audience
    name: Check the SSO audience
    how_to: Reject tokens whose audience is not this app.
    effort: low                         # low | medium | high
    asvs: []                            # optional, format v5.0.0-<chapter>.<section>.<item>

  - id: require-imdsv2-internal         # infrastructure entries can add these fields
    name: Require IMDSv2 on our base AMI module
    how_to: Set http_tokens = "required" and a hop limit of 1 in the module.
    effort: low
    providers: [aws]                    # optional: aws | azure | gcp | any
    checks:                             # optional: scanner check ids only
      trivy: [AVD-AWS-0028]             # AVD-AWS-0028 or AWS-0028 (AWS, AZU, GCP, DS, KSV)
      checkov: [CKV_AWS_79]             # CKV_ or CKV2_ ids
      prowler: [ec2_instance_imdsv2_enabled]
      kics: [c306ac53-ee5b-41d3-86a9-0fd2722b4e67]   # query UUID
    compliance:                         # optional: benchmark and control ids only
      cis_aws: ["6.7"]                  # quote CIS ids so YAML keeps them as text
      nist_800_53: [CM-6]               # such as AC-6 or SC-7(5)
    false_positives: Scanners may flag aws_instance when the launch template sets this.

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
- `attack` lists MITRE ATT&CK Enterprise technique ids only (`T1190`, `T1078.004`),
  never names or descriptions. Use current ids: not revoked or deprecated in the
  latest ATT&CK release (check the technique page on attack.mitre.org, or look the
  id up with the `threatmodel_attack_technique` tool). Reviews add the technique
  name and tactics from the ATT&CK catalogue the server downloads; until it has
  downloaded, they show the ids only. Leave `attack` out when no technique fits.
- The risk level of a review is the highest severity among the threats on the components
  the agent picked. Sensitive data (`data_handled`) raises it one step.
- A component with `deprecated_alias_for` is a retired id kept for old callers. Picking
  it is the same as picking each listed component; it is hidden from the menu. The
  built-in `container-and-iac` is one, standing for the nine cloud, container,
  Kubernetes, and CI components.

## Infrastructure fields

Countermeasures for infrastructure code (components starting with `cloud-`, plus
`container-image`, `kubernetes`, and `ci-pipeline`) can carry reference fields. When
any of those components is picked, `verify_code_security` returns an infrastructure
checklist: each item ends with its ids and false positive note, for example
`... [Trivy AVD-AWS-0028; Checkov CKV_AWS_79; Prowler ec2_instance_imdsv2_enabled;
CIS AWS 6.7] (false positive: ...)`. The app-code baseline is left out; only
baseline items with `providers: [any]` (secrets and logging) stay.

- `checks` lists the ids of scanner checks that test for the countermeasure: `trivy`,
  `checkov`, `prowler`, and `kics`. Each list is validated against the id format of
  that scanner. Confirm each id in the scanner's public catalogue before adding it
  (Trivy: the aquasecurity/trivy-checks repo or avd.aquasec.com; Checkov: the
  bridgecrewio/checkov repo or checkov.io; Prowler: the check folders under
  `prowler/providers/<cloud>/services/` in prowler-cloud/prowler; KICS: the
  `metadata.json` of each query in Checkmarx/kics). Leave out ids you cannot confirm
  and ids marked deprecated.
- `compliance` lists benchmark and control ids: `cis_aws` (CIS AWS Foundations
  Benchmark v7.0), `cis_azure` (CIS Azure Foundations v6.0), `cis_gcp` (CIS GCP
  Foundations v5.0), and `nist_800_53` (NIST SP 800-53 rev 5).
- `false_positives` (up to 400 characters) says when scanners report the control
  wrongly, such as settings that live on a launch template rather than the instance.
- `providers` says which clouds the advice applies to (`aws`, `azure`, `gcp`), or
  `any` when it does not depend on one.
- Copy only identifiers from scanners and benchmarks. Names, `how_to`, and
  `false_positives` are written in your own words; never paste a rule's title or
  description.

## Checking your files

Ask your agent for a review. If a file is invalid, the tool returns every problem found.
For the built-in library, `tests/unit/library/` checks references, uniqueness, that
every cited ASVS id exists in ASVS 5.0.0, that every ATT&CK id exists and is
current, and that every infrastructure countermeasure carries scanner check ids.
