"""Tests for the built-in threat library and the component lookup."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mcp_security_review.library import (
    LibraryError,
    Severity,
    UnknownComponentError,
    describe,
    load_library,
)
from mcp_security_review.library.library import Library
from mcp_security_review.library.models import (
    ComplianceRefs,
    Countermeasure,
    ScannerChecks,
    Threat,
)
from mcp_security_review.providers.attack import PENDING_STATUS, AttackIndex

ASVS_IDS = {
    line.strip()
    for line in (Path(__file__).parent / "asvs_5_0_0_ids.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.strip() and not line.startswith("#")
}


@pytest.fixture(scope="module")
def library() -> Library:
    return load_library(Path("/nonexistent-project-root"))


def test_builtin_library_is_not_empty(library: Library) -> None:
    assert len(library.components) >= 25
    assert len(library.threats) >= 85
    assert len(library.countermeasures) >= 85


def test_every_component_has_threats(library: Library) -> None:
    used = {c for t in library.threats.values() for c in t.components}
    aliases = {c.id for c in library.components.values() if c.deprecated_alias_for}
    assert set(library.components) - aliases - used == set()


def test_every_countermeasure_is_used(library: Library) -> None:
    used = {m for t in library.threats.values() for m in t.countermeasures}
    assert set(library.countermeasures) - used == set()


MCP_TOP10 = dict(
    line.split("\t", 1)
    for line in (Path(__file__).parent / "mcp_top10_2025.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.strip() and not line.startswith("#")
)


def test_cited_mcp_top10_ids_exist(library: Library) -> None:
    cited = {i for t in library.threats.values() for i in t.mcp_top10}
    assert len(MCP_TOP10) == 10
    assert cited
    assert cited - set(MCP_TOP10) == set()


def test_agent_threats_are_mapped_to_the_mcp_top10(library: Library) -> None:
    assert library.threats["prompt-injection"].mcp_top10 == ["MCP06:2025"]
    assert library.threats["excessive-agent-permissions"].mcp_top10 == ["MCP02:2025"]
    assert "MCP03:2025" in library.threats["untrusted-mcp-server"].mcp_top10
    assert "MCP01:2025" in library.threats["agent-reads-secrets"].mcp_top10
    # Ordinary web threats are not forced into the MCP list.
    assert library.threats["sql-injection"].mcp_top10 == []


def test_cryptography_and_transport_threats_exist(library: Library) -> None:
    crypto = library.resolve(["cryptography"])
    transport = library.resolve(["transport-security"])

    assert {"weak-crypto-algorithms", "hardcoded-crypto-keys"} <= {
        t.id for t in crypto.threats
    }
    assert "CWE-327" in {c for t in crypto.threats for c in t.cwe}
    assert {"cleartext-transport", "outdated-tls"} <= {t.id for t in transport.threats}


def test_cited_asvs_ids_exist(library: Library) -> None:
    cited = {a for m in library.countermeasures.values() for a in m.asvs}
    assert cited
    assert cited - ASVS_IDS == set()


def test_expand_adds_implied_components(library: Library) -> None:
    assert library.expand(["file-upload"]) == ["file-upload", "web-endpoint"]


def test_expand_keeps_order_and_drops_duplicates(library: Library) -> None:
    result = library.expand(["web-endpoint", "file-upload", "web-endpoint"])
    assert result == ["web-endpoint", "file-upload"]


def test_unknown_component_is_rejected_with_valid_ids(library: Library) -> None:
    with pytest.raises(UnknownComponentError) as info:
        library.resolve(["file-upload", "teleporter"])
    assert info.value.unknown == ["teleporter"]
    assert "file-upload" in info.value.valid


def test_upload_example_returns_upload_threats(library: Library) -> None:
    result = library.resolve(["file-upload", "object-storage"])
    ids = {t.id for t in result.threats}

    assert {"upload-executable-file", "upload-path-traversal", "public-bucket"} <= ids
    assert result.risk_level is Severity.HIGH
    assert result.components == ["file-upload", "object-storage", "web-endpoint"]


def test_implied_only_threats_do_not_drive_the_result(library: Library) -> None:
    result = library.resolve(["file-upload"])

    direct = {t.id for t in result.threats}
    assert "csrf" not in direct
    assert "csrf" in {t.id for t in result.also_consider}
    # A critical generic web threat must not raise the level of an upload review.
    assert result.risk_level is Severity.HIGH


def test_threats_are_sorted_most_severe_first(library: Library) -> None:
    result = library.resolve(["authentication", "database"])
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    ranks = [order.index(t.severity) for t in result.threats]
    assert ranks == sorted(ranks)


def test_countermeasures_are_deduplicated_with_mitigated_threats(
    library: Library,
) -> None:
    result = library.resolve(["file-upload"])

    ids = [m.id for m in result.countermeasures]
    assert len(ids) == len(set(ids))
    assert result.mitigates["upload-rename-and-isolate"] == [
        "upload-executable-file",
        "upload-path-traversal",
    ]


def test_sensitive_data_raises_risk_one_step(library: Library) -> None:
    base = library.resolve(["file-upload"])
    raised = library.resolve(["file-upload"], ["personal_data"])

    assert base.risk_level is Severity.HIGH
    assert raised.risk_level is Severity.CRITICAL
    assert raised.sensitive_data == ["personal_data"]


def test_sensitive_data_kinds_accept_hyphens_and_case(library: Library) -> None:
    result = library.resolve(["file-upload"], ["Personal-Data", "personal_data"])

    assert result.sensitive_data == ["personal_data"]
    assert result.risk_level is Severity.CRITICAL


def test_unknown_sensitive_data_kinds_are_ignored(library: Library) -> None:
    result = library.resolve(["file-upload"], ["favorite_color"])
    assert result.sensitive_data == []
    assert result.risk_level is Severity.HIGH


def test_critical_stays_critical_with_sensitive_data(library: Library) -> None:
    result = library.resolve(["database"], ["credentials"])
    assert result.risk_level is Severity.CRITICAL


def test_menu_lists_every_component(library: Library) -> None:
    menu = library.menu()
    assert [m["id"] for m in menu] == [
        c.id for c in library.components.values() if not c.deprecated_alias_for
    ]
    assert all(m["applies_when"] for m in menu)


def test_baseline_countermeasures_are_flagged(library: Library) -> None:
    ids = {m.id for m in library.baseline_countermeasures()}
    assert ids == {
        "secrets-manager",
        "parameterized-queries",
        "server-side-validation",
        "log-without-secrets",
        "generic-error-messages",
    }


# ---- ATT&CK ----


@pytest.fixture
def attack_index(attack_data: dict[str, Any]) -> AttackIndex:
    return AttackIndex.from_dict(attack_data)


def test_every_attack_id_exists_and_is_current(
    library: Library, attack_index: AttackIndex
) -> None:
    for threat in library.threats.values():
        for tid in threat.attack:
            tech = attack_index.technique(tid)
            assert tech is not None, (threat.id, tid)
            assert not tech["revoked"], (threat.id, tid)
            assert not tech["deprecated"], (threat.id, tid)


def test_majority_of_threats_have_attack_ids(library: Library) -> None:
    mapped = sum(bool(t.attack) for t in library.threats.values())
    assert mapped >= 0.6 * len(library.threats)


def test_attack_ids_follow_the_library_mapping(library: Library) -> None:
    threats = library.threats
    assert "T1190" in threats["sql-injection"].attack
    assert threats["credential-stuffing"].attack == ["T1110.004"]
    assert "T1552.005" in threats["ssrf"].attack
    assert threats["public-bucket"].attack == ["T1530"]
    assert "T1195.001" in threats["typosquatted-package"].attack
    # The most specific sub-technique, not its parent.
    assert threats["default-accounts"].attack == ["T1078.001"]
    assert threats["weak-password-rules"].attack == ["T1110.001"]
    assert threats["weak-password-storage"].attack == ["T1110.002"]
    assert threats["session-fixation"].attack == ["T1550.004"]
    assert threats["model-cost-abuse"].attack == ["T1496.004"]


def test_prompt_injection_threats_are_mapped_alike(library: Library) -> None:
    # Prompt injection is not an ATT&CK Enterprise technique (it is in
    # MITRE ATLAS); what an injected agent then does is mapped on the
    # agent-permission threats instead.
    assert library.threats["prompt-injection"].attack == []
    assert library.threats["indirect-prompt-injection"].attack == []
    assert library.threats["excessive-agent-permissions"].attack == ["T1059"]


def test_threat_rejects_malformed_attack_ids() -> None:
    base: dict[str, Any] = {
        "id": "x",
        "name": "x",
        "components": ["database"],
        "severity": "high",
        "countermeasures": ["parameterized-queries"],
    }
    assert Threat(**base, attack=["T1190", "T1078.004"]).attack == [
        "T1190",
        "T1078.004",
    ]
    for bad in ("t1190", "T190", "T1190.4", "TA0001", "T1190 "):
        with pytest.raises(ValidationError):
            Threat(**base, attack=[bad])


def test_describe_names_attack_techniques_with_an_index(
    library: Library, attack_index: AttackIndex
) -> None:
    view = describe(library.resolve(["database"]), attack=attack_index)

    sqli = next(t for t in view["threats"] if t["id"] == "sql-injection")
    assert sqli["attack"][0]["id"] == "T1190"
    assert sqli["attack"][0]["name"] == "Exploit Public-Facing Application"
    assert sqli["attack"][0]["tactics"] == ["initial-access"]
    assert view["sources"] == {"attack": "ok (ATT&CK 20.0)"}


def test_describe_without_an_index_gives_ids_and_pending(library: Library) -> None:
    view = describe(library.resolve(["database"]), 8)

    sqli = next(t for t in view["threats"] if t["id"] == "sql-injection")
    assert sqli["attack"] == [{"id": "T1190"}]
    assert view["sources"] == {"attack": PENDING_STATUS}
    # Threats without an ATT&CK mapping carry no attack field.
    unmapped = [t for t in view["threats"] if not library.threats[t["id"]].attack]
    assert all("attack" not in t for t in unmapped)


# ---- Cloud, container, Kubernetes, and CI ----

CLOUD_COMPONENTS = [
    "cloud-network",
    "cloud-compute",
    "cloud-iam",
    "cloud-storage",
    "cloud-data-store",
    "cloud-encryption-and-logging",
    "container-image",
    "kubernetes",
    "ci-pipeline",
]

# AWS entries with no matching check in Trivy's catalogue (checked when the
# entries were written). Every other AWS entry carries a Trivy id.
NO_TRIVY_AWS_CHECK = {
    "lb-access-logs",
    "enforce-db-tls",
    "instance-role-least-privilege",
}


def _cloud_entries(library: Library) -> tuple[list[Threat], list[Countermeasure]]:
    threats = [
        t for t in library.threats.values() if set(t.components) & set(CLOUD_COMPONENTS)
    ]
    ids = dict.fromkeys(m for t in threats for m in t.countermeasures)
    return threats, [library.countermeasures[i] for i in ids]


def test_new_components_exist(library: Library) -> None:
    for component_id in CLOUD_COMPONENTS:
        component = library.components[component_id]
        assert "\n" not in component.applies_when
        assert len(component.applies_when) <= 120, component_id
    alias = library.components["container-and-iac"]
    assert alias.deprecated_alias_for == CLOUD_COMPONENTS


def test_alias_expands_as_picked(library: Library) -> None:
    result = library.resolve(["container-and-iac"])

    assert result.picked == CLOUD_COMPONENTS
    assert library.expand(["container-and-iac"]) == CLOUD_COMPONENTS
    ids = {t.id for t in result.threats}
    assert "imds-credential-theft" in ids
    assert {
        "container-runs-as-root",
        "secrets-baked-into-image",
        "overbroad-cloud-permissions",
        "exposed-data-store",
    } <= ids
    assert "imds-credential-theft" not in {t.id for t in result.also_consider}


def test_alias_and_new_ids_resolve_alike(library: Library) -> None:
    by_alias = library.resolve(["container-and-iac", "database"])
    direct = library.resolve([*CLOUD_COMPONENTS, "database"])
    assert [t.id for t in by_alias.threats] == [t.id for t in direct.threats]


def test_alias_hidden_from_menu(library: Library) -> None:
    ids = [m["id"] for m in library.menu()]
    assert "container-and-iac" not in ids
    assert set(CLOUD_COMPONENTS) <= set(ids)


def test_moved_threats_use_the_new_components(library: Library) -> None:
    threats = library.threats
    used = {c for t in threats.values() for c in t.components}
    assert "container-and-iac" not in used
    assert "container-image" in threats["container-runs-as-root"].components
    assert "kubernetes" in threats["container-runs-as-root"].components
    assert "container-image" in threats["secrets-baked-into-image"].components
    assert threats["overbroad-cloud-permissions"].components == ["cloud-iam"]
    assert "cloud-data-store" in threats["exposed-data-store"].components


def test_every_cloud_countermeasure_has_check_ids(library: Library) -> None:
    _, measures = _cloud_entries(library)
    assert len(measures) >= 30
    for m in measures:
        if m.providers == ["any"]:
            continue
        assert m.checks is not None, m.id
        ids = m.checks.trivy + m.checks.checkov + m.checks.prowler + m.checks.kics
        assert ids, m.id
        joined = " ".join(ids)
        if "aws" in m.providers:
            assert m.checks.checkov and m.checks.prowler, m.id
            assert any("AWS" in i for i in m.checks.trivy) or (
                m.id in NO_TRIVY_AWS_CHECK
            ), m.id
        refs = m.compliance
        if "azure" in m.providers:
            assert "AZU" in joined or (refs and refs.cis_azure), m.id
        if "gcp" in m.providers:
            assert "GCP" in joined or (refs and refs.cis_gcp), m.id


def test_aws_entries_cite_cis_where_the_benchmark_covers_them(
    library: Library,
) -> None:
    _, measures = _cloud_entries(library)
    aws = [m for m in measures if "aws" in m.providers]
    cited = [m for m in aws if m.compliance and m.compliance.cis_aws]
    assert len(cited) >= len(aws) // 2
    imds = library.countermeasures["require-imdsv2"]
    assert imds.compliance is not None
    assert imds.compliance.cis_aws == ["6.7"]
    assert imds.false_positives == (
        "Scanners may flag aws_instance when metadata_options are set on the "
        "launch template it uses."
    )
    assert "launch template" in (
        library.countermeasures["encrypt-block-storage"].false_positives or ""
    )


def test_check_id_patterns_enforced(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "bad.yaml").write_text(
        "countermeasures:\n"
        "  - id: bad-check\n"
        "    name: Bad check\n"
        "    how_to: Do it.\n"
        "    effort: low\n"
        "    checks:\n"
        "      trivy: [AVD-XYZ-1]\n"
        "      tfsec: [aws-ec2-x]\n",
        encoding="utf-8",
    )
    with pytest.raises(LibraryError) as info:
        load_library(tmp_path)
    joined = "\n".join(info.value.errors)
    assert "checks.trivy" in joined
    assert "tfsec" in joined


def test_scanner_and_compliance_patterns() -> None:
    good = ScannerChecks(
        trivy=["AVD-AWS-0028", "AWS-0028", "AVD-KSV-0017", "AVD-DS-0002"],
        checkov=["CKV_AWS_79", "CKV2_AWS_11", "CKV_K8S_16"],
        prowler=["ec2_instance_imdsv2_enabled"],
        kics=["c306ac53-ee5b-41d3-86a9-0fd2722b4e67"],
    )
    assert good.trivy[1] == "AWS-0028"
    for field, bad in (
        ("trivy", "AVD-XYZ-1"),
        ("trivy", "AVD-AWS-28"),
        ("checkov", "CKV-AWS-79"),
        ("prowler", "EC2 IMDS"),
        ("kics", "not-a-uuid"),
    ):
        with pytest.raises(ValidationError):
            ScannerChecks(**{field: [bad]})
    assert ComplianceRefs(cis_aws=["6.7", "3.1.4"], nist_800_53=["SC-7(5)"])
    for field, bad in (("cis_aws", "6.x"), ("nist_800_53", "sc-7")):
        with pytest.raises(ValidationError):
            ComplianceRefs(**{field: [bad]})
    with pytest.raises(ValidationError):
        Countermeasure(
            id="x", name="x", how_to="x", effort="low", false_positives="x" * 401
        )
    with pytest.raises(ValidationError):
        Countermeasure(id="x", name="x", how_to="x", effort="low", providers=["oci"])


REQUIRED_TOPICS = [
    "imdsv2",
    "hop limit",
    "0.0.0.0/0",
    "egress",
    "public ip",
    "block public access",
    "publicly_accessible",
    "access log",
    "tls 1.2",
    "kms",
    "rotation",
    "wildcard",
    "instance profile",
    "flow log",
    "cloudtrail",
    "log file validation",
    "user data",
    "force_ssl",
    "verify-full",
    "backup",
    "deletion protection",
    "point-in-time",
    "state",
    "non-root",
    "digest",
    "privileged",
    "readonlyrootfilesystem",
    "limits",
    "networkpolicy",
    "automountserviceaccounttoken",
    "commit sha",
    "permissions:",
    "pull_request_target",
    "oidc",
]


def test_required_topics_covered(library: Library) -> None:
    threats, measures = _cloud_entries(library)
    text = " ".join(
        [t.name for t in threats] + [f"{m.name} {m.how_to}" for m in measures]
    ).lower()
    missing = [topic for topic in REQUIRED_TOPICS if topic not in text]
    assert missing == []


def test_ssm_wildcard_named(library: Library) -> None:
    measures = library.resolve(["cloud-iam"]).countermeasures
    iam = next(m for m in measures if m.id == "least-privilege-iam")
    assert "ssm:*" in iam.how_to
    assert 'Resource "*"' in iam.how_to


# A few public scanner rule titles. Library text must be original wording, so
# none of these may appear in a name or how_to.
SCANNER_TITLES = [
    "aws_instance should activate session tokens for Instance Metadata Service.",
    "Ensure Instance Metadata Service Version 1 is not enabled",
    "A security group rule should not allow unrestricted egress to any IP address.",
    "Security groups should not allow unrestricted ingress to SSH or RDP from any IP "
    "address.",
    "An outdated SSL policy is in use by a load balancer.",
    "Ensure the ELBv2 (Application/Network) has access logging enabled",
    "A KMS key is not configured to auto-rotate.",
    "Ensure rotation for customer created CMKs is enabled",
    "Cloudtrail log validation should be enabled to prevent tampering of log data",
    "Ensure VPC flow logging is enabled in all VPCs",
    "Ensure all data stored in RDS is not publicly accessible",
    "S3 Access block should block public ACL",
    "Image user should not be 'root'",
    "Containers should not run with allowPrivilegeEscalation",
    "Ensure top-level permissions are not set to write-all",
]


def test_no_scanner_text_copied(library: Library) -> None:
    for m in library.countermeasures.values():
        text = f"{m.name} {m.how_to} {m.false_positives or ''}".lower()
        for title in SCANNER_TITLES:
            assert title.lower().rstrip(".") not in text, (m.id, title)
    for t in library.threats.values():
        for title in SCANNER_TITLES:
            assert title.lower().rstrip(".") != t.name.lower(), (t.id, title)


def test_non_root_advice_cites_the_high_uid_checks(library: Library) -> None:
    measure = library.countermeasures["non-root-minimal-images"]
    assert measure.checks is not None
    assert "AVD-KSV-0020" in measure.checks.trivy
    assert "CKV_K8S_40" in measure.checks.checkov
    # runAsNonRoot accepts any non-zero UID; only the high-UID checks want > 10000.
    assert "satisfies Kubernetes runAsNonRoot" not in measure.how_to


@pytest.mark.parametrize(
    ("measure_id", "providers"),
    [
        ("encrypt-databases-at-rest", {"aws", "azure", "gcp"}),
        ("encrypt-queues-topics-and-logs", {"aws", "azure", "gcp"}),
        ("db-backups-and-deletion-protection", {"aws", "azure", "gcp"}),
        ("lb-access-logs", {"aws", "azure", "gcp"}),
    ],
)
def test_data_and_logging_entries_cover_every_cloud(
    library: Library, measure_id: str, providers: set[str]
) -> None:
    measure = library.countermeasures[measure_id]
    assert set(measure.providers) == providers
    assert "On Azure" in measure.how_to or "on Azure" in measure.how_to
    assert "GCP" in measure.how_to


def test_alias_is_dropped_when_all_its_targets_are_disabled(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "off.yaml").write_text(
        "disable: [" + ", ".join(CLOUD_COMPONENTS) + "]\n", encoding="utf-8"
    )
    library = load_library(tmp_path)

    assert "container-and-iac" not in library.components
    assert "container-and-iac" not in [m["id"] for m in library.menu()]
    with pytest.raises(UnknownComponentError):
        library.resolve(["container-and-iac"])


def test_alias_keeps_its_remaining_targets(tmp_path: Path) -> None:
    folder = tmp_path / ".ai-security-crew" / "library"
    folder.mkdir(parents=True)
    (folder / "off.yaml").write_text("disable: [ci-pipeline]\n", encoding="utf-8")
    library = load_library(tmp_path)

    assert library.resolve(["container-and-iac"]).picked == CLOUD_COMPONENTS[:-1]
    assert "container-and-iac" not in [m["id"] for m in library.menu()]
