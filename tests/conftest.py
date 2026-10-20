"""Root pytest configuration for AI Security Crew tests."""

from pathlib import Path
from typing import Any

import pytest

from mcp_security_review.providers.attack import ATTACK_INDEX_KEY, build_index
from mcp_security_review.providers.intel import IntelCache

ATTACK_FIXTURE = Path(__file__).parent / "fixtures" / "attack-enterprise-subset.json"
"""A small ATT&CK Enterprise 20.0 STIX bundle sliced from the real one."""

# Every place a background ATT&CK refresh can be started from. Each holds its
# own reference (or looks the function up at call time), so each is replaced.
_REFRESH_STARTERS = (
    "mcp_security_review.servers.library_support.ensure_attack_index_background",
    "mcp_security_review.providers.attack.ensure_attack_index_background",
)


@pytest.fixture(autouse=True)
def _isolated_intel_cache(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point the intel cache at a temp dir and never start ATT&CK downloads.

    Review tools and dependency scans read the cached ATT&CK index and start
    a background refresh when it is missing. Tests must not read the
    developer's cache or reach the network, so the cache is empty unless a
    test fills it, and the refresh starters are no-ops unless a test asks
    for `refresh_calls`.
    """
    cache_dir = tmp_path_factory.mktemp("intel-cache")
    monkeypatch.setenv("MCP_SECURITY_REVIEW_CACHE_DIR", str(cache_dir))
    for target in _REFRESH_STARTERS:
        monkeypatch.setattr(target, lambda cache=None: False)


@pytest.fixture
def refresh_calls(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record the background ATT&CK refreshes code asks for (the cache passed)."""
    calls: list[object] = []

    def fake(cache: object = None) -> bool:
        calls.append(cache)
        return True

    for target in _REFRESH_STARTERS:
        monkeypatch.setattr(target, fake)
    return calls


@pytest.fixture(scope="session")
def attack_data() -> dict[str, Any]:
    """The ATT&CK index built from `ATTACK_FIXTURE`, once per session.

    Shared: tests must copy it before changing it.
    """
    return build_index(ATTACK_FIXTURE)


@pytest.fixture
def cached_attack(attack_data: dict[str, Any]) -> None:
    """Put the fixture ATT&CK index in this test's intel cache."""
    IntelCache().put(ATTACK_INDEX_KEY, attack_data)


# ---- Project context fixture repo ----

STACK50_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
"""A 40-hex commit SHA used for the one pinned GitHub Actions step."""

_STACK50_FILES: dict[str, str] = {
    "README.md": (
        "# stack50\n\nFastAPI API, Express/EJS UI, PostgreSQL, and Redis on AWS EC2.\n"
    ),
    "api/pyproject.toml": (
        "[project]\n"
        'name = "stack50-api"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.11"\n'
        "dependencies = [\n"
        '    "fastapi==0.115.0",\n'
        '    "uvicorn[standard]==0.30.6",\n'
        '    "sqlalchemy==2.0.35",\n'
        '    "psycopg[binary]==3.2.3",\n'
        '    "redis==5.0.8",\n'
        "]\n"
    ),
    "api/app/__init__.py": "",
    "api/app/main.py": (
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n\n"
        '@app.get("/health")\n'
        "def health() -> dict[str, str]:\n"
        '    return {"status": "ok"}\n'
    ),
    "api/app/db.py": (
        "import os\n\n"
        "from sqlalchemy import create_engine\n\n"
        'engine = create_engine(os.environ["DATABASE_URL"])\n'
    ),
    "ui/package.json": (
        "{\n"
        '  "name": "stack50-ui",\n'
        '  "version": "0.1.0",\n'
        '  "private": true,\n'
        '  "main": "server.js",\n'
        '  "dependencies": {\n'
        '    "ejs": "^3.1.10",\n'
        '    "express": "^4.19.2",\n'
        '    "express-session": "^1.18.0",\n'
        '    "connect-redis": "^7.1.1"\n'
        "  }\n"
        "}\n"
    ),
    "ui/server.js": (
        "const express = require('express');\n\n"
        "const app = express();\n"
        "app.set('view engine', 'ejs');\n"
        "app.get('/', (req, res) => res.render('index', { title: 'stack50' }));\n"
        "app.listen(3000);\n"
    ),
    "ui/views/index.ejs": "<h1><%= title %></h1>\n",
    "infra/main.tf": (
        "terraform {\n"
        "  required_providers {\n"
        "    aws = {\n"
        '      source  = "hashicorp/aws"\n'
        '      version = "~> 5.0"\n'
        "    }\n"
        "  }\n"
        "}\n\n"
        'provider "aws" {\n'
        "  region = var.region\n"
        "}\n\n"
        'module "vpc" {\n'
        '  source = "terraform-aws-modules/vpc/aws"\n'
        '  name   = "stack50"\n'
        '  cidr   = "10.0.0.0/16"\n'
        "}\n\n"
        'resource "aws_instance" "app" {\n'
        "  ami           = var.ami_id\n"
        '  instance_type = "t3.small"\n'
        "  subnet_id     = module.vpc.private_subnets[0]\n"
        "}\n"
    ),
    "infra/variables.tf": (
        'variable "region" {\n'
        '  default = "us-east-1"\n'
        "}\n\n"
        'variable "ami_id" {\n'
        "  type = string\n"
        "}\n"
    ),
    ".github/workflows/ci.yml": (
        "name: ci\n"
        "on: [push, pull_request]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        f"      - uses: astral-sh/setup-uv@{STACK50_SHA}  # v3\n"
        "      - run: uv sync --frozen\n"
        "        working-directory: api\n"
        "      - run: uv run pytest\n"
        "        working-directory: api\n"
    ),
    ".github/workflows/semgrep.yml": (
        "name: semgrep\n"
        "on: [pull_request]\n"
        "jobs:\n"
        "  semgrep:\n"
        "    runs-on: ubuntu-latest\n"
        "    container:\n"
        "      image: semgrep/semgrep\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{STACK50_SHA}\n"
        "      - run: semgrep scan --config auto --error\n"
    ),
    "Dockerfile": (
        "FROM python:3.12-slim AS base\n"
        "WORKDIR /app\n"
        "COPY api/ /app/\n"
        "RUN pip install --no-cache-dir .\n\n"
        "FROM base AS runtime\n"
        "USER 1000\n"
        'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]\n'
    ),
    "docker-compose.yml": (
        "services:\n"
        "  api:\n"
        "    build: .\n"
        "  ui:\n"
        "    build: ./ui\n"
        "  db:\n"
        "    image: postgres:16\n"
        "  cache:\n"
        "    image: redis:7\n"
    ),
    "trivy.yaml": (
        "severity:\n"
        "  - HIGH\n"
        "  - CRITICAL\n"
        "scan:\n"
        "  scanners:\n"
        "    - vuln\n"
        "    - misconfig\n"
        "    - secret\n"
    ),
    "threat-model.md": (
        "# Threat model: stack50\n\n"
        "## Assets\n\n"
        "User accounts and session data in PostgreSQL and Redis.\n\n"
        "## Threats\n\n"
        "Session theft through the UI; SQL injection through the API.\n"
    ),
    ".env": "SECRET=do-not-read\n",
}


def make_stack50(root: Path) -> Path:
    """Write the issue #50 example repo into `root` and return `root`.

    The stack: a FastAPI API (`api/`), an Express/EJS UI (`ui/`), PostgreSQL
    and Redis in `docker-compose.yml`, and Terraform for an AWS EC2 instance
    (`infra/`). It holds one unpinned and one SHA-pinned GitHub Actions step,
    a mutable `FROM python:3.12-slim`, a registry module without a version,
    Semgrep and Trivy configuration, a `threat-model.md` with two `##`
    headings, and a `.env` whose value must never be read.
    """
    for rel, text in _STACK50_FILES.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root
