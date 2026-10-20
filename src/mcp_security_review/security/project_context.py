"""Read-only scan of a project folder: its stack, IaC, CI, and pinning gaps.

The scan backs ``general_project_context``. It walks the folder without
following symlinks, never opens secret-looking files (they are only listed by
name), and reads at most ``MAX_FILES`` files, ``MAX_FILE_BYTES`` per file, and
``MAX_TOTAL_BYTES`` in total. Every file name, reference, and heading it
returns is repository data: control characters are removed and the text is
clipped to ``LINE_LIMIT`` characters.
"""

import fnmatch
import json
import os
import re
import stat
import tomllib
from collections.abc import Callable, Collection
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_security_review.library import builtin_library
from mcp_security_review.providers.intel import untrusted

MAX_FILES = 2000
MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 8_000_000
MAX_FLAGS = 50
MAX_LISTED = 100
"""Most entries kept in any list of file names."""
MAX_HEADINGS = 50
LINE_LIMIT = 200
"""Characters kept from any file name, reference, or heading."""
FIX_WITH = "sca_verify_packages"

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".terraform",
    "__pycache__",
    ".tox",
}
SENSITIVE_PATTERNS = (
    ".env*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "*.tfstate*",
    "*.tfvars",
    "*.tfvars.json",
)
"""File names that are listed as present but never opened."""

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".scala": "scala",
    ".ex": "elixir",
}
# Manifest name -> (package manager, language).
_MANIFESTS = {
    "pyproject.toml": ("pip", "python"),
    "setup.py": ("pip", "python"),
    "setup.cfg": ("pip", "python"),
    "pipfile": ("pipenv", "python"),
    "poetry.lock": ("poetry", "python"),
    "uv.lock": ("uv", "python"),
    "package.json": ("npm", "javascript"),
    "yarn.lock": ("yarn", "javascript"),
    "pnpm-lock.yaml": ("pnpm", "javascript"),
    "go.mod": ("go", "go"),
    "cargo.toml": ("cargo", "rust"),
    "gemfile": ("bundler", "ruby"),
    "pom.xml": ("maven", "java"),
    "build.gradle": ("gradle", "java"),
    "build.gradle.kts": ("gradle", "kotlin"),
    "composer.json": ("composer", "php"),
}
# Dependency name -> framework reported.
_FRAMEWORKS = {
    "fastapi": "fastapi",
    "flask": "flask",
    "django": "django",
    "starlette": "starlette",
    "sqlalchemy": "sqlalchemy",
    "psycopg": "psycopg",
    "psycopg-binary": "psycopg",
    "psycopg2": "psycopg",
    "psycopg2-binary": "psycopg",
    "asyncpg": "asyncpg",
    "pymongo": "pymongo",
    "redis": "redis",
    "celery": "celery",
    "express": "express",
    "ejs": "ejs",
    "koa": "koa",
    "fastify": "fastify",
    "next": "next",
    "@nestjs/core": "nestjs",
    "react": "react",
    "pg": "pg",
    "prisma": "prisma",
    "@prisma/client": "prisma",
    "mysql2": "mysql2",
    "mongoose": "mongoose",
    "sequelize": "sequelize",
    "typeorm": "typeorm",
    "ioredis": "redis",
}
_WEB_FRAMEWORKS = {
    "fastapi",
    "flask",
    "django",
    "starlette",
    "express",
    "koa",
    "fastify",
    "next",
    "nestjs",
}
_DB_LIBRARIES = {
    "sqlalchemy",
    "psycopg",
    "asyncpg",
    "pg",
    "prisma",
    "mysql2",
    "sequelize",
    "typeorm",
    "mongoose",
    "pymongo",
}
_CLOUD_PROVIDERS = {"aws", "azurerm", "google", "google-beta"}
_STORAGE_RESOURCE = re.compile(
    r"^(aws_s3_bucket|azurerm_storage_|google_storage_bucket)"
)
_DATA_STORE_RESOURCE = re.compile(
    r"^(aws_(db_|rds_|dynamodb_|elasticache_|redshift_|docdb_|neptune_)"
    r"|azurerm_(\w*sql\w*|cosmosdb_|redis_)"
    r"|google_(sql_|bigquery_|spanner_|bigtable_|firestore_|redis_))"
)
_CI_FILES = {
    ".gitlab-ci.yml": "gitlab-ci",
    "jenkinsfile": "jenkins",
    "azure-pipelines.yml": "azure-pipelines",
    "bitbucket-pipelines.yml": "bitbucket-pipelines",
    ".travis.yml": "travis",
}
_SCANNER_CONFIGS = {
    "trivy.yaml": "trivy",
    "trivy.yml": "trivy",
    ".trivyignore": "trivy",
    ".semgrep.yml": "semgrep",
    ".semgrep.yaml": "semgrep",
    ".semgrepignore": "semgrep",
    ".checkov.yml": "checkov",
    ".checkov.yaml": "checkov",
    ".gitleaks.toml": "gitleaks",
    ".tflint.hcl": "tflint",
    ".snyk": "snyk",
    ".bandit": "bandit",
    ".hadolint.yaml": "hadolint",
    ".hadolint.yml": "hadolint",
    ".grype.yaml": "grype",
    "zizmor.yml": "zizmor",
    "dependabot.yml": "dependabot",
    "renovate.json": "renovate",
}
# Token found in CI files -> scanner reported.
_SCANNER_TOKENS = {
    "semgrep": "semgrep",
    "trivy": "trivy",
    "checkov": "checkov",
    "gitleaks": "gitleaks",
    "trufflehog": "trufflehog",
    "codeql": "codeql",
    "snyk": "snyk",
    "bandit": "bandit",
    "tfsec": "tfsec",
    "kics": "kics",
    "grype": "grype",
    "zizmor": "zizmor",
    "hadolint": "hadolint",
    "osv-scanner": "osv-scanner",
    "prowler": "prowler",
    "tflint": "tflint",
    "pip-audit": "pip-audit",
    "dependency-review-action": "dependency-review",
    "scorecard-action": "scorecard",
}
_SCANNER_PATTERN = re.compile(
    r"(?<![a-z0-9-])("
    + "|".join(re.escape(t) for t in sorted(_SCANNER_TOKENS, key=len, reverse=True))
    + r")(?![a-z0-9])"
)
_COMPOSE_NAME = re.compile(r"^(docker-)?compose(\.[\w.-]+)?\.ya?ml$")
_THREAT_MODEL_NAMES = {"threat-model.md", "threat_model.md", "threatmodel.md"}

_USES_LINE = re.compile(
    r"""^[ \t]*(?:-[ \t]*)?(?:\{(?:[^}]*?[, \t])?)?uses:[ \t]*["']?([^\s"'#,}]+)"""
)
_SHA = re.compile(r"[0-9a-fA-F]{40}")
_FROM_LINE = re.compile(r"^\s*FROM\s+(.*)$", re.IGNORECASE)
_MODULE_START = re.compile(r'^\s*module\s+"[^"]*"\s*\{')
_MODULE_SOURCE = re.compile(r'\bsource\s*=\s*"([^"]*)"')
_MODULE_VERSION = re.compile(r"\bversion\s*=")
_GIT_REF_SHA = re.compile(r"[?&]ref=[0-9a-fA-F]{40}(?:&|$)")
_REGISTRY_SOURCE = re.compile(r"^(?:[\w.-]+/)?[\w-]+/[\w-]+/[\w-]+(?://\S*)?$")
_REQUIRED_PROVIDER = re.compile(
    r'(?<![\w-])([\w-]+)\s*=\s*\{[^{}]*?\bsource\s*=\s*"([^"]+)"', re.DOTALL
)
_PROVIDER_BLOCK = re.compile(r'^[ \t]*provider[ \t]+"([\w-]+)"', re.MULTILINE)
_RESOURCE_BLOCK = re.compile(r'^[ \t]*(resource|data)[ \t]+"([\w-]+)"', re.MULTILINE)
_PROVIDER_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
_REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9@][A-Za-z0-9._/@-]*)")
_K8S_API = re.compile(r"^apiVersion:[ \t]*\S", re.MULTILINE)
_K8S_KIND = re.compile(r"^kind:[ \t]*\S", re.MULTILINE)
_HEADING = re.compile(r"^##(?!#)(.*)$")
_PROVIDER_SOURCE = re.compile(r"(?:[\w.-]+/)?[\w-]+/([\w-]+)")
_WORKFLOW_ITEM_BUDGET = 10_000
_HAS_FWALK = hasattr(os, "fwalk")
"""`os.fwalk` is POSIX-only; elsewhere the scan falls back to `os.walk`."""


class PathOutsideProjectError(ValueError):
    """The requested path is not the server's working directory or inside it."""


class ProjectPathNotFoundError(FileNotFoundError):
    """The requested path does not exist or is not a folder."""


@dataclass
class ProjectContext:
    """What a project scan found. Every string in it is repository data."""

    languages: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    iac: dict[str, list[str]] = field(
        default_factory=lambda: {
            "terraform_providers": [],
            "kubernetes": [],
            "helm": [],
            "dockerfiles": [],
            "compose": [],
        }
    )
    ci: list[str] = field(default_factory=list)
    ci_scanners: list[str] = field(default_factory=list)
    suggested_components: list[str] = field(default_factory=list)
    flags: list[dict[str, Any]] = field(default_factory=list)
    existing_threat_model: dict[str, Any] | None = None
    sensitive_files_present: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return the context as plain JSON-ready data."""
        return asdict(self)


def resolve_project_path(path: str, cwd: Path) -> Path:
    """Resolve `path` and check it is `cwd` or a folder inside it.

    Relative paths are taken from `cwd`. Symlinks are resolved before the
    check, so a link inside the project that points outside is refused.

    Args:
        path: Relative or absolute folder; empty means `cwd`.
        cwd: The server's working directory.

    Returns:
        The resolved folder.

    Raises:
        PathOutsideProjectError: If the path, written or resolved, leaves `cwd`.
        ProjectPathNotFoundError: If nothing exists there or it is not a folder.
    """
    base = cwd.resolve(strict=True)
    bases = (base, Path(os.path.normpath(cwd.absolute())))
    raw = Path(path) if path else Path()
    candidate = raw if raw.is_absolute() else base / raw
    lexical = Path(os.path.normpath(candidate))
    if not any(lexical.is_relative_to(b) for b in bases):
        raise PathOutsideProjectError("path is outside the working directory")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as e:
        raise ProjectPathNotFoundError("path does not exist") from e
    if not resolved.is_relative_to(base):
        raise PathOutsideProjectError("path resolves outside the working directory")
    if not resolved.is_dir():
        raise ProjectPathNotFoundError("path is not a folder")
    return resolved


def scan_project(
    root: Path, *, known_components: Collection[str] | None = None
) -> ProjectContext:
    """Scan a project folder without following symlinks or reading secrets.

    Args:
        root: The folder to scan, already checked with `resolve_project_path`.
        known_components: Component ids in the loaded library; suggestions are
            limited to these. Defaults to the built-in library.

    Returns:
        The detected stack, IaC, CI, flags, and suggested components.
    """
    if known_components is None:
        known_components = set(builtin_library().components)
    return _Scanner(root, set(known_components)).run()


def _lstat_is(name: str, dir_fd: int | None, kind: Callable[[int], bool]) -> bool:
    """Whether `name` is of `kind` without following a symlink.

    `name` is relative to `dir_fd`, or a full path when `dir_fd` is None.
    """
    try:
        return kind(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _clip(text: str) -> str:
    return untrusted(text, LINE_LIMIT)


def _is_sensitive(lower_name: str) -> bool:
    return any(fnmatch.fnmatchcase(lower_name, p) for p in SENSITIVE_PATTERNS)


def _lines(text: str) -> list[str]:
    """Split on newlines only, so line numbers match what editors show."""
    return [line.rstrip("\r") for line in text.split("\n")]


def _action_pinned(ref: str) -> bool:
    """Whether a workflow `uses:` value is local or pinned to a full SHA/digest."""
    if ref.startswith("./"):
        return True
    if ref.startswith("docker://"):
        return "@sha256:" in ref
    _, sep, version = ref.rpartition("@")
    return bool(sep) and _SHA.fullmatch(version) is not None


def _module_unpinned(source: str, *, has_version: bool) -> bool:
    """Whether a Terraform module source is remote and not pinned."""
    if source.startswith(("./", "../")):
        return False
    is_git = (
        source.startswith(("git::", "git@", "github.com/", "bitbucket.org/"))
        or ".git?" in source
        or source.endswith(".git")
    )
    if is_git:
        return _GIT_REF_SHA.search(source) is None
    if "::" not in source and _REGISTRY_SOURCE.match(source):
        return not has_version
    return False


def _workflow_uses(doc: object) -> set[str]:
    """Collect `jobs.*.uses` and `jobs.*.steps[*].uses` from a parsed workflow.

    YAML aliases can repeat one list many times, so each object is visited
    once and the number of items looked at is capped.
    """
    found: set[str] = set()
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return found
    seen: set[int] = set()
    budget = _WORKFLOW_ITEM_BUDGET
    for job in doc["jobs"].values():
        budget -= 1
        if budget <= 0:
            break
        if not isinstance(job, dict) or id(job) in seen:
            continue
        seen.add(id(job))
        if isinstance(job.get("uses"), str):
            found.add(job["uses"])
        steps = job.get("steps")
        if not isinstance(steps, list) or id(steps) in seen:
            continue
        seen.add(id(steps))
        for step in steps[:budget]:
            budget -= 1
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                found.add(step["uses"])
    return found


def _python_requirements(name: str, text: str) -> list[str]:
    """Dependency names from pyproject.toml, Pipfile, or requirements files."""
    if name.endswith(".txt"):
        specs = [
            line
            for line in _lines(text)
            if line.strip() and not line.lstrip().startswith(("#", "-"))
        ]
    else:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return re.findall(r'"([A-Za-z0-9][A-Za-z0-9._-]*)', text)
        specs = []
        project = data.get("project")
        if isinstance(project, dict):
            specs += _str_list(project.get("dependencies"))
            for group in _dict(project.get("optional-dependencies")).values():
                specs += _str_list(group)
        for group in _dict(data.get("dependency-groups")).values():
            specs += _str_list(group)
        poetry = _dict(_dict(data.get("tool")).get("poetry"))
        specs += list(_dict(poetry.get("dependencies")))
        for group in _dict(poetry.get("group")).values():
            specs += list(_dict(_dict(group).get("dependencies")))
        specs += list(_dict(data.get("packages")))
        specs += list(_dict(data.get("dev-packages")))
    names = []
    for spec in specs:
        m = _REQUIREMENT_NAME.match(spec)
        if m:
            names.append(m.group(1))
    return names


def _node_requirements(text: str) -> list[str]:
    """Dependency names from package.json."""
    try:
        data = json.loads(text)
    except ValueError:
        return re.findall(r'"([@a-z0-9][@a-z0-9/._-]*)"\s*:', text)
    names: list[str] = []
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        names += [n for n in _dict(_dict(data).get(key)) if isinstance(n, str)]
    return names


def _dict(value: object) -> dict[Any, Any]:
    return value if isinstance(value, dict) else {}


def _str_list(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


class _Scanner:
    """One scan's state: what was found and how much was read."""

    def __init__(self, root: Path, known: set[str]) -> None:
        self.root = root
        self.known = known
        self.ctx = ProjectContext()
        self.files_seen = 0
        self.bytes_read = 0
        self.languages: set[str] = set()
        self.package_managers: set[str] = set()
        self.frameworks: set[str] = set()
        self.providers: set[str] = set()
        self.ci: set[str] = set()
        self.scanners: set[str] = set()
        self.terraform = False
        self.storage = False
        self.data_store = False
        self.threat_model_key: tuple[int, str] | None = None
        self.dir_fd: int | None = None
        self.current_dir = root

    def run(self) -> ProjectContext:
        self._walk()
        ctx = self.ctx
        ctx.languages = sorted(self.languages)
        ctx.package_managers = sorted(self.package_managers)
        ctx.frameworks = sorted(self.frameworks)
        ctx.iac["terraform_providers"] = sorted(self.providers)
        ctx.ci = sorted(self.ci)
        ctx.ci_scanners = sorted(self.scanners)
        ctx.sensitive_files_present.sort()
        ctx.suggested_components = self._suggest()
        return ctx

    # ---- walking and reading ----

    def _walk(self) -> None:
        if _HAS_FWALK:
            self._fwalk()
        else:
            self._walk_portable()

    def _fwalk(self) -> None:
        """Walk with directory file descriptors so nothing can be swapped in.

        `os.fwalk` never descends into a symlinked directory, and every entry
        is checked with `lstat` relative to its open parent, so a symlink
        created during the scan is skipped rather than followed.
        """
        walker = os.fwalk(self.root, follow_symlinks=False)
        try:
            for dirpath, dirnames, filenames, dir_fd in walker:
                rel_dir = Path(dirpath).relative_to(self.root)
                dirnames[:] = sorted(
                    d
                    for d in dirnames
                    if d not in SKIP_DIRS and _lstat_is(d, dir_fd, stat.S_ISDIR)
                )
                self.dir_fd = dir_fd
                regular = [n for n in filenames if _lstat_is(n, dir_fd, stat.S_ISREG)]
                if not self._visit_files(rel_dir, regular):
                    return
        finally:
            # A generator: closing it releases the directory descriptors now
            # rather than when it is collected (typeshed types it Iterator).
            close = getattr(walker, "close", None)
            if callable(close):
                close()

    def _walk_portable(self) -> None:
        """Walk with `os.walk` where `os.fwalk` does not exist (Windows).

        Symlinked directories and files are skipped by `lstat` before use, and
        files are opened with `O_NOFOLLOW` where the platform has it.
        """
        self.dir_fd = None
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in SKIP_DIRS
                and _lstat_is(str(current / d), None, stat.S_ISDIR)
            )
            self.current_dir = current
            regular = [
                n for n in filenames if _lstat_is(str(current / n), None, stat.S_ISREG)
            ]
            if not self._visit_files(current.relative_to(self.root), regular):
                return

    def _visit_files(self, rel_dir: Path, names: list[str]) -> bool:
        """Visit regular files in one directory; False once MAX_FILES is hit."""
        for name in sorted(names):
            if self.files_seen >= MAX_FILES:
                self.ctx.truncated = True
                return False
            self.files_seen += 1
            self._visit(name, (rel_dir / name).as_posix())
        return True

    def _read(self, name: str) -> tuple[str, bool] | None:
        """Read a regular file in the current directory, within the caps.

        With `os.fwalk` the file is opened relative to the walked directory's
        descriptor, and with `O_NOFOLLOW` wherever it exists, so a symlink
        swapped in after the walk listed it fails to open.

        Returns:
            The text and whether all of it was read, or None if unreadable.
        """
        remaining = MAX_TOTAL_BYTES - self.bytes_read
        if remaining <= 0:
            self.ctx.truncated = True
            return None
        limit = min(MAX_FILE_BYTES, remaining)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_BINARY", 0)
        )
        target = name if self.dir_fd is not None else str(self.current_dir / name)
        try:
            fd = os.open(target, flags, dir_fd=self.dir_fd)
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            chunks: list[bytes] = []
            size = 0
            while size <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
        except OSError:
            return None
        finally:
            os.close(fd)
        data = b"".join(chunks)
        complete = len(data) <= limit
        if not complete:
            self.ctx.truncated = True
            data = data[:limit]
        self.bytes_read += len(data)
        return data.decode("utf-8", errors="replace"), complete

    def _list(self, target: list[str], rel: str) -> None:
        if len(target) >= MAX_LISTED:
            self.ctx.truncated = True
            return
        target.append(_clip(rel))

    def _flag(self, kind: str, rel: str, line: int, ref: str) -> None:
        if len(self.ctx.flags) >= MAX_FLAGS:
            self.ctx.truncated = True
            return
        self.ctx.flags.append(
            {
                "kind": kind,
                "file": _clip(rel),
                "line": line,
                "ref": _clip(ref),
                "fix_with": FIX_WITH,
            }
        )

    # ---- classification ----

    def _visit(self, name: str, rel: str) -> None:
        lower = name.lower()
        if _is_sensitive(lower):
            self._list(self.ctx.sensitive_files_present, rel)
            return
        language = _LANGUAGE_BY_SUFFIX.get(Path(lower).suffix)
        if language:
            self.languages.add(language)
        manifest = _MANIFESTS.get(lower)
        if manifest:
            self.package_managers.add(manifest[0])
            self.languages.add(manifest[1])
        if lower.startswith("requirements") and lower.endswith(".txt"):
            self.package_managers.add("pip")
            self.languages.add("python")
        parts = rel.lower().split("/")

        if lower in ("pyproject.toml", "pipfile") or (
            lower.startswith("requirements") and lower.endswith(".txt")
        ):
            self._dependencies(name, lambda text: _python_requirements(lower, text))
        elif lower == "package.json":
            self._dependencies(name, _node_requirements)
        elif lower.endswith(".tf"):
            self._terraform(name, rel)
        elif (
            lower in ("dockerfile", "containerfile")
            or lower.startswith("dockerfile.")
            or lower.endswith(".dockerfile")
        ):
            self._list(self.ctx.iac["dockerfiles"], rel)
            self._dockerfile(name, rel)
        elif parts[-3:-1] == [".github", "workflows"] and lower.endswith(
            (".yml", ".yaml")
        ):
            self.ci.add("github-actions")
            self._workflow(name, rel)
        elif lower in _CI_FILES or parts[-2:] == [".circleci", "config.yml"]:
            self.ci.add(_CI_FILES.get(lower, "circleci"))
            self._scanner_tokens(name)
        elif lower == ".pre-commit-config.yaml":
            self._scanner_tokens(name)
        elif _COMPOSE_NAME.match(lower):
            self._list(self.ctx.iac["compose"], rel)
        elif lower == "chart.yaml":
            self._list(self.ctx.iac["helm"], rel)
        elif lower in _THREAT_MODEL_NAMES:
            self._threat_model(name, rel, len(parts))
        elif lower.endswith((".yaml", ".yml")) and not lower.endswith("lock.yaml"):
            self._maybe_kubernetes(name, rel)

        if lower in _SCANNER_CONFIGS:
            self.scanners.add(_SCANNER_CONFIGS[lower])
        elif ".semgrep" in parts[:-1]:
            self.scanners.add("semgrep")

    def _dependencies(self, name: str, parse: Callable[[str], list[str]]) -> None:
        read = self._read(name)
        if read is None:
            return
        for dep in parse(read[0]):
            framework = _FRAMEWORKS.get(dep.lower().replace("_", "-"))
            if framework:
                self.frameworks.add(framework)

    def _terraform(self, name: str, rel: str) -> None:
        self.terraform = True
        read = self._read(name)
        if read is None:
            return
        text = read[0]
        names = [
            m.group(1)
            for _, src in _REQUIRED_PROVIDER.findall(text)
            if (m := _PROVIDER_SOURCE.fullmatch(src))
        ]
        names += _PROVIDER_BLOCK.findall(text)
        for _, resource in _RESOURCE_BLOCK.findall(text):
            names.append(resource.split("_", 1)[0])
            if _STORAGE_RESOURCE.match(resource):
                self.storage = True
            if _DATA_STORE_RESOURCE.match(resource):
                self.data_store = True
        for provider in names:
            provider = provider.lower()
            if provider != "terraform" and _PROVIDER_NAME.fullmatch(provider):
                self.providers.add(provider)
        self._modules(text, rel)

    def _modules(self, text: str, rel: str) -> None:
        depth = 0
        source: tuple[int, str] | None = None
        has_version = False
        for number, line in enumerate(_lines(text), start=1):
            if depth == 0:
                if not _MODULE_START.match(line):
                    continue
                source, has_version = None, False
            m = _MODULE_SOURCE.search(line)
            if m and source is None:
                source = (number, m.group(1))
            if _MODULE_VERSION.search(line):
                has_version = True
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                depth = 0
                if source and _module_unpinned(source[1], has_version=has_version):
                    self._flag("unpinned_module", rel, source[0], source[1])

    def _dockerfile(self, name: str, rel: str) -> None:
        read = self._read(name)
        if read is None:
            return
        stages: set[str] = set()
        for number, line in enumerate(_lines(read[0]), start=1):
            m = _FROM_LINE.match(line)
            if not m:
                continue
            tokens = [t for t in m.group(1).split() if not t.startswith("--")]
            if not tokens:
                continue
            image = tokens[0]
            pinned = (
                image.lower() == "scratch"
                or image.lower() in stages
                or "@sha256:" in image
                or image.startswith("$")
            )
            if not pinned:
                self._flag("mutable_image", rel, number, image)
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                stages.add(tokens[2].lower())

    def _workflow(self, name: str, rel: str) -> None:
        read = self._read(name)
        if read is None:
            return
        text, complete = read
        self._tokens(text)
        allowed: set[str] | None = None
        if complete:
            try:
                allowed = _workflow_uses(yaml.safe_load(text))
            except (yaml.YAMLError, RecursionError, ValueError):
                allowed = None
        for number, line in enumerate(_lines(text), start=1):
            m = _USES_LINE.match(line)
            if not m:
                continue
            ref = m.group(1)
            if allowed is not None and ref not in allowed:
                continue
            if not _action_pinned(ref):
                self._flag("unpinned_action", rel, number, ref)

    def _scanner_tokens(self, name: str) -> None:
        read = self._read(name)
        if read is not None:
            self._tokens(read[0])

    def _tokens(self, text: str) -> None:
        for token in _SCANNER_PATTERN.findall(text.lower()):
            self.scanners.add(_SCANNER_TOKENS[token])

    def _maybe_kubernetes(self, name: str, rel: str) -> None:
        read = self._read(name)
        if read is None:
            return
        if _K8S_API.search(read[0]) and _K8S_KIND.search(read[0]):
            self._list(self.ctx.iac["kubernetes"], rel)

    def _threat_model(self, name: str, rel: str, depth: int) -> None:
        """Keep the headings of the shallowest threat model (then by name)."""
        key = (depth, rel)
        if self.threat_model_key is not None and key >= self.threat_model_key:
            return
        read = self._read(name)
        if read is None:
            return
        self.threat_model_key = key
        headings: list[str] = []
        for line in _lines(read[0]):
            m = _HEADING.match(line)
            heading = m.group(1).strip(" \t#") if m else ""
            if not heading:
                continue
            if len(headings) >= MAX_HEADINGS:
                self.ctx.truncated = True
                break
            headings.append(_clip(heading))
        self.ctx.existing_threat_model = {"path": _clip(rel), "headings": headings}

    # ---- suggestions ----

    def _suggest(self) -> list[str]:
        ids: list[str] = []
        if self.frameworks & _WEB_FRAMEWORKS:
            ids.append("web-endpoint")
        if self.frameworks & _DB_LIBRARIES:
            ids.append("database")
        if self.providers & _CLOUD_PROVIDERS:
            ids += ["cloud-compute", "cloud-network", "cloud-iam"]
            if self.storage:
                ids.append("cloud-storage")
            if self.data_store:
                ids.append("cloud-data-store")
        if self.terraform:
            ids.append("cloud-encryption-and-logging")
        if self.ctx.iac["dockerfiles"]:
            ids.append("container-image")
        if self.ctx.iac["kubernetes"] or self.ctx.iac["helm"]:
            ids.append("kubernetes")
        if self.ci:
            ids.append("ci-pipeline")
        return [i for i in ids if i in self.known]
