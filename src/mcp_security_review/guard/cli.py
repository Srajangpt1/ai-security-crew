"""The `asc-guard` command: hook, check and install."""

import json
import shutil
import sys
from pathlib import Path

import click

from mcp_security_review.guard.install import UVX_PREFIX, build_hooks, install

_HOOK_EVENTS = ("pre-tool-use", "post-tool-use", "user-prompt")


@click.group()
def main() -> None:
    """Runtime guard for coding agents."""


@main.command()
@click.argument("event", type=click.Choice(_HOOK_EVENTS))
def hook(event: str) -> None:
    """Handle one client hook call (JSON on stdin). Fails open on errors."""
    from mcp_security_review.guard import claude_code
    from mcp_security_review.guard.engine import handle, is_enabled

    if not is_enabled():
        return
    try:
        parsed = claude_code.parse(json.load(sys.stdin))
        output = claude_code.render(parsed, handle(parsed))
    except (ValueError, OSError) as e:
        click.echo(f"asc-guard: skipped ({e})", err=True)
        return
    if output:
        click.echo(json.dumps(output))


@main.command()
@click.argument("tool")
@click.argument("tool_input")
@click.option("--cwd", default=".", show_default=True)
def check(tool: str, tool_input: str, cwd: str) -> None:
    """Judge one tool call. Exit code: 0 allow, 1 ask, 2 deny."""
    from mcp_security_review.guard.engine import handle
    from mcp_security_review.guard.events import Event

    try:
        data = json.loads(tool_input)
    except ValueError as e:
        raise click.BadParameter(f"not valid JSON: {e}") from e
    event = Event("pre", "check", cwd, tool, data if isinstance(data, dict) else {})
    decision = handle(event)
    click.echo(json.dumps({"action": decision.action, "reason": decision.reason}))
    sys.exit(decision.exit_code)


@main.command("install")
@click.option("--scope", type=click.Choice(["project", "user"]), default="project")
@click.option("--print", "print_only", is_flag=True, help="Show the hooks only.")
def install_cmd(scope: str, print_only: bool) -> None:
    """Add the guard's hooks to Claude Code's settings."""
    prefix = "asc-guard" if shutil.which("asc-guard") else UVX_PREFIX
    if print_only:
        click.echo(json.dumps({"hooks": build_hooks(prefix)}, indent=2))
        return
    base = Path.home() if scope == "user" else Path.cwd()
    path = base / ".claude" / "settings.json"
    try:
        changed = install(path, prefix)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"{'Updated' if changed else 'Already up to date:'} {path}")
