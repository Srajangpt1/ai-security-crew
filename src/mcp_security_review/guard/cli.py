"""The `asc-guard` command: hook, check and install."""

import json
import sys
from pathlib import Path

import click

from mcp_security_review.guard.install import (
    CLIENTS,
    CONFIG_PATHS,
    hook_prefix,
    hooks_config,
    install,
)

_HOOK_EVENTS = ("pre-tool-use", "post-tool-use", "user-prompt")
_CLIENT = click.option(
    "--client",
    type=click.Choice(CLIENTS),
    default="claude-code",
    show_default=True,
    help="The coding agent whose hooks call or get installed.",
)


@click.group()
def main() -> None:
    """Runtime guard for coding agents."""


@main.command()
@_CLIENT
@click.argument("event", type=click.Choice(_HOOK_EVENTS))
def hook(client: str, event: str) -> None:
    """Handle one client hook call (JSON on stdin). Fails open on errors."""
    from mcp_security_review.guard import claude_code, cursor
    from mcp_security_review.guard.decision import Decision
    from mcp_security_review.guard.engine import handle, is_enabled

    enabled = is_enabled()
    if not enabled and client == "claude-code":
        return  # Claude Code takes no output as "carry on"
    adapter = cursor if client == "cursor" else claude_code
    try:
        # Bytes, not text: clients send UTF-8 whatever the console code page is.
        raw = json.loads(sys.stdin.buffer.read())
        if not isinstance(raw, dict):
            raise ValueError("hook input is not a JSON object")
        if client == "claude-code" and "cursor_version" in raw:
            # Cursor also runs Claude Code's hooks; its own hooks judge the call.
            return
        parsed = adapter.parse(raw)
        output = adapter.render(parsed, handle(parsed) if enabled else Decision())
    except Exception as e:  # noqa: BLE001 - a hook that crashes must still fail open
        click.echo(f"asc-guard: skipped ({type(e).__name__}: {e})", err=True)
        if client == "cursor":
            sys.exit(1)  # Cursor logs the failure and lets the action through
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
@_CLIENT
@click.option("--scope", type=click.Choice(["project", "user"]), default="project")
@click.option("--print", "print_only", is_flag=True, help="Show the hooks only.")
def install_cmd(client: str, scope: str, print_only: bool) -> None:
    """Add the guard's hooks to Claude Code's or Cursor's config."""
    prefix = hook_prefix()
    if print_only:
        click.echo(json.dumps(hooks_config(client, prefix), indent=2))
        return
    base = Path.home() if scope == "user" else Path.cwd()
    path = base / CONFIG_PATHS[client]
    try:
        changed = install(path, prefix, client)
    except ValueError as e:
        raise click.ClickException(f"{e}\nThe file was not changed.") from e
    except OSError as e:
        raise click.ClickException(
            f"Could not write {path}: {e}\nThe file was not changed."
        ) from e
    click.echo(f"{'Updated' if changed else 'Already up to date:'} {path}")
