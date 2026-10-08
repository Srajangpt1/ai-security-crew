"""I/O utility functions for AI Security Crew."""

from mcp_security_review.utils.env import is_env_extended_truthy


def is_read_only_mode() -> bool:
    """Check if the server is running in read-only mode.

    Read-only mode prevents all write operations (create, update, delete)
    while allowing all read operations. This is useful for working with
    environments where you want to prevent accidental
    file modifications.

    Returns:
        True if read-only mode is enabled, False otherwise
    """
    return is_env_extended_truthy("READ_ONLY_MODE", "false")
