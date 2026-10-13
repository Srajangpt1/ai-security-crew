"""Runtime guard for coding agents (`asc-guard`).

A client hook calls `asc-guard hook <event>` around each tool call. The guard
asks a decision model narrow questions about the call and answers allow, ask
or deny, so a prompt-injected agent is stopped while it runs.
"""
