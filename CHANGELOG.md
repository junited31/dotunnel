# Changelog

## 0.1.0 — first public candidate

- Single name `dotunnel` for the distribution, import package and command. The stdio MCP server runs as `dotunnel serve --config PATH`; `cli-job` and `claude-token` are `dotunnel` subcommands; `python -m dotunnel` is the same entry point.
- MIT license. README in English (`README.md`) and Korean (`README.ko.md`).
- Scoped stdio MCP server with seven tools: bounded file list/read/search, hash-guarded write, and administrator-defined fixed tasks started asynchronously (`run_task` returns a result ID; `get_task_result` polls).
- `dotunnel` operator command: `help`, `setup`, `update`, `doctor`. Bare `dotunnel` points to `dotunnel help` and exits 2.
- `dotunnel setup` creates a private Secure MCP Tunnel configuration (hidden key entry, 0700/0600 files, official client doctor, optional foreground start) and can enable installed Codex, Claude Code and OMP integrations from a selection list (Up/Down, Space, Enter, Esc/Ctrl-C).
- Optional isolated native CLI jobs (`cli-job`) run reviews or candidate edits inside mandatory bubblewrap isolation, publish SHA-256-addressed reports and never write the source originals.
- `dotunnel doctor` is read-only: validates configuration and CLI integration metadata and reports readiness only when observed on the local health endpoint.
- `dotunnel update` checks the latest stable GitHub release and asks `[Y/n]` before installing a size-, SHA-256- and metadata-verified wheel into the current non-root, non-editable virtualenv. It never restarts services or changes configuration/credentials.
