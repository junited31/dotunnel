# Changelog

## 0.1.2

- When Bubblewrap is missing and the setup account can use sudo (passwordless `sudo -n true`, or membership in `sudo`/`wheel`/`admin`), setup offers to install it with the distribution's command and `[Y/n]` (Enter approves). The command runs on the same terminal so sudo can ask for a password, then setup re-probes and continues. Without sudo, or after a declined or failed install, setup shows the command for an administrator. An installed but unusable bwrap is never reinstalled.
- Install commands are now non-interactive (`apt-get install -y`, `dnf install -y`, `pacman --noconfirm`, `zypper --non-interactive`, `apk add`), since setup already asked for approval.
- Documentation recommends installing from an administrator account and keeping the runtime account without sudo, because tasks and CLI jobs inherit its permissions.

## 0.1.1

- setup always checks Bubblewrap right after the configuration doctor, before any CLI prompts. The check runs a short isolated probe with the same namespace flags as CLI jobs, so an installed but blocked bwrap is reported as unusable rather than ready.
- When Bubblewrap is missing, setup and doctor show the distribution's install command (apt/dnf/pacman/zypper/apk) for an administrator to run with sudo; dotunnel never runs sudo. With CLIs installed, setup waits: Enter re-checks and continues to the selection in the same run, `s` skips and keeps the base setup.
- Bubblewrap remains required only for optional Codex/Claude Code/OMP integrations; the Tunnel, file tools and fixed tasks do not need it.

## 0.1.0 — first public candidate

- Single name `dotunnel` for the distribution, import package and command. The stdio MCP server runs as `dotunnel serve --config PATH`; `cli-job` and `claude-token` are `dotunnel` subcommands; `python -m dotunnel` is the same entry point.
- MIT license. README in English (`README.md`) and Korean (`README.ko.md`).
- Scoped stdio MCP server with seven tools: bounded file list/read/search, hash-guarded write, and administrator-defined fixed tasks started asynchronously (`run_task` returns a result ID; `get_task_result` polls).
- `dotunnel` operator command: `help`, `setup`, `update`, `doctor`. Bare `dotunnel` points to `dotunnel help` and exits 2.
- `dotunnel setup` creates a private Secure MCP Tunnel configuration (hidden key entry, 0700/0600 files, official client doctor, optional foreground start) and can enable installed Codex, Claude Code and OMP integrations from a selection list (Up/Down, Space, Enter, Esc/Ctrl-C).
- Optional isolated native CLI jobs (`cli-job`) run reviews or candidate edits inside mandatory bubblewrap isolation, publish SHA-256-addressed reports and never write the source originals.
- `dotunnel doctor` is read-only: validates configuration and CLI integration metadata and reports readiness only when observed on the local health endpoint.
- `dotunnel update` checks the latest stable GitHub release and asks `[Y/n]` before installing a size-, SHA-256- and metadata-verified wheel into the current non-root, non-editable virtualenv. It never restarts services or changes configuration/credentials.
