# Changelog

## Unreleased — installer and documentation

- Add a one-line Linux installer for the pinned 0.1.3 release. It verifies the wheel's size and SHA-256 before isolated, binary-only installation into a user-owned virtualenv, and refuses existing installations or unrelated launchers.
- Keep a completed virtualenv and its launcher together even if printing the final installation message fails.
- Shorten both READMEs to quickstarts and move detailed installation, account, Tunnel, task and CLI guidance into bilingual guides. Anonymous installation becomes available only after the repository is made public.
- The package version and existing 0.1.3 release wheel are unchanged; no credentials, connections or services are changed by installation.

## 0.1.3

- Harden Bubblewrap installation against inherited PATH substitution of sudo or package-manager commands. Administrative execution uses trusted absolute system executables.
- Require interactive terminal approval for existing setup too; redirected blank input must not authorize a system package install.
- Generate isolated `python -I -m dotunnel` MCP commands so a writable workspace cannot shadow the installed module. Existing 0.1.0–0.1.2 profiles need the documented `-I` addition before their next connection start; package updates do not modify profiles or restart connections.
- Cap saved Claude token values at 4095 ASCII characters, leaving room for the newline within the existing 4096-byte token-file limit.
- Move initial wheel checksum verification before installation, document non-native failure/rejection codes, and add the hollow-cylinder tunnel artwork to both READMEs.

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
