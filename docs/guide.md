# Installation and operations guide

<p align="center"><img src="../assets/dotunnel.png" alt="dotunnel: a hollow cylinder forming a tunnel" width="640"></p>

[English front page](../README.md) · [한국어](guide.ko.md) · [Design](../DESIGN.md) · [Example config](../config.example.json) · [Logo asset](../assets/dotunnel.png) · [License](../LICENSE)

This guide covers installation, private Tunnel setup, workspace tools and optional native CLI jobs. `dotunnel` is a local stdio MCP server; it is not a hosted service, a public HTTP endpoint or a sandbox for arbitrary code.

## 1. Installation

Use a non-root Linux account with Python 3.11 or later, `python3` with `venv` and `pip`, `curl`, `sha256sum`, and network access to download the wheel and dependencies. `uv` is not required. Dependencies are installed from binary wheels into an isolated venv.

### Public installer

The front-page one-line command downloads `install.sh` from the public repository's `main` branch without GitHub authentication and runs it as your current user. `curl | sh` executes that script; read and trust the script itself. The installer verifies the pinned wheel before pip installs it, but that wheel checksum does not authenticate the shell script. The installer only installs the package: it does not run interactive setup from piped stdin.

The public installer uses `$HOME/.local/share/dotunnel/venv` and exposes `$HOME/.local/bin/dotunnel`. It refuses to overwrite an existing install path or unrelated launcher. It does not use sudo, change accounts or permissions, edit shell startup files, start services, install the official Tunnel client, create keys or modify Tunnel settings. If the launcher is not found, add `$HOME/.local/bin` to `PATH` yourself or invoke it by absolute path; no shell startup file is edited.

### Manual installation

To avoid executing a downloaded shell script, download the v0.1.3 release wheel directly. GitHub authentication and `gh` are not required. Check both the expected byte count and SHA-256 **before** installing:

```sh
set -eu
umask 077
install="$HOME/.local/share/dotunnel/venv"
if [ -e "$install" ] || [ -L "$install" ]; then
  printf '%s\n' "Install path already exists; use dotunnel update instead." >&2
  exit 1
fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
wheel="$tmp/dotunnel-0.1.3-py3-none-any.whl"
curl --fail --location --output "$wheel" \
  https://github.com/junited31/dotunnel/releases/download/v0.1.3/dotunnel-0.1.3-py3-none-any.whl
test "$(wc -c < "$wheel")" -eq 90633
printf '%s  %s\n' \
  fbb6fd8d2ebea7368fe86e5096fe40c1830d829065c81ca3e7ed49e552eb9912 \
  "$wheel" | sha256sum --check -
python3 -I -m venv "$install"
"$install/bin/python" -I -m pip --isolated install --only-binary :all: "$wheel"
"$install/bin/dotunnel" help
```

Stop if the size or checksum check fails. This manual route invokes `$HOME/.local/share/dotunnel/venv/bin/dotunnel` directly; it does not create the one-line installer's `$HOME/.local/bin/dotunnel` launcher. Do not replace an existing install path; use `dotunnel update` from that installation.

For this manual wheel route, start setup with the venv's absolute launcher:

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

## 2. Runtime account and private paths

The process gets the Linux account's filesystem and task permissions. A dedicated non-root account without sudo or broad groups is recommended; check an existing account's groups before using it. `dotunnel` does not create accounts, change groups, add sudoers rules or recursively change ownership. A separate account reduces exposure but is not a complete sandbox.

Keep the installed program, trusted configuration/credentials and writable workspace in separate locations. Do not put the configuration or keys in the workspace or source control. Setup creates a private workspace and starts with no tasks (`tasks: []`). The MCP server has no separate user authentication, so restrict who can reach the local stdio process and Tunnel.

## 3. Set up a private Secure MCP Tunnel

Before running setup, separately install the official [tunnel-client](https://github.com/openai/tunnel-client/releases/latest) for your OS/architecture and verify its official checksum. You also need ChatGPT developer-MCP eligibility and the right account/workspace, [Platform Tunnel settings](https://platform.openai.com/settings/organization/tunnels) permissions, and a Tunnel ID. Creating or editing a Tunnel requires Tunnels **Read+Manage**; using the app requires **Read+Use**. Create a **Restricted** runtime API key with Tunnels Read+Use in [Platform API keys](https://platform.openai.com/settings/organization/api-keys), never an Admin key. `dotunnel` cannot grant these permissions, sign in to Platform, create a Tunnel, issue a key or download the official client.

Run setup in a real interactive terminal:

```sh
"$HOME/.local/share/dotunnel/venv/bin/dotunnel" setup --directory "$HOME/.dotunnel-setup"
```

Use a new directory for a new Tunnel or key. Setup asks for the Tunnel ID and accepts the existing runtime key through hidden terminal input; it does not put the key in argv, the profile or the workspace. It creates private configuration, profile and key files (directories mode 0700, files mode 0600) and a separate workspace. Keep custom paths out of version control too. The setup directory and parents of client/CLI executables and auth references must have trusted ownership and must not be writable by untrusted users; symlinks and unsafe parents are refused.

Setup checks the official client's configuration doctor, then offers an optional foreground connection only after explicit confirmation. A successful configuration doctor is not remote authentication. If started, setup waits up to 45 seconds for live/ready health and a successful control-plane poll; if authenticated readiness is not reached, it stops only the client it started. Otherwise it reports not connected. It may then guide you through [registering the app in ChatGPT](https://chatgpt.com/plugins) with the same Tunnel ID. Never enter the runtime key in ChatGPT; select the Tunnel connection and provide the Tunnel ID. Keep setup interactive. Cancelling or failing can leave private files in place, so retry with a new directory. Setup creates no service or autostart.

Re-running setup with an existing directory only configures optional CLI integrations; it does not read or overwrite the key or profile. To configure a new Tunnel/key, use a new directory. Only one active stdio client is supported per Tunnel ID.

### Existing profile migration

Package updates do not rewrite profiles made by v0.1.0–v0.1.2. Before starting one with v0.1.3, edit the trusted `profile.yaml` command in `mcp.commands[].command`: insert `-I` between the absolute Python interpreter and `-m dotunnel`. Keep the interpreter, config path, Tunnel ID and key reference unchanged. New setups already generate the isolated command.

## 4. Diagnose, update and disconnect

- **`dotunnel doctor`** is read-only: it starts no client or model and changes no settings. It checks setup/configuration, the selected client and optional Bubblewrap status. Valid config or auth-file metadata alone is not proof of provider authentication. Unless live/ready and a successful control-plane poll are observed, doctor exits 2. Use `--directory DIR` and, if needed, `--tunnel-client /absolute/path` to select paths.
- **`dotunnel update`** checks the latest stable GitHub release and asks before installing. It is limited to non-root Linux, non-editable venv installations; it does not downgrade a newer version. The release wheel name, size, GitHub-reported SHA-256 and package name/version are checked before binary-only installation. Update uses GitHub CLI (`gh`); install it and authenticate with `gh auth login`. Lookup failure, a missing release, EOF or non-interactive input fails closed (exit 2); Ctrl-C exits 130. A partial-install rollback is not guaranteed. Update changes no config, credentials or Tunnel settings and restarts no running process; restart idle MCP/client processes yourself. `gh` is not required for a fresh install.
- **Disconnecting** a foreground client with Ctrl-C stops that client but does not revoke access. Depending on your setup, fully removing access may require disconnecting/deleting the ChatGPT app, removing the Tunnel association and revoking the runtime key. Data already sent to ChatGPT is not recalled. The project creates no persistent service; manage any service you set up according to your own server policy.

## 5. Workspace, tasks and MCP tools

Setup creates the initial workspace and config. For manual configuration, start from [`config.example.json`](../config.example.json), keep the config outside the workspace, and set `root` to an existing absolute workspace path. The config must be a private regular file owned by the runtime account; symlinks, hardlinks and group/world write access are refused. The root cannot be `/`, the account's home, or overlap the program/config paths; ancestor symlinks and unknown/duplicate fields are rejected.

`tasks: []` grants no command execution. Each administrator-defined task has a name, a description, an absolute `argv[0]` outside the workspace, fixed arguments, a workspace-relative `cwd` and a timeout (60 seconds by default, at most 300 seconds). At most 50 tasks can be registered. Callers choose only a task name; they cannot change its arguments, environment, shell, working directory or timeout. Review the executable, code and side effects before registration: fixed tasks run with the full OS permissions of the MCP account, and a workspace is not an OS sandbox.

| Tool | Behavior and limits |
|---|---|
| `list_files(path=".")` | Immediate entries only; up to 200 results and 1,000 visited entries |
| `read_file(path)` | UTF-8 file content and SHA-256; up to 64 KiB |
| `search_files(query, path=".")` | Literal search; up to 100 matches, 1,000 entries and 4 MiB scanned |
| `write_file(path, content, expected_sha256=null)` | `null` creates only; replacing an existing file requires its current hash |
| `list_tasks()` | Names and descriptions of registered tasks |
| `run_task(name)` | Starts one fixed task and returns a result ID immediately |
| `get_task_result(result_id)` | Reads the current process's running/final result; at most 20 IDs are retained |

Paths are relative to `root`. Absolute paths, `..`, symlinks/hardlinks, special files, hidden paths and common credential/key names are refused or excluded. Parent directories must already exist; there are no delete, move, mkdir or chmod tools. Writes are hash-guarded against changes observed by this server but are not atomic with external editors and may be partial on an OS/I/O failure. One task runs at a time; output is capped at 16 KiB and excess is drained. Task stdin is closed and only a minimal environment is passed; this is not CPU, memory, disk or network isolation. Process-group cleanup does not guarantee termination of a child that escapes into a new session.

Call `run_task(name)` once, save its `result_id`, then poll `get_task_result(result_id)` at a bounded interval. Polling does not start work. Check `exit_code`, `output` and `truncated`; `completed` does not mean exit code zero. There is no partial output while running. IDs are in-memory, limited to 20 and invalidated on server restart; never blindly retry a task after losing its start response.

## 6. Optional native CLI jobs

CLI jobs are disabled unless an operator explicitly registers them. They add no MCP tools and setup registration alone does not run a model or prove provider login. The native Codex, Claude Code or OMP CLI and its provider access must be installed/configured separately. `dotunnel setup` detects safe launchers on `PATH` without running them. Optional jobs require non-root Linux and usable `/usr/bin/bwrap` (Bubblewrap); the core Tunnel, file tools and fixed tasks do not. Bubblewrap creates mount/PID namespaces, drops capabilities and exposes only an allowlisted candidate at `/workspace`, with a separate `/home/job`; setup checks that namespaces work, not just that the executable exists. If Bubblewrap is missing, setup may offer installation when sudo appears available; if installed but unusable, kernel/AppArmor policy must allow unprivileged namespaces (reinstalling will not fix it). On shared servers, prefer an administrator installing the system package while keeping the runtime account non-sudo. You may skip integrations and configure them later.

An operator-owned config fixes each backend's runtime, auth references, source root (separate from the MCP workspace), target aliases, file allowlist and editable subset outside the writable workspace. `review` is read-only; `edit` may change only existing allowlisted files. Jobs copy approved files into an isolated candidate, never apply changes to originals, run tests, commit/push or offer arbitrary shell. The task registry is updated as a whole; deselecting a backend removes only its setup-owned task. Auth references are read-only, but the native CLI runs as the same user and can read them. Provider networking is shared, so credentials are not hidden from the CLI and egress is not blocked. Do not allowlist secrets; selected source/instructions/results may reach ChatGPT through the provider.

Write only `{ "target": "alias", "mode": "review", "instruction": "..." }` to the configured request file, then call the registered `run_task` once and poll its result. `target` must be registered, `mode` is `review` or `edit`, and `instruction` is at most 8 KiB of UTF-8. Do not overwrite a running request. A target has at most 32 regular files, each at most 64 KiB. Set the MCP task timeout to cover the 200-second native limit plus cleanup (for example, 240 seconds). The native run captures at most 1 MiB. The result points to a report and SHA-256-addressed diff chunks (at most 48 KiB each); read and verify those artifacts. `candidate_ready` means only that a candidate was prepared, not that it was applied or correct; reports say `verification: not_run`.

- **Codex** requires a compatible native app-server installation with experimental `dynamicTools`/Code Mode and effective-feature queries, plus its `codex-code-mode-host` companion. Incompatible installations are refused; there is no `exec` or shell fallback.
- **Claude Code** requires a long-lived token from `claude setup-token`, not the normal `/login` credential. `dotunnel claude-token --output PATH` creates a new private token file interactively; existing files are not replaced unless `--replace` is requested. The token is passed to the isolated process as `CLAUDE_CODE_OAUTH_TOKEN`, not argv or a mount. The same-UID Claude process can read it, so revoke and replace a leaked token. Claude runs with `--safe-mode --restricted` and fixed file tools; host settings, hooks, plugins, skills, MCP servers and sessions are not mounted.
- **OMP** output is validated frame by frame; cumulative progress/tool bodies are not retained. A malformed or oversized frame, or an unfinished latest turn, fails rather than reusing an earlier completion.

Native execution failures return `status: failed`, `error_code: NATIVE_FAILED` and allowlisted `native_error_code` values (`SANDBOX_UNAVAILABLE`, `NATIVE_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_LIMIT`, `NATIVE_FAILURE`, `INVALID_NATIVE_STREAM`) plus fixed `native_detail` values (`AUTH_FAILED`, `RATE_LIMITED`, `PROVIDER_ERROR`, `PERMISSION_DENIED`, `UNSUCCESSFUL_RESULT`, `INVALID_RESULT`, `EMPTY_RESULT`, `SUMMARY_TOO_LARGE`, `NO_RESULT`, `INVALID_STREAM`, `EXIT_NONZERO`); raw CLI logs are not returned. Other failed jobs use `CANDIDATE_INVALID`, `SOURCE_CONFLICT`, `ARTIFACT_FAILURE` or `JOB_FAILED`; rejected inputs use `INVALID_REQUEST` or `INVALID_CONFIG` (exit 2; failed jobs exit 1). Do not interpret a safety rejection as a successful result or automatically retry it.

## 7. Development without publishing secrets

Keep the source checkout separate from private runtime configuration, keys and writable workspaces. `.gitignore` reduces accidental staging, but does not untrack existing files or prevent `git add -f`. Private repositories still need secret protection.

Install [Gitleaks](https://github.com/gitleaks/gitleaks/releases) (verified with 8.30.1), verify its release checksum, and put `gitleaks` on `PATH`. In each development checkout:

```sh
git config --get core.hooksPath
# If an existing hook path or .git/hooks/pre-commit is in use, integrate
# the guard with it instead of replacing that hook.
git config --local core.hooksPath .githooks
gitleaks git --log-opts=--all --redact=100 --no-banner
```

The executable `.githooks/pre-commit` scans staged changes only. A detected secret, missing scanner, scan timeout or scanner error rejects the commit. Logs redact detected secret values. An unstaged edit is not part of the commit and is not scanned by this hook.

Before pushing, review `git diff --cached` locally, verify that runtime/key files are absent, and run the history scan above on the source repository—not the runtime directory. Do not paste sensitive diffs or scan reports into public issues. Enable GitHub secret scanning and push protection on your repository where available. Neither detector catches every secret; hooks can be bypassed and provider push protection has pattern and bypass limitations. If a real secret is committed or pushed, revoke/rotate it first; deleting the latest file does not remove Git history.

For unpublished feature work, create a separate **private repository**, clone the public source and push to that private remote. A public GitHub fork remains public and cannot independently become private; see [GitHub fork visibility](https://docs.github.com/en/pull-requests/reference/forks). Keep public upstream as a fetch source; publish only reviewed code changes, never private runtime files or operational history. A separate private development repository is optional, not a runtime requirement.

## Further reading

- [Front page](../README.md) · [한국어 front page](../README.ko.md)
- [Design and runtime boundaries](../DESIGN.md)
- [Minimal example config](../config.example.json)
- [Logo asset](../assets/dotunnel.png) · [MIT License](../LICENSE)
- [OpenAI Secure MCP Tunnel documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
