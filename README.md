# dotunnel

<p align="center"><img src="assets/dotunnel.png" alt="dotunnel: a hollow cylinder forming a tunnel" width="840"></p>

**English** | [한국어](README.ko.md)

A **self-hosted stdio MCP server** for Linux plus a helper for connecting it through a private Secure MCP Tunnel. ChatGPT can read and modify files in one designated working directory and run only the fixed tasks that the server administrator has defined. It needs no public HTTP listener and no terminal multiplexer such as tmux.

```text
Your ChatGPT → your Secure MCP Tunnel → tunnel-client on your server
                                        → stdio MCP → designated workspace / fixed tasks
```

Each user **installs it on their own server**. It is not a hosted service, a public MCP endpoint or a public ChatGPT plugin. Secure MCP Tunnel itself is [not intended for public plugin submission or distribution](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

| Part | Includes |
|---|---|
| Core | Tunnel connection helper (`dotunnel setup/doctor`) + file and fixed-task MCP server |
| Optional | Connect installed Codex, Claude Code or OMP as isolated fixed tasks |

## Requirements

- Linux, Python 3.11 or later, official MCP Python SDK 2.2.x (the package requires `mcp==2.2.0`).
- A non-administrator Linux account to run it. Running as root is refused.
- **Separate** locations for the installed program, trusted configuration and the writable workspace.
- PyPI access to install dependencies. For `uv`, see the [official installation guide](https://docs.astral.sh/uv/getting-started/installation/).
- GitHub CLI (`gh`), logged in, for `dotunnel update`.
- ChatGPT connection prerequisites, obtained separately: developer-mode eligibility, Platform Tunnel permissions, workspace association, a Tunnel ID, a runtime key and the official tunnel-client.
- Optional CLI integrations only: Bubblewrap (`/usr/bin/bwrap`) and an installed, logged-in Codex/Claude Code/OMP. setup checks Bubblewrap and, if this account can use sudo, offers to install it (`[Y/n]`); otherwise it shows the command for an administrator.

## 1. Choose the runtime account

The Tunnel is not an SSH/IAM login. File and task permissions are those of **the Linux account running the MCP process**. Check the account's groups and permissions with `id` before installing. The installer does not remove existing permissions.

### A. Dedicated `dotmcp` account (recommended)

The following are **instructions for an administrator to review, approve and run separately**. This project never creates accounts automatically.

```sh
getent passwd dotmcp
```

If the account already exists, do not overwrite it; confirm its owner and purpose. Only if it does not exist:

```sh
sudo useradd --user-group --create-home --shell /usr/sbin/nologin dotmcp
sudo -u dotmcp -H mkdir -m 700 /home/dotmcp/workspace
```

Do not add sudoers entries, the docker group, shared project groups or SSH login. Keep the program (`/home/dotmcp/app`), setup (`/home/dotmcp/.dotunnel-setup`) and workspace (`/home/dotmcp/workspace`) separate. An administrator can run the installation below via `sudo -u dotmcp -H /bin/sh`.

### B. An existing non-administrator account

Install and run from that account's terminal. To use another existing account, install/run from `sudo -u ACCOUNT -H /bin/sh`. Nothing changes the account's password, login settings or groups automatically. Do not recursively `chown` other projects or grant global write access.

**If the account has broad permissions (for example the docker group), fixed tasks have them too. Even a dedicated account is not a complete sandbox.**

## 2. Install

Do not install the program inside the workspace, into the system Python or into a shared environment. Install `dotunnel-<version>-py3-none-any.whl` from [GitHub Releases](https://github.com/junited31/dotunnel/releases) into a dedicated virtualenv. Set `VERSION` to the release you want.

```sh
umask 077
VERSION=0.1.3
curl -fLO "https://github.com/junited31/dotunnel/releases/download/v${VERSION}/dotunnel-${VERSION}-py3-none-any.whl"
sha256sum "dotunnel-${VERSION}-py3-none-any.whl"
```

Compare with the release asset's SHA-256. **Stop if it does not match.** Only after verification, install:

```sh
uv venv --python 3.13 ~/app/venv
uv pip install --python ~/app/venv/bin/python --only-binary :all: "./dotunnel-${VERSION}-py3-none-any.whl"
. ~/app/venv/bin/activate
dotunnel help
```

Verify the downloaded wheel **before installing it**: compare the printed SHA-256 with the release asset's digest and continue only on an exact match. Without `uv`, `python -m venv` and `pip install --only-binary :all: ./dotunnel-...whl` also work. Installation needs no keys or tokens. Later updates use `dotunnel update`.

## Commands

| Command | What it does |
|---|---|
| `dotunnel help` | Full usage. Bare `dotunnel` opens no menu; it points here and exits 2 |
| `dotunnel setup` | Create a new Tunnel setup, or enable/disable optional CLI integrations of an existing one |
| `dotunnel update` | Check the latest stable GitHub release; if newer, install into the current venv after `[Y/n]` approval |
| `dotunnel doctor` | Read-only diagnosis of config, CLI integration metadata, bubblewrap, the official client doctor and loopback connection state |

These four are the commands you use directly. The engine commands below are run by the Tunnel client or by registered tasks; you normally do not type them.

| Engine command | What it does |
|---|---|
| `dotunnel serve --config PATH [--check-config]` | stdio MCP server. Never prints a user menu to MCP stdout |
| `dotunnel cli-job --config PATH` | Run one registered optional CLI job (see `cli-job` below) |
| `dotunnel claude-token --output PATH [--replace]` | Create the Claude long-lived token file (interactive terminal) |

`python -m dotunnel ...` is the same command.

### Update

```sh
dotunnel update
```

- Shows the installed version and the latest stable release of `junited31/dotunnel` on GitHub Releases. If they match it exits as up to date; it never downgrades a newer installed version.
- If a newer version exists it asks `Update now? [Y/n]`. **Enter/y/yes approves**; n/no exits without changes. Other input is asked again. EOF or non-interactive input installs nothing and exits 2; Ctrl-C exits 130.
- Automatic installation is limited to a **non-root Linux, non-editable venv installation**. Update source checkouts, editable installs and system Python manually. It uses `uv pip` when `uv` is available, otherwise the current interpreter's pip, with binary-only dependencies.
- A release needs a stable `vMAJOR.MINOR.PATCH` tag and a `dotunnel-MAJOR.MINOR.PATCH-py3-none-any.whl` asset. The download size, the asset SHA-256 reported by GitHub and the wheel's package name (`dotunnel`) and version are verified before installing. Drafts and prereleases are ignored.
- A failed lookup or a missing release is reported with exit 2, never as "up to date". Automatic rollback of a partial installation is not guaranteed.
- It changes no configuration, keys, CLI authentication or Tunnel connection, and restarts no services. Restart running MCP/client processes yourself, when idle, to load the new code.

### Diagnose

```sh
dotunnel doctor \
  --directory /home/dotmcp/.dotunnel-setup \
  --tunnel-client /home/dotmcp/bin/tunnel-client
```

doctor starts no client or model and changes no settings. Even with a valid config it exits 2 unless live/ready and a successful control-plane poll are observed. The client is taken from PATH or an explicit absolute path only; executables in the current directory are never run automatically. An existing auth file or valid metadata does not prove provider authentication.

## 3. Interactive private Tunnel setup

First prepare your OpenAI account/organization, ChatGPT developer-mode eligibility and a least-privilege runtime account. Install the binary for your OS/architecture from the [official client release](https://github.com/openai/tunnel-client/releases/latest) yourself and verify the official checksum. setup does not download binaries, log in to Platform, create Tunnels or issue keys.

```sh
dotunnel setup \
  --directory /home/dotmcp/.dotunnel-setup \
  --tunnel-client /home/dotmcp/bin/tunnel-client
```

The default directory is `.dotunnel-setup` in the current directory. The parent of a new setup, and the parent directories of client/CLI executables and auth references, must be owned by root or the current user and not writable by others (a trusted-owner sticky `/tmp` is allowed; other group/world-writable parents, parents owned by other users and symlinks are refused). Re-running `dotunnel setup --directory DIR` on an existing setup reconfigures only the optional integrations below; it never reads or overwrites the key/profile. Configure a new Tunnel/key in a new directory, and start an existing connection with the existing profile's `run` command.

**Existing profiles from 0.1.0–0.1.2:** updating the package does not rewrite profiles. Before the next connection start, add `-I` between the absolute Python interpreter and `-m dotunnel` in `mcp.commands[].command` in your trusted `profile.yaml`. Keep the interpreter, config path, Tunnel ID and key reference unchanged. New setups generate this isolated command automatically; it prevents workspace files such as `dotunnel.py` from replacing the installed module. Both new and existing setup require an interactive terminal.

setup walks through one flow:

1. [Platform Tunnel settings](https://platform.openai.com/settings/organization/tunnels): creating/editing needs Tunnels **Read+Manage**. Set both the owning organization and the target ChatGPT workspace association.
2. Enter the Tunnel ID. ChatGPT developer-mode access is separate and cannot be granted by this tool.
3. [Create a runtime API key](https://platform.openai.com/settings/organization/api-keys): **Restricted, Tunnels Read+Use**. Never use an Admin key at runtime.
4. Enter the key with hidden input in a real terminal. Without a TTY/hidden input it stops; the key never appears in chat, argv, literal profile values or on screen.
5. It creates a new 0700 directory with `workspace/` (0700) and `runtime-api-key`, `config.json`, `profile.yaml` (0600). Key and config live outside the workspace, with `tasks: []` by default. Keep custom paths out of version control too.
6. It checks the official `doctor --json` result. **A successful configuration doctor is not successful remote authentication.** A manual foreground run starts only if you choose `y`; do not start it if another client already runs for the same Tunnel.
7. If you start it, it confirms loopback health live/ready and a **successful control-plane poll**, then guides [ChatGPT app registration](https://chatgpt.com/plugins) with the same Tunnel ID. Without authenticated readiness within 45 seconds it stops only the client it started.

If you do not start it, it shows `NOT CONNECTED` and a manual command containing no secrets. Keep the setup terminal open while it runs. Ctrl-C cleans up only that client/process group and does not revoke app/Tunnel/key access. No services, autostart, account/permission changes or public endpoints are created. Private files created before a failure or cancellation are kept; retrying needs a new directory.

Never enter the Platform runtime key in the ChatGPT app. The connection type is **Tunnel** and the input is the **Tunnel ID**. The local stdio MCP has no separate OAuth. Where the app picker appears depends on the account/UI; if you cannot find it, ask for a call that names the registered app and tool. Calls only work while the server's client is running.

### Bubblewrap check and optional CLI integrations

After the configuration doctor, setup always checks Bubblewrap: whether `/usr/bin/bwrap` exists **and** can actually create the isolated namespaces CLI jobs use. The core (Tunnel, file tools, fixed tasks) never needs it.

- **ready:** CLI selection opens (if any CLI is installed).
- **not installed, sudo appears available:** setup offers installation with trusted absolute system commands, e.g. `/usr/bin/sudo /usr/bin/apt-get install -y bubblewrap`, answered with `[Y/n]`. Enter/y runs it in the same terminal, where sudo may ask for your password, then checks again. n skips installation. A successful non-interactive permission listing (`sudo -n -l`) or membership in `sudo`/`wheel`/`admin` is only a best-effort signal, not a guarantee of installation permission. On failure, setup falls back to the guidance below.
- **not installed, no sudo:** setup shows the command for an administrator to run: `sudo apt-get install -y bubblewrap` (Debian/Ubuntu), `sudo dnf install -y bubblewrap` (Fedora/RHEL), `sudo pacman -S --noconfirm bubblewrap` (Arch), `sudo zypper --non-interactive install bubblewrap` (openSUSE) or `sudo apk add bubblewrap` (Alpine). Unknown distributions get the package name only.
- **installed but unusable:** the kernel, AppArmor or container policy blocks unprivileged user namespaces; an administrator must allow them for bwrap. Reinstalling does not help, so it is not offered.

If CLIs are installed but Bubblewrap is still not ready, setup waits: install it in another terminal, then press Enter to check again and continue to the selection in the same run, or type `s` to skip. Skipping keeps the base setup; later run `dotunnel setup --directory DIR` to enable integrations. `dotunnel doctor` reports the same status and command.

**Prefer a runtime account without sudo.** Fixed tasks and CLI jobs run with that account's permissions, so a sudo-capable (especially passwordless) runtime account lets them reach root. The installation offer exists for convenience on single-user servers; on shared or exposed servers install Bubblewrap once from an administrator account (the package is system-wide) and keep the runtime account without sudo.

Only CLIs with a safe executable on PATH are listed. Detection never runs the CLI; if none is installed this step is skipped.

```text
Select installed native CLI integrations
> [ ] Codex
  [ ] Claude Code
  [ ] OMP

↑↓ move · Space toggle · Enter install selected · Esc/Ctrl-C cancel
```

- It does not re-download installed CLIs. It registers fixed tasks for the `cli-job` wrapper.
- For each selected backend you enter the native runtime path, auth file **reference path**, target alias, source root, allowed files and the editable subset. Keep the source root separate from the MCP workspace; an empty editable list means review only. Claude needs a long-lived token file, not the `/login` file (see Claude below).
- Provider login is not proven by setup; jobs still refuse to run whenever isolation is unavailable.
- All selections are validated, then the task registry is replaced at once. On failure no partial set of CLIs is enabled, and repeating the same selection does not change the registry.
- Fixed task names are `dotunnel-codex`, `dotunnel-claude`, `dotunnel-omp`. Operator configs are `DIR/cli-jobs/<backend>.json`, caller requests `workspace/dotunnel-requests/<backend>.json`, and the default request is review. Registration alone never runs a model.
- Deselecting removes only that setup-owned task and keeps its config/request files. Other tasks and the key/profile are unchanged.
- Cancelling the selection in a new setup keeps the private files already created and exits 130 before any connection starts. Cancelling in an existing setup leaves the registry unchanged.
- Scope is a security responsibility. The current backend's auth/config references and setup-internal files are refused as task inputs, but not every secret can be detected. Do not allowlist auth files or secrets such as another backend's arbitrarily named token. Allowed files can reach ChatGPT through the CLI and job results.

## 4. Workspace and config

Interactive setup already creates the workspace/config. Operators configuring by hand create a new workspace, copy `config.example.json` to a `config.json` **outside the workspace** and set `root` to the real absolute path. The initial `tasks: []` grants no execution.

```json
{
  "root": "/home/dotmcp/workspace",
  "tasks": []
}
```

The config must be a regular file owned by the runtime account; symlinks, hardlinks and group/world write permission are refused. Apply `chmod 600` to new files. `root` must be an existing non-symlink directory; `/`, the account's home itself and paths containing the program/config are refused, as are ancestor symlinks, duplicate JSON keys and unknown fields. Do not choose another project's directory.

The administrator adds fixed tasks:

```json
{
  "root": "/home/dotmcp/workspace",
  "tasks": [
    {
      "name": "verify-access",
      "description": "Print a fixed installation check message",
      "argv": ["/usr/bin/printf", "workspace task ready\n"],
      "cwd": ".",
      "timeout_seconds": 5
    }
  ]
}
```

`argv[0]` is an absolute path outside the workspace and `cwd` a workspace-relative directory. Default timeout 60 s, maximum 300 s, at most 50 tasks; clients only choose a name. Callers cannot change argv/env/shell/timeout/cwd, and unknown tool arguments are **refused before a task starts**.

**Review the executable, fixed arguments, the code that runs and its side effects before approving a task.** Running builds/tests or editable scripts in the workspace can execute arbitrary code. Do not assume that choosing a directory limits OS permissions. Children that start a new session can escape process-group cleanup.

### Optional CLI jobs in detail (`cli-job`)

`dotunnel cli-job --config /absolute/operator-config.json` copies only operator-approved files into a separate candidate and has a native CLI review or edit them. It adds no MCP tools or arguments and offers no applying to originals, test runs, commit/push or arbitrary shell. `review` keeps the whole candidate read-only; `edit` allows changes only to existing files listed in `editable`. If files are added/deleted, protected files change, or an original/root is replaced during the job, no result is published.

Non-root Linux and `/usr/bin/bwrap` are required; without them the job is refused. It applies dedicated mount/PID namespaces, drops capabilities, links to parent death, and mounts only the allowlisted copy at `/workspace`. The isolated HOME is `/home/job`, keeping the CLI's writable temporary state separate from the host home. Auth references are read-only, so states needing a saved refresh can fail.

OMP example (paths are examples; use your real installation paths; the config is a private regular file owned by the runtime UID, outside the workspace):

```json
{
  "backend": "omp",
  "workspace": "/home/dotmcp/workspace",
  "request": "cli-request.json",
  "runtime": {
    "executable": "/opt/bun/bin/bun",
    "cli": "/opt/omp/node_modules/@oh-my-pi/pi-coding-agent/dist/cli.js",
    "modules": "/opt/omp/node_modules",
    "config": "/home/dotmcp/.omp/agent/config.yml",
    "auth": "/home/dotmcp/.omp/agent/agent.db"
  },
  "targets": {
    "demo": {
      "root": "/home/dotmcp/projects/demo",
      "files": ["arithmetic.py", "check.py"],
      "editable": ["arithmetic.py"]
    }
  }
}
```

Codex uses `backend: "codex"` and these runtime fields. `companion` must be `codex-code-mode-host` in the same directory as the executable. The installation must support the native `app-server` experimental `dynamicTools`/Code Mode and effective-feature queries; on mismatch it refuses rather than falling back to `exec` or a shell.

```json
{
  "executable": "/opt/codex/bin/codex",
  "companion": "/opt/codex/bin/codex-code-mode-host",
  "auth": "/home/dotmcp/.codex/auth.json"
}
```

Claude Code uses `backend: "claude"` and these runtime fields. `executable` is the real native installation file, not a symlink or launcher. `oauth_token` is a `0600` file owned by the runtime UID containing **only one** long-lived token issued by `claude setup-token`. Group/other permissions, symlinks, hardlinks or multiple values are refused.

```json
{
  "executable": "/home/dotmcp/.local/share/claude/versions/<version>",
  "oauth_token": "/home/dotmcp/.dotunnel/claude-oauth-token"
}
```

Create the token file once from an **interactive terminal** of the runtime UID (requires a Claude subscription):

```sh
dotunnel claude-token --output /home/dotmcp/.dotunnel/claude-oauth-token
```

It runs `claude setup-token` in a pseudo-terminal, shows its screen, detects the single printed token and saves it to a new `0600` file; if detection fails it asks you to paste it with hidden input. Existing files are never overwritten; `--replace` rotates atomically. The token is never accepted as an argument and never displayed again. At run time the parent passes the token only as the `CLAUDE_CODE_OAUTH_TOKEN` environment variable of the bubblewrap process, never in argv or a mount. Claude running as the same UID can read it, so this is not a secrecy boundary. If it leaks, revoke it in your Claude account and issue a new one. Do not treat `loggedIn: true` from `claude auth status` as proof that server authentication works.

Claude runs with `--safe-mode --restricted` and fixed file tools only (`review`: `Read`, `edit`: `Read,Edit,Write`). No `--bare` or permission bypass is used, and host settings/hooks/skills/plugins/MCP/sessions are not mounted. Every success field of the single final `result` (`is_error: false`, `terminal_reason: "completed"` and more) is checked; `subtype: "success"` alone is not success. Claude edit mounts only the minimal parent directories of editable files writable inside the candidate copy, and leftover new entries, deletions or protected-file changes are rejected before publication.

The administrator registers each backend as a task with **fixed argv** in the MCP config, e.g. `["/home/dotmcp/app/venv/bin/dotunnel", "cli-job", "--config", "/home/dotmcp/omp-cli-job.json"]`. Set the timeout to cover the native 200-second limit plus cleanup (e.g. 240 s). `run_task` does not wait for completion; check with `get_task_result`.

Callers write only these three fields to the configured request file with `write_file` and call `run_task(name)` **once**. Keep the returned `result_id` and poll at a bounded interval and deadline. Do not overwrite the request file of a running job. `target` must be a registered alias, `mode` is `review` or `edit`, and `instruction` is at most 8 KiB of UTF-8.

```json
{"target":"demo","mode":"edit","instruction":"Using check.py as reference, change only arithmetic.py and briefly report the change."}
```

Success output contains `reviewed` or `candidate_ready`, `report_path`, `report_sha256` and more. Limits: 32 UTF-8 regular files per target, 64 KiB per file. When done, `read_file` the `cli-results/<backend>/<job_id>/report.json` and every diff chunk it lists (at most 48 KiB each), and check their SHA-256. `candidate_ready` **does not mean the change was applied to originals or that the problem is fixed.** The model summary is not verification evidence, and every report has `verification: not_run`.

Native output (1 MiB logical capture) and run time (200 s) are bounded; failures return fixed diagnostics instead of raw CLI logs. The wrapper never re-runs a failed job. **Native execution failures** return `{"status":"failed","error_code":"NATIVE_FAILED"}` plus only these fields:

- `native_error_code`: `SANDBOX_UNAVAILABLE`, `NATIVE_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_LIMIT`, `NATIVE_FAILURE`, `INVALID_NATIVE_STREAM`.
- `native_detail`: `AUTH_FAILED` (API 401/403), `RATE_LIMITED` (429), `PROVIDER_ERROR`, `PERMISSION_DENIED`, `UNSUCCESSFUL_RESULT`, `INVALID_RESULT`, `EMPTY_RESULT`, `SUMMARY_TOO_LARGE`, `NO_RESULT`, `INVALID_STREAM`, `EXIT_NONZERO`.
- `native_exit_code`, `native_elapsed_seconds`: omitted when absent or malformed.

Other job failures return `status: failed` with `CANDIDATE_INVALID` (unsafe candidate), `SOURCE_CONFLICT` (sources changed during execution), `ARTIFACT_FAILURE` (result publication failed), or `JOB_FAILED` (unexpected failure). Invalid inputs return `status: rejected` with `INVALID_REQUEST` or `INVALID_CONFIG`. Failed jobs exit 1; rejected inputs exit 2. Do not treat these safety rejections as a successful candidate or automatically retry them.

OMP JSON is validated frame by frame and cumulative progress/tool bodies are not stored. The 1 MiB budget is split into frames of at most 980,992 bytes, a 2 KiB final summary and 64 KiB of stderr. A single frame containing the whole conversation that exceeds the limit fails. A CLI running as the same UID can read its referenced credentials and shares provider networking, so neither credential secrecy nor exfiltration prevention is guaranteed. Allowed sources, instructions, summaries and diffs may themselves contain sensitive data.

## 5. Local checks and foreground run

```sh
dotunnel serve --config /home/dotmcp/config.json --check-config
dotunnel serve --config /home/dotmcp/config.json
```

`--check-config` only validates the configuration and runs no tasks or Tunnel. The second is the stdio server: it prints no menu in a normal shell and expects an MCP client on stdin/stdout. Logs go to stderr; stdout is reserved for MCP. When configuring tunnel-client's child yourself, use the **absolute path** of the installed `dotunnel` with `serve --config ...`. Profiles created by `dotunnel setup` include this command automatically.

Development checks (small fixture tests):

```sh
python -m unittest discover -s tests -v
```

## Tools and limits

| Tool | What it does |
|---|---|
| `list_files(path=".")` | Immediate entries, at most 200, inspecting at most 1000 entries |
| `read_file(path)` | UTF-8 file content and SHA-256, at most 64 KiB |
| `search_files(query, path=".")` | Literal content search, at most 100 matches, 1000 entries, 4 MiB scanned |
| `write_file(path, content, expected_sha256=null)` | null creates a new file only; replacing an existing file requires its current hash |
| `list_tasks()` | Allowed task names/descriptions |
| `run_task(name)` | Start a fixed task and immediately return `running` with a result ID |
| `get_task_result(result_id)` | Running or final result; the last 20 IDs of the current server process |

Task call sequence:

1. Call `run_task(name)` once and keep the `result_id`. The response is `result_id`, `task`, `status: "running"`, `exit_code: null`, `output: ""`, `truncated: false`.
2. Query `get_task_result(result_id)`. If `running`, wait and query the same ID again; queries never start work. Do not poll endlessly or rapidly.
3. Final states are `completed`, `timed_out`, `failed` and `cancelled`. `completed` does not mean exit code 0; check `exit_code`, `output` and `truncated` together. There is no partial output while running.
4. IDs are not persisted and the cache holds at most 20 including the running one. After a server restart or eviction they cannot be queried. Never automatically retry an already started task because a start response was lost.

- Paths are relative to root. `..`, absolute paths, symlinks, hardlinks, FIFOs/devices/sockets and hidden/credential/private-key names are refused or excluded, including protected names with an added extension. Parent directories must already exist; there are no mkdir/delete/move/chmod tools.
- Hash checks serialize writes within one server instance but are not an atomic transaction with external editors. A write can be partially applied on OS/I/O failure.
- One task at a time; output is limited to 16 KiB of UTF-8. Excess output is drained rather than accumulated, truncation is reported, and terminal control sequences are removed.
- Task stdin is closed and only a minimal PATH/HOME/LANG environment is passed. Inherited OpenAI/SSH/cloud credential variables are not passed; HOME is the workspace.
- Same-process-group children are cleaned up on completion, timeout and server shutdown. After the start response, a cancelled request/query does not stop the server-owned job; shutdown blocks new starts and waits for cleanup of starting and running jobs. If a detached child keeps the pipe open, the transport is closed and the direct child reaped. Termination of children that escape into a new session is not guaranteed, and this is no OS CPU/RAM/disk/network sandbox.
- Hidden/key filename rules **do not guarantee that all secrets are excluded.** Allowed files and task output can contain code, prompts, personal data or secrets. The stdio MCP has no separate user authentication, so restrict who can reach the endpoint/runtime.
- Read-only/destructive tool hints are UI hints, not server-side authorization.

## Before connecting ChatGPT

Based on the [official OpenAI Secure MCP Tunnel documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

1. Confirm developer MCP registration and **support for write/execute tools** in the target ChatGPT account/plan/workspace.
2. Confirm Platform organization permissions: running/selecting the app needs Tunnels Read+Use, creating/editing needs Read+Manage; both are separate from ChatGPT developer mode.
3. Settle the target workspace/organization association and a single tunnel.
4. Review which workspace files and task output will reach ChatGPT, execution permissions and how to disconnect.
5. Only then download the [official tunnel-client release](https://github.com/openai/tunnel-client/releases/latest), verify its checksum and configure credentials. stdio supports one active client per Tunnel ID.

The runtime key is Restricted (Tunnels Read+Use) and **not an Admin key.** Never put keys in chat, source, literal argv or logs, and keep the child's environment minimal.

To stop the connection, end the foreground client with Ctrl-C or stop the service if you configured one. That alone does not revoke existing access; full removal may require disconnecting/deleting the app, removing/deleting the tunnel association and revoking the runtime key. Data already sent to ChatGPT is not recalled by disconnecting. This project creates no services or autostart; configure persistence yourself according to your server policy if needed.

## Secrets and repositories

Keep `.dotunnel-setup/`, runtime keys, profiles, configs and token files out of version control and shared repositories. This repository's `.gitignore` excludes the default setup directory, `.env`, `*.pem` and `*.key`.

## License

[MIT](LICENSE)
