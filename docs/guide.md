# Installation and operations guide

<p align="center"><img src="../assets/dotunnel.png" alt="dotunnel: a hollow cylinder forming a tunnel" width="640"></p>

[English front page](../README.md) · [한국어](guide.ko.md) · [Design](../DESIGN.md) · [Example config](../config.example.json) · [Logo asset](../assets/dotunnel.png) · [License](../LICENSE)

This guide covers installation, private Tunnel setup, workspace tools, optional native CLI jobs and optional Herdr/tmux agent supervision. `dotunnel` is a local stdio MCP server; it is not a hosted service, a public HTTP endpoint or a sandbox for arbitrary code.

## 1. Installation

Use a non-root Linux account with Python 3.11 or later, `python3` with `venv` and `pip`, `curl`, `sha256sum`, and network access to download the wheel and dependencies. `uv` is not required. Dependencies are installed from binary wheels into an isolated venv.

### Public installer

The front-page one-line command downloads `install.sh` from the public repository's `main` branch without GitHub authentication and runs it as your current user. `curl | sh` executes that script; read and trust the script itself. The installer verifies the pinned wheel before pip installs it, but that wheel checksum does not authenticate the shell script. The installer only installs the package: it does not run interactive setup from piped stdin.

The public installer uses `$HOME/.local/share/dotunnel/venv` and exposes `$HOME/.local/bin/dotunnel`. It refuses to overwrite an existing install path or unrelated launcher. It does not use sudo, change accounts or permissions, edit shell startup files, start services, install the official Tunnel client, create keys or modify Tunnel settings. If the launcher is not found, add `$HOME/.local/bin` to `PATH` yourself or invoke it by absolute path; no shell startup file is edited.

### Manual installation

To avoid executing a downloaded shell script, download the v0.1.6 release wheel directly. GitHub authentication and `gh` are not required. Check both the expected byte count and SHA-256 **before** installing:

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
wheel="$tmp/dotunnel-0.1.6-py3-none-any.whl"
curl --fail --location --output "$wheel" \
  https://github.com/junited31/dotunnel/releases/download/v0.1.6/dotunnel-0.1.6-py3-none-any.whl
test "$(wc -c < "$wheel")" -eq 142242
printf '%s  %s\n' \
  17f5c95c215f29028bf9a7ce8b563a8bf5e013437b55c61179d5952979f79de1 \
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

Setup checks the official client's configuration doctor, then offers an optional foreground connection only after explicit confirmation. A successful configuration doctor is not remote authentication. If started, setup waits up to 45 seconds for live/ready health and a successful control-plane poll; if authenticated readiness is not reached, it stops only the client it started. Otherwise it reports not connected. It may then guide you through [registering the app in ChatGPT](https://chatgpt.com/plugins) with the same Tunnel ID. Never enter the runtime key in ChatGPT; select the Tunnel connection and provide the Tunnel ID. Keep setup interactive. Canceling the final permission review creates no files; a later failure may leave private files, so check the final status and inspect reported paths before retrying. Setup creates no service or autostart.

Re-running `dotunnel setup` with an existing directory reviews the workspace, MCP file-access rules and optional fixed-job/live-supervision selections. It reuses existing key and profile references without reading or displaying the key value. Before editing an existing setup, it requires the matching local Tunnel client to be known stopped and a separate operator confirmation that no other local or remote client is using that Tunnel; setup does not stop or restart existing clients or services. Saved permissions take effect when a new MCP server process starts.

### Integrated permission review (0.1.6)

Setup drafts the workspace, MCP file rules, selected fixed CLI jobs and optional live-supervision grants before creating new private artifacts. The final review shows the actual paths, read/write rules, fixed-job source/editable sets, live project/profile actions, executable metadata and retained task commands. The final `[y/N]` approval defaults to No: pressing Enter cancels without requesting a key or changing files. The key value is not printed in the review.

If new live supervision needs a state directory, its initialization has a separate default-No confirmation. Initialization creates state only: it does not start an agent or approve a runtime scope. After approval, setup prepares private references and job artifacts, validates the complete registry, then atomically publishes the setup configuration last. The saved permissions are used by a newly started MCP server, not a process already running.

After saving, setup runs the local Tunnel-client doctor. Starting the Tunnel connection is a separate default-No foreground choice, and requires another explicit confirmation that no other local or remote client is active for that Tunnel. Setup does not run a native model/CLI or create or restart a service.

If you decline the external-client attestation or foreground start after saving, setup leaves the client stopped and prints a shell-quoted manual command plus ChatGPT registration guidance. The command uses `env -i` with the same `HOME`, `PATH` and `LANG` values as automatic foreground startup instead of inheriting arbitrary shell variables. Before starting manually, independently confirm no other client uses that Tunnel. Existing setups do not print an unknown Tunnel ID as `None`.

Read the final status on errors instead of assuming an all-or-nothing rollback. Before configuration publication, the old configuration remains authoritative, but setup may report private files that were attempted or remain; inspect those exact paths and follow its retry instructions. Once it reports the configuration saved, a doctor or startup/readiness failure does not roll it back. If foreground startup/readiness is uncertain, a client may have started; check its status before trying again.

If configuration publication is unconfirmed after a rename or an ambiguous rename outcome, setup preserves the prepared references and reports that no new connection was started. The config may already exist: reconcile its trusted identity and referenced paths before retrying or deleting artifacts. A failed durability or readback check is not proof that publication did not happen.

### Existing profile migration

Package updates do not rewrite profiles made by v0.1.0–v0.1.2. Before starting one with v0.1.3 or later, edit the trusted `profile.yaml` command in `mcp.commands[].command`: insert `-I` between the absolute Python interpreter and `-m dotunnel`. Keep the interpreter, config path, Tunnel ID and key reference unchanged. New setups already generate the isolated command.

### Existing setup and permission migration

**0.1.6 upgrade boundary:** `dotunnel serve` rejects an older config that lacks `file_access`; installing the package does not make that config usable. Keep a private backup, stop the owned client, review and migrate the existing setup, then restart only after the saved config validates. For a manually maintained config outside a setup directory, explicitly add the reviewed file rules and supervision project/profile actions using the documented schema before restarting; do not run the setup wizard against an unrelated directory or recreate existing state/key references.

Package installation alone does not migrate an existing setup. Run interactive `dotunnel setup --directory PATH` for the existing setup and review its full draft. Setup refuses to update while the matching local Tunnel client is active or its ownership/state cannot be established; stop the owned client yourself and rerun it. It also requires a separate default-No attestation that no other local or remote client uses the Tunnel, which a local process check cannot prove. Missing or unsafe existing supervision state is not silently recreated or rotated.

Existing setup-owned native CLI tasks can be explicitly unregistered even when their CLI is unavailable or their job document is invalid. Removal defaults to No and still requires the final draft approval; it removes only the task registration, not prior job/request files. Skipping optional Bubblewrap/integration configuration is not deselection: existing registrations remain by default, with a separate removal choice. Retained jobs must still validate against the reviewed workspace. Retained supervision state is opened read-only and its authority identity is rechecked before publication; missing, malformed or changed state blocks saving without recreating or rotating it.

Legacy configurations without `file_access` are converted to explicit `tree .` read and write rules, preserving their former whole-workspace access rather than narrowing it on upgrade. The prompt to keep existing read/write rules defaults to Yes; answer No to enter narrower paths. Otherwise the final summary shows the full-tree grants, and only approving that summary saves them. Existing supervision permissions are translated into explicit project ceilings and per-profile actions; they are not automatically cleared. A legacy live profile without `executable_policy` asks you to select `compatible` or `strict` (Enter selects `compatible`); select `strict` to retain the former writable/multiple-link executable metadata checks.

## 4. Diagnose, update and disconnect

- **`dotunnel doctor`** is read-only: it starts no client or model and changes no settings. It checks setup/configuration, the selected client and optional Bubblewrap status. Valid config or auth-file metadata alone is not proof of provider authentication. Unless live/ready and a successful control-plane poll are observed, doctor exits 2. Use `--directory DIR` and, if needed, `--tunnel-client /absolute/path` to select paths.
- **`dotunnel update`** checks the latest stable public GitHub release over HTTPS without GitHub CLI or login and asks before installing. It is limited to non-root Linux, non-editable venv installations; it does not downgrade a newer version. The release wheel name, size, GitHub-reported SHA-256 and package name/version are checked before binary-only installation. Network/TLS errors, GitHub rate limits, a missing release, EOF or non-interactive input fail closed (exit 2); Ctrl-C exits 130. A partial-install rollback is not guaranteed. Update changes no config, credentials or Tunnel settings and restarts no running process; restart idle MCP/client processes yourself. Versions before 0.1.4 still use their old updater: use that updater once or manually install the verified current wheel to obtain the anonymous updater.
- **Disconnecting** a foreground client with Ctrl-C stops that client but does not revoke access. Depending on your setup, fully removing access may require disconnecting/deleting the ChatGPT app, removing the Tunnel association and revoking the runtime key. Data already sent to ChatGPT is not recalled. The project creates no persistent service; manage any service you set up according to your own server policy.

## 5. Workspace, tasks and MCP tools

Setup creates the initial workspace and config. For manual configuration, start from [`config.example.json`](../config.example.json), keep the config outside the workspace, and set `root` to an existing absolute workspace path. The config must be a private regular file owned by the runtime account; symlinks, hardlinks and group/world write access are refused. The root cannot be `/`, the account's home, or overlap the program/config paths; ancestor symlinks and unknown/duplicate fields are rejected.

### MCP file-access rules

From 0.1.6, `file_access` explicitly limits the four MCP file tools. A new setup starts with both `read` and `write` empty; selecting a workspace does not grant access to its contents. Rules use workspace-relative paths and `kind` `file` for one exact file or `tree` for a directory and all descendants, including files created later. For example:

```json
{
  "root": "/srv/example/workspace",
  "file_access": {
    "read": [
      {"path": "src", "kind": "tree"},
      {"path": "README.md", "kind": "file"}
    ],
    "write": [
      {"path": "src/change.py", "kind": "file"}
    ]
  },
  "tasks": []
}
```

Every write rule must be contained within the read rules. `list_files` and `search_files` follow the read policy too: they omit inaccessible entries, names and matches; an ancestor may be traversed only to reach an allowed path. Existing restrictions on hidden/credential paths, links and special files still apply. These rules do not restrict administrator-defined `tasks`, fixed CLI jobs or live agents, which have separate execution boundaries.

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

Supervision is a separate optional API: the existing seven file/task tools remain unchanged, and one shared set of eight `agent_*` tools is registered only when supervision is configured. See section 7 for its configuration and safety contract.

Paths are relative to `root`. Absolute paths, `..`, symlinks/hardlinks, special files, hidden paths and common credential/key names are refused or excluded. Parent directories must already exist; there are no delete, move, mkdir or chmod tools. Writes are hash-guarded against changes observed by this server but are not atomic with external editors and may be partial on an OS/I/O failure. One task runs at a time; output is capped at 16 KiB and excess is drained. Task stdin is closed and only a minimal environment is passed; this is not CPU, memory, disk or network isolation. Process-group cleanup does not guarantee termination of a child that escapes into a new session.

Call `run_task(name)` once, save its `result_id`, then poll `get_task_result(result_id)` at a bounded interval. Polling does not start work. Check `exit_code`, `output` and `truncated`; `completed` does not mean exit code zero. There is no partial output while running. IDs are in-memory, limited to 20 and invalidated on server restart; never blindly retry a task after losing its start response.

## 6. Optional native CLI jobs

CLI jobs are disabled unless an operator explicitly registers them. They add no MCP tools and setup registration alone does not run a model or prove provider login. The native Codex, Claude Code or OMP CLI and its provider access must be installed/configured separately. `dotunnel setup` detects safe launchers on `PATH` without running them. Optional jobs require non-root Linux and usable `/usr/bin/bwrap` (Bubblewrap); the core Tunnel, file tools and fixed tasks do not. Bubblewrap creates mount/PID namespaces, drops capabilities and exposes only an allowlisted candidate at `/workspace`, with a separate `/home/job`; setup checks that namespaces work, not just that the executable exists. If Bubblewrap is missing, setup may offer installation when sudo appears available; if installed but unusable, kernel/AppArmor policy must allow unprivileged namespaces (reinstalling will not fix it). On shared servers, prefer an administrator installing the system package while keeping the runtime account non-sudo. You may skip integrations and configure them later.

An operator-owned config fixes each backend's runtime, auth references, source root (separate from the MCP workspace), target aliases, file allowlist and editable subset outside the writable workspace. `review` is read-only; `edit` may change only existing allowlisted files in the isolated candidate. This source/editable selection is distinct from MCP `file_access`: neither grant implies the other. Jobs never apply changes to originals, run tests, commit/push or offer arbitrary shell. The task registry is updated as a whole; deselecting a backend removes only its setup-owned task. The native CLI runs as the same user, can read referenced credentials and shares provider networking. Do not allowlist secrets; selected source/instructions/results may be sent to the provider. These fixed jobs use the Bubblewrap candidate boundary; live Herdr/tmux agents in section 7 do not and retain native OS filesystem/authentication authority.

Write only `{ "target": "alias", "mode": "review", "instruction": "..." }` to the configured request file, then call the registered `run_task` once and poll its result. `target` must be registered, `mode` is `review` or `edit`, and `instruction` is at most 8 KiB of UTF-8. Do not overwrite a running request. A target has at most 32 regular files, each at most 64 KiB. Set the MCP task timeout to cover the 200-second native limit plus cleanup (for example, 240 seconds). The native run captures at most 1 MiB. The result points to a report and SHA-256-addressed diff chunks (at most 48 KiB each); read and verify those artifacts. `candidate_ready` means only that a candidate was prepared, not that it was applied or correct; reports say `verification: not_run`.

When setup registers a fixed job, its request-control file is a separate exact-file MCP read/write grant. Setup shows those paths for explicit approval; it does not add broad workspace access to make request files writable.

- **Codex** requires a compatible native app-server installation with experimental `dynamicTools`/Code Mode and effective-feature queries, plus its `codex-code-mode-host` companion. Incompatible installations are refused; there is no `exec` or shell fallback.
- **Claude Code** requires a long-lived token from `claude setup-token`, not the normal `/login` credential. `dotunnel claude-token --output PATH` creates a new private token file interactively; existing files are not replaced unless `--replace` is requested. The token is passed to the isolated process as `CLAUDE_CODE_OAUTH_TOKEN`, not argv or a mount. The same-UID Claude process can read it, so revoke and replace a leaked token. Claude runs with `--safe-mode --restricted` and fixed file tools; host settings, hooks, plugins, skills, MCP servers and sessions are not mounted.
- **OMP** output is validated frame by frame; cumulative progress/tool bodies are not retained. A malformed or oversized frame, or an unfinished latest turn, fails rather than reusing an earlier completion.

Native execution failures return `status: failed`, `error_code: NATIVE_FAILED` and allowlisted `native_error_code` values (`SANDBOX_UNAVAILABLE`, `NATIVE_UNAVAILABLE`, `TIMEOUT`, `OUTPUT_LIMIT`, `NATIVE_FAILURE`, `INVALID_NATIVE_STREAM`) plus fixed `native_detail` values (`AUTH_FAILED`, `RATE_LIMITED`, `PROVIDER_ERROR`, `PERMISSION_DENIED`, `UNSUCCESSFUL_RESULT`, `INVALID_RESULT`, `EMPTY_RESULT`, `SUMMARY_TOO_LARGE`, `NO_RESULT`, `INVALID_STREAM`, `EXIT_NONZERO`); raw CLI logs are not returned. Other failed jobs use `CANDIDATE_INVALID`, `SOURCE_CONFLICT`, `ARTIFACT_FAILURE` or `JOB_FAILED`; rejected inputs use `INVALID_REQUEST` or `INVALID_CONFIG` (exit 2; failed jobs exit 1). Do not interpret a safety rejection as a successful result or automatically retry it.

## 7. Optional Herdr/tmux agent supervision

Supervision is disabled unless a trusted `dotunnel` configuration contains a fixed `supervision` registry and its state is explicitly initialized. It can use configured Herdr sessions, tmux sockets, or both (up to four connections total). Projects bind canonical paths to allowed connections and profiles; profiles bind a CLI kind to an absolute executable and fixed arguments. Callers cannot supply a cwd, executable, arguments or environment. Supervision is available in 0.1.5; from 0.1.6, interactive setup can configure it alongside explicit action permissions. Package installation or update alone does not activate it.

The base [`config.example.json`](../config.example.json) intentionally stays minimal. This is a complete, syntactically valid illustrative configuration; replace the anonymous sample paths with your own trusted absolute paths. The Herdr and tmux backends may coexist in the same `connections` list when each is explicitly configured.

Live profiles use `executable_policy: "compatible"` by default; `strict` is selectable. Compatible mode can admit a group/world-writable or multiply hard-linked leaf executable, so another writer or link sharer may change code run with the live agent's native filesystem and authentication authority. This is an accepted tampering risk, not a security guarantee. Strict restores the leaf executable's writable-mode and multiple-link refusals; ownership, parent-path, symlink, regular-file, executable and set-ID checks remain in force either way. This setting applies only to live supervision profiles, not the fixed Bubblewrap jobs in section 6, and does not grant any agent action.

```json
{
  "root": "/srv/example/workspace",
  "file_access": {"read": [], "write": []},
  "tasks": [],
  "supervision": {
    "state_dir": "/srv/example/state/supervision",
    "default_connection": "tmux-example",
    "connections": [
      {
        "id": "tmux-example",
        "backend": "tmux",
        "executable": "/usr/bin/tmux",
        "socket": "/srv/example/state/tmux-example.sock"
      }
    ],
    "projects": [
      {
        "id": "example-project",
        "path": "/srv/example/project",
        "connections": ["tmux-example"],
        "profiles": ["omp"],
        "allowed_actions": [],
        "profile_actions": {"omp": []}
      }
    ],
    "profiles": [
      {
        "id": "omp",
        "kind": "omp",
        "executable": "/usr/local/bin/omp",
        "executable_policy": "compatible",
        "args": [],
        "backends": ["tmux"],
        "input_mode": "bracketed-paste"
      }
    ],
    "protected_paths": ["/srv/example/protected"]
  }
}
```

Initialize state before serving MCP requests:

```sh
dotunnel supervision init --config /path/to/trusted/config.json
dotunnel serve --config /path/to/trusted/config.json
```

`init` creates private state only; it does not start agents. The state directory
must be owned by the runtime UID, mode `0700`, with mode `0600` files, and remain
outside the writable MCP `root`.
MCP startup does not create missing state or silently recover damaged state.
Use `dotunnel supervision reinit --config /path/to/trusted/config.json` as a
deliberate authority rotation, not automatic recovery. It requires terminal
acknowledgement and preserves the old namespace as `<state_dir>.previous`;
reconcile that archive before requesting another rotation. Old handles,
approvals and operation IDs do not become authority in the new namespace.

Namespace creation and rotation use a persistent empty mode `0600`,
single-link, runtime-UID-owned `.dotunnel-owner-<64 lowercase hex digits>` file
in the state directory's parent. Its name hashes the state basename's filesystem
bytes; its lock remains held across both renames, rollback and final validation.
A competing command returns `busy` without publishing another namespace.
Do not remove or replace this file while any command may hold it. Stop commands
using older binaries before cutover or owner-file cleanup; their root-inode lock
alone does not cover a missing active pathname during rotation.
A pre-created empty private state directory can still be initialized below a
non-writable parent, using existing-root inode ownership when the owner file is
absent. This path never creates a missing root or bypasses an existing unsafe
owner file. Creating the state directory or rotating it requires parent write access.
After SIGKILL, explicit reinitialization can archive one bounded, owner-only
`.write-<32 lowercase hex digits>` staging file along with the old namespace.
Startup still refuses that incomplete namespace; staged bytes never become
approvals or receipts. Malformed or unsafe staging files remain refused.

### Tools, scopes and selection

The registered common API has exactly eight tools:

| Tool | Contract |
|---|---|
| `agent_status(connection?, project?, cursor?)` | Read-only inventory and recovery diagnostics, paged to 100 rows and 64 KiB; a changed registry/scope invalidates the cursor |
| `agent_read(target, lines=80)` | Reads the latest screen tail, at most 1–200 lines and 16 KiB, and issues a signed observation valid for 60 seconds |
| `agent_approve(scope)` | Approves the current configuration generation for `connection_id:project_id` |
| `agent_revoke(scope)` | Revokes that scope; it does not stop an agent or retract delivered input |
| `agent_start(project, profile, name, operation_id, connection?, worktree_branch?)` | Starts a registered profile; `name` is display text, not target identity; worktree branches are Herdr-only |
| `agent_prompt(target, observation, text, operation_id)` | Rechecks the handle, current identity, approval and fresh observation before sending literal text (up to 8 KiB) |
| `agent_answer(target, observation, keys, operation_id)` | Sends up to eight explicitly selected lowercase keys: `enter`, `esc`, `up`, `down`, `left`, `right`, `tab`, `y`, `n`, or `1`–`9` |
| `agent_wait(target, observation, timeout_seconds=60)` | Waits for a bounded change and returns a fresh observation; maximum wait is 110 seconds |

New project grants use `projects[].allowed_actions` as a ceiling: it may contain `read`, `start`, `prompt` and `answer`. `projects[].profile_actions` separately lists the `start`, `prompt` and `answer` actions allowed for each profile; each profile's actions must fit inside the project ceiling, and `prompt`/`answer` also require project `read`. New grants start empty. A setup-time grant does not by itself approve a runtime scope: `agent_approve` remains a separate approval for the exact `connection_id:project_id`. Runtime approval cannot add an action omitted from the project or profile configuration, and neither kind of agent permission is an MCP file-access grant.

`agent_approve` and `agent_revoke` scopes are exactly `connection_id:project_id`
and bind the active configuration generation. This is an operator mistake guard,
not human authentication; the stdio MCP server has no separate caller identity.
Restrict access to the stdio process and Tunnel. Scope changes invalidate old
approvals and handles, but do not undo an effect that has already occurred.

Targets are opaque signed handles, not display names, pane IDs or names supplied
by a caller. A recovery identity or unresolved-start record is diagnostic only
and is never an actionable target. The default connection selects a connection
for a new start only. It does not approve a scope, resolve an ambiguous existing
target, restart an agent, broadcast an operation or fall back to another
connection. Existing targets require explicit handle selection, never
display-name adoption.

Herdr may expose only weak native process identity; its handles require fresh
discovery after supervisor restart or connection failure. tmux provides stronger
managed identity evidence: writes are limited to agents dotunnel started from
fixed profiles with recorded and rechecked boot/server/pane/process identity.
Arbitrary existing tmux panes are never adopted for input; register an exact
`read_targets` identity to observe an existing pane read-only. Even this
evidence and repeated checks are not an atomic delivery guarantee or a sandbox.
Backend status, screen changes and confirmed input do not prove logical task
success; tmux agent status may legitimately be `unknown`.

Put `read_targets` on its tmux connection using the current exact identity;
PID/start-time values are decimal strings. Replace all illustrative values
with that server and pane's `/proc` evidence. A replaced process invalidates
the registration, and approval never makes it writable.

```json
"read_targets": [{
  "project": "example-project", "native_id": "%3",
  "identity": {
    "boot_id": "00000000-0000-4000-8000-000000000000",
    "server_pid": "12345", "server_start": "100000",
    "pane_pid": "12346", "pane_start": "100001"
  }
}]
```

Screen observations and native output may contain secrets; terminal/ANSI cleanup
is not redaction.

### Durable operations and execution limits

Every start, prompt and answer requires a unique `operation_id`. Persistent
receipts bind the ID to the canonical request: replaying the same ID and
identical payload returns its recorded result without repeating native effects;
reusing it with different content conflicts. A delivery or start reported as
`unknown` may already have taken effect. Inspect its receipt and recovery
diagnostics and reconcile the target before proceeding; never blindly retry an
unknown operation with the same or a new ID. Recovery records are not handles.
Receipts and target records are each limited to 1,000 entries of at most 64 KiB;
they are not silently pruned.

A `busy` refusal from `agent_revoke` is not a completed revocation. Wait for
the in-flight mutation to finish, explicitly revoke again, and check status.

The shared native CLI pool permits at most four concurrent CLI processes.
Ordinary status/inspection/input calls have a 20-second deadline, a start has a
180-second overall deadline, and `agent_wait` is capped at 110 seconds. Combined
captured stdout and stderr are capped at 4 MiB. Status pages and screen excerpts
are bounded as described above; these limits do not promise that an agent has
finished or that its work is correct.
On successful leader exit, even when ordinary helpers inherit stdout/stderr,
the pool cleans up its owned process group before waiting for pipe EOF, then
finishes bounded output drains before transport closure. Separately detached
backend servers and agents are not stopped.

`protected_paths` is an admission-time overlap guard: if a project's path,
working directory or original repository overlaps a protected path in either
direction, mutations are refused and only observation remains. It is not
filesystem confinement, does not restrict a running native process, and is not
a sandbox. Native agents retain their own account permissions, tools and
network access.
For tmux, the reported working directory is the verified process's canonical
live cwd, not the configured project path. It is rechecked before observation
or input; an unavailable cwd hides the target and refuses further interaction.
Native agents retain their own approval policies. For an OMP write-approval
smoke, use `--approval-mode=always-ask` and owner-only YAML
`tools.approval.write: prompt`; `--approval-mode=write` permits that tier rather
than requiring its approval UI. Read the prompt and send only the user's
explicit choice. Herdr prompt text can be visible in host process arguments
during submission; do not send credentials.

The standalone [`dotunnel-adapter-runner`](../adapter_runner/README.md) remains a
separate contract and uses only the seven base tools. It ships no Herdr, Orca,
tmux or provider adapters; Orca is not part of core supervision.

## 8. Development without publishing secrets

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

Public push/PR CI also scans fetched Git history, runs the Linux regression suite on Python 3.11 and 3.13, builds a wheel and exercises its installed CLI outside the checkout. It uses isolated GitHub-hosted Ubuntu runners with read-only permissions and no operator/worker credentials. CI failure reports a failed check; branch-protection rules are a separate repository policy.

Before pushing, review `git diff --cached` locally, verify that runtime/key files are absent, and run the history scan above on the source repository—not the runtime directory. Do not paste sensitive diffs or scan reports into public issues. Enable GitHub secret scanning and push protection on your repository where available. Neither detector catches every secret; hooks can be bypassed and provider push protection has pattern and bypass limitations. If a real secret is committed or pushed, revoke/rotate it first; deleting the latest file does not remove Git history.

For unpublished feature work, create a separate **private repository**, clone the public source and push to that private remote. A public GitHub fork remains public and cannot independently become private; see [GitHub fork visibility](https://docs.github.com/en/pull-requests/reference/forks). Keep public upstream as a fetch source; publish only reviewed code changes, never private runtime files or operational history. A separate private development repository is optional, not a runtime requirement.

## 9. Maintainer draft releases

Publish source changes through a feature branch and PR. Public `main` requires `Secret scan`, `Python 3.11` and `Python 3.13` from GitHub Actions, an up-to-date base and resolved review conversations; these rules also apply to administrators. No direct main push, force-push or branch deletion.

The release workflow prepares **drafts only**. For a release, merge the intended canonical package version into main and wait for its exact commit's main CI to succeed. Then push the matching stable tag. For example, after main declares `0.1.5`:

```sh
git fetch origin main
git tag v0.1.5 origin/main
git push origin v0.1.5
```

The workflow rejects a tag/package mismatch, a source outside main history, missing successful main CI and an existing release. Read-only jobs build and validate one universal wheel and generate its size/SHA-pinned `install.sh`, `SHA256SUMS` and source-SHA manifest. Only the separate draft attachment job has repository write permission; it uses no PAT, operator or worker credential. Inspect the complete assets before manually publishing the draft in GitHub Releases. A failed upload leaves a draft, not a partially published release; existing assets are never overwritten.

To verify preparation without creating a tag or changing any Release:

```sh
gh workflow run release.yml --ref main -f dry_run=true
```

Inspect that run's summary and download its verification artifact. A dry-run verifies preparation, not live draft upload or publication. Drafts are not the updater's latest stable release; only manual Publish makes the version available. GitHub CLI here is a maintainer tool, not an installation/updater requirement.

Every prepared release includes its own fixed-pin installer. The front-page raw `main/install.sh` remains an independently reviewed pin: advancing it requires a separate ordinary PR using the exact released wheel's byte count and SHA, and does not happen automatically. Do not substitute a dry-run rebuild's checksum for the already published wheel's checksum.

## Further reading

- [Front page](../README.md) · [한국어 front page](../README.ko.md)
- [Design and runtime boundaries](../DESIGN.md)
- [Minimal example config](../config.example.json)
- [Logo asset](../assets/dotunnel.png) · [MIT License](../LICENSE)
- [OpenAI Secure MCP Tunnel documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
