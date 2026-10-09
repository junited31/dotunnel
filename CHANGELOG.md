# Changelog

## 0.1.6 (2026-10-09)

- Integrate workspace file-access and optional CLI/live-agent permission selection into interactive setup. New MCP read and write rules start empty; exact-file and directory-tree rules are explicit, writes must remain within read access, and file listing/search respects the read rules.
- Distinguish fixed Bubblewrap CLI candidate jobs from live Herdr/tmux agents, which retain the native agent's OS and authentication authority. Live profile `compatible` executable policy is the default and may allow writable or shared-inode executable code; `strict` remains selectable.
- Give live projects an action ceiling and profiles separate mutation grants, both empty for new setup; these setup-time permissions do not approve runtime scopes or start agents. Require a default-No final review before key input/artifact generation, atomically publish configuration last, and keep new supervision-state initialization and Tunnel connection startup separate. Report publication state and any remaining private preparation paths on errors; report uncertain foreground startup as potentially attempted.
- Make legacy migration explicit and fail closed when an existing local client is active or its state is unknown. Translate old supervision rights and preserve legacy whole-workspace read/write access unless the operator narrows it during review; require separate confirmation that no other client is using the Tunnel. Runtime configuration now requires `file_access`: migrate older configurations before restarting with 0.1.6; package installation alone does not migrate them.
- Allow explicitly reviewed unregistration of unavailable setup-owned CLI jobs without deleting prior artifacts; keep registrations by default when optional integration configuration is skipped. Validate retained jobs against the reviewed workspace and recheck persisted supervision authority read-only before publication. Preserve referenced artifacts when initial publication is unconfirmed, and show safe manual-start/registration guidance on saved-but-not-started paths.
- Include every prospective registered task's effective command in the final permission review, retain the foreground launcher's clean environment in manual startup commands, and align CLI help with integrated permission migration.
- Advance the stable installer and bilingual manual-install examples to the published 0.1.6 wheel, pinned to 142242 bytes and SHA-256 `17f5c95c215f29028bf9a7ce8b563a8bf5e013437b55c61179d5952979f79de1`; preserve already-published release assets.

## 0.1.5 (2026-10-08)

- Advance the default installer and bilingual manual-install examples to the published `0.1.5` wheel, pinned to 123908 bytes and SHA-256 `5b617552d1d9dbaabd4209a99f42c4a25e7757fad8c3e9a0e684d9f01a949810`. Existing installations, services, credentials and `0.1.4` release assets remain unchanged.
- Align package metadata and the public module version at `0.1.5`. Existing `0.1.4` release assets remain unchanged.
- Add optional core Herdr/tmux supervision through an explicit fixed project/profile/connection registry. The base seven file/task tools stay unchanged; one shared set of eight `agent_*` tools is added only when enabled (15 total), with no broadcast or automatic fallback.
- Require explicit `dotunnel supervision init/reinit` for owner-only state outside the writable root. Scope approval binds `connection_id:project_id` and the active configuration generation; opaque handles and fresh signed observations bind writes to current identity. Herdr may provide weak process identity, while tmux writes are limited to managed agents with recorded and rechecked native identity; exact existing pane registrations remain read-only.
- Persist operation receipts and recovery diagnostics. Exact `operation_id` replay does not repeat effects, changed payloads conflict, and an `unknown` outcome or recovery record is never an actionable target or reason for blind retry. Bound status/screens, four-way CLI concurrency and operation deadlines.
- Preserve literal executable paths for empty-argument tmux profiles with a fixed exec launcher rather than tmux's single-word shell interpretation. Normalize readonly registration PID/start-time strings to native integer identity fields; registered readonly panes never acquire input permission.
- Remove only the owned atomic-write temporary file on pre-rename failures so transient persistence errors fail closed without preventing namespace reopening or explicit reinitialization. Preserve prior durable data and exact historical receipts.
- Return compact SDK TextContent with matching structured content so the actual encoded status page, including cursors and diagnostics, remains at most 64 KiB.
- Serialize namespace creation and explicit rotation with a persistent private per-state parent owner file, retaining the guard across the active-name rename gap and rollback. Pre-created private state under a non-writable parent remains initializable without permitting missing-root creation or bypassing an existing unsafe guard.
- Permit explicit reinitialization to archive one bounded, owner-only atomic staging file left by SIGKILL, without trusting or promoting it on startup. Malformed or unsafe staging entries remain refused.
- Report and recheck tmux's verified live working directory for protected-path admission; unavailable working directories fail closed. Preserve quoted arguments in supported `env -S` shebangs.
- Observe CLI leader exit independently of inherited stdout/stderr EOF, terminate ordinary owned-group helpers promptly, and finish bounded drains before transport closure. Successful output and cancellation cleanup remain intact; separately detached backend agents remain running.
- Publish regression fixture PID and SIGKILL staging markers atomically, so readiness checks cannot observe incomplete diagnostic contents.
- Add the separately installed `dotunnel-adapter-runner` common JSON-stdio runner with fixed private registry profiles, strict typed requests/reports, local per-operation consent, durable ownership/replay, and protected-project refusal. It uses the existing seven MCP tools and is not enabled by base setup.
- Publish runner reports atomically without replacement, reserve the complete bounded history frame, and preserve unknown outcomes after admitted effects/signals/state failures. Its synthetic tests and installed CLI/PTy/MCP smoke cover consent, one-effect replay, stale/revoked/protected refusal and ambiguous recovery; the standalone runner ships no Herdr/Orca/tmux/provider adapters. Core Herdr/tmux supervision is separate, and Orca remains unavailable.
- Prepare stable-tag GitHub Release drafts through exact-source/main-CI validation, read-only wheel preparation and a separate narrowly privileged asset attachment job; publication remains manual.
- Provide read-only manual release dry-runs, checksum/source manifests and release-specific fixed-pin installers without rewriting the main installer pin or existing Release assets.
- Document the protected-main publication flow and the distinction between preparation verification and live draft/publication verification.

## 0.1.4

- Add a one-line Linux installer for the pinned 0.1.4 release. It verifies the wheel's size and SHA-256 before isolated, binary-only installation into a user-owned virtualenv, and refuses existing installations or unrelated launchers.
- Keep a completed virtualenv and its launcher together even if printing the final installation message fails.
- Shorten both READMEs to quickstarts and move detailed installation, account, Tunnel, task and CLI guidance into bilingual guides. The repository is now public; fresh installation and manual wheel downloads require no GitHub login.
- Keep existing release wheels unchanged; no credentials, connections or services are changed by installation.
- Add an opt-in staged-only Gitleaks pre-commit guard that refuses commits on detection, scanner absence or errors; document private development and detector limitations, and ignore private runtime paths.
- Run secret scanning, Python 3.11/3.13 regression tests, wheel builds and installed CLI checks on isolated GitHub-hosted Ubuntu CI runners, with read-only permissions and immutable action/checksum pins.
- Remove the updater's GitHub CLI/login dependency. Fetch public release metadata and wheel assets anonymously over HTTPS using Python's standard library; retain bounded responses, HTTPS-only redirects, wheel identity/size/SHA checks and interactive approval.

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
