# dotunnel-adapter-runner

A separately installed, stdlib-only fixed-task runner for operator-approved JSON-stdio adapters. It does not add MCP tools, load workspace plugins, ship a synthetic backend, or implement Herdr, Orca, tmux, or provider adapters. Those integrations and execution checks remain deferred. The common runner passed its 88-test suite and installed-wheel CLI/PTy/MCP smoke with a test-only synthetic backend.

## Install and register explicitly

Python3.11+ and a non-root Linux account are required. Build/install this optional distribution into its own virtualenv; installing base dotunnel does not install or enable it:

```sh
python3 -m venv "$HOME/.local/share/dotunnel-adapter/venv"
"$HOME/.local/share/dotunnel-adapter/venv/bin/python" -m pip install ./adapter_runner
```

This builds from the selected reviewed source. A separately built and reviewed optional wheel may be installed from its wheel path when available. Installing base dotunnel does not install or enable the runner; no service or task is automatically created.

Install a separately reviewed backend implementing the JSON-stdio contract below. Keep its executable, scripts, modules and dependencies outside the writable workspace. Resolve executable symlinks to a real absolute executable path; calculate its actual SHA-256. Its configured `digest` is `sha256:` followed by the64 lowercase hex digits, not an arbitrary version label.

Create owner-only config/state directories outside the workspace (`0700` directories, `0600` config). The following configuration is an **illustrative schema example**, not an installed backend or a ready-to-run host configuration. Replace its absolute paths and illustrative digest with the actual reviewed installation. The loader refuses invalid pins/paths rather than falling back:

```json
{
  "protocol": "dotunnel.adapter.config/1",
  "workspace": "/home/operator/adapter-workspace",
  "request": "adapter/pending.json",
  "reports": "adapter/reports",
  "state_dir": "/home/operator/private-adapter/state",
  "project": {
    "id": "selected-project",
    "generation": "project-1",
    "protected": false,
    "write_enabled": false,
    "operations": ["capabilities", "list_targets", "inspect", "read_output", "report"]
  },
  "backend": {
    "id": "reviewed-adapter",
    "generation": "adapter-1",
    "version": "1.0.0",
    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "argv": ["/home/operator/adapter-venv/bin/reviewed-json-adapter"],
    "timeout_seconds": 20
  }
}
```

The configuration registers one project/backend/request lane. Multiple fixed tasks use separate reviewed configurations, not caller-selected executables. Configuration and state must not overlap the workspace. The backend receives no inherited provider credentials/environment: its fixed cwd/HOME are the private state directory and PATH is `/usr/bin:/bin`. Any backend authentication/transport design is a separate operator concern, not a caller field.
The workspace cannot be `/` or the operator account's passwd home directory. A fixed task may set `HOME` to its workspace; that sanitized environment does not redefine the account-home restriction. Script/path arguments, including relative paths from the private state cwd and option values, cannot point into the writable workspace.


Initialize the private ownership state explicitly:

```sh
dotunnel-adapter-runner initialize --config /home/operator/private-adapter/config.json
```

Record the returned owner `{instance_id,epoch}` when constructing requests. Each invocation reuses that owner; initialization refuses to overwrite state. A missing/lost state database is not automatically recreated. Initializing a new state directory creates a fresh owner UUID, invalidating old requests/grants; do not replay effects from lost state without operator reconciliation.

Register one operator-defined dotunnel task with **absolute fixed argv**:

```json
{
  "name": "inspect_selected_adapter",
  "description": "Run one configured optional adapter request",
  "argv": [
    "/home/operator/.local/share/dotunnel-adapter/venv/bin/dotunnel-adapter-runner",
    "run",
    "--config",
    "/home/operator/private-adapter/config.json"
  ],
  "cwd": ".",
  "timeout_seconds": 40
}
```

The task timeout must exceed the configured whole backend-phase budget plus cleanup/state/report overhead. Each `run` shares one backend deadline across capabilities, inspection and dispatch; it does not allocate the full timeout anew for every phase. Core TaskRunner still supplies the outer deadline and admits one task globally. This example is documentation only: no operating task is registered by the package.

## Existing MCP file/task flow

1. Create the configured pending request with `write_file(..., expected_sha256=null)`. The request is UTF-8 JSON, at most 64 KiB; its paths are configured, never caller-supplied. At most one pending request per lane.
2. Invoke `run_task` with the fixed registered task name only.
3. Retain `result_id`; poll `get_task_result`. Do not resubmit a mutation just because the task result was lost.
4. Read the derived report file using the path in stdout's summary. Compare `read_file`'s SHA-256 with summary `sha256` before parsing it.

A summary is `{request_id,report,sha256}`; `sha256` is plain 64-hex. Reports carry `protocol=dotunnel.adapter/1`, matching request ID, outcome and full binding, plus capabilities/job/status/output/report or a fixed refusal code. Each report and its historical form must fit within 64 KiB; the runner reserves room for the maximum 64-character request ID, history markers, and target-binding variants. If a normalized mutation result cannot fit that budget, it records `outcome_unknown` rather than a result that cannot be replayed. `run` exits 0 for a successful read/accepted effect/recorded successful replay; a validated refusal or ambiguous effect exits 2 and still writes a bounded report. Invalid config/request errors use fixed codes on stderr; no backend stderr or arbitrary exceptions are forwarded.

Requests/reports are restricted to descriptor-rooted workspace regular files; links/special files and traversal are refused. Before claiming a request or admitting an effect, the runner validates/creates each report-directory component as owner-only `0700` and confirms the final report name is absent. On Linux, request claims and report publication use `renameat2(RENAME_NOREPLACE)` and fail closed if unavailable. A mismatched claim is restored to the pending path if it is still vacant; if another request has occupied that path, the bytes remain in private `.dotunnel-claims` quarantine rather than replacing it. Reports are written to a same-directory temporary file, fsynced, atomically published without replacement, and followed by a directory fsync; a failed temporary write leaves no partial final report. Publication failure does not undo a dispatched effect; mutation recovery uses the durable operation ID.

## Request schema

Every request contains `protocol`, `request_id`, `action`, `owner`, `project={id,generation}`, and `backend={id,generation}`. IDs are constrained strings; epoch/revisions are nonnegative safe integers where applicable, never bools/floats. Unknown fields, duplicate JSON keys, nonfinite numbers, lone Unicode surrogates and over-limit data are refused.

| Action | Additional fields |
| --- | --- |
| capabilities/list_targets | None |
| inspect | target |
| read_output | target; optional cursor/limit |
| report | target, job_id, attempt_id; optional cursor/revision (saved report only; any supplied value must match exactly; no live refresh) |
| start | target(kind profile), instruction |
| submit | target(kind agent/owned-job), instruction |
| answer | target, prompt={id,revision,choice} |
| cancel | target, job_id, attempt_id |

A target is `{kind,id,incarnation}`. Instructions are at most8192 UTF-8 bytes. All mutations also require `operation={id,fingerprint}` and `authorization={grant_id,action}`. Fingerprints are `sha256:<64hex>` over RFC8785 canonical JSON of action/project/backend/target and the action inputs, excluding request ID, owner, authorization and the operation itself. This protocol is integer-only; JSON numbers outside the exact IEEE754 safe integer range are rejected. Unicode strings are not normalized, and object keys sort by UTF-16 code units.

To compute a pending mutation's fingerprint locally, use:

```sh
dotunnel-adapter-runner fingerprint --config /home/operator/private-adapter/config.json
```

This validates a semantic request with its computed fingerprint; it does not modify or consume the pending file. The caller fills the returned fingerprint using the existing file SHA/CAS update. `run` and `approve` require the supplied fingerprint to match.

## Individual mutation consent

Project `write_enabled` and operation allowlists are opt-in policy, **not** permission to execute a particular request. Protected projects refuse every new mutation regardless of a previously issued grant.

Local operator approval is interactive only:

```sh
dotunnel-adapter-runner approve --config /home/operator/private-adapter/config.json --ttl-seconds 300
```

Both stdin/stdout must be a TTY. The CLI displays the exact inert request together with the private registry profile and its fingerprint, then asks `[y/N]`; Enter/No/EOF refuse. The profile fingerprint binds workspace, project policy, and configured backend ID/generation/version/digest/argv/timeout. The command probes the reviewed backend's capabilities/current target before presenting consent and verifies that the pending request/config did not change during confirmation.

Approval returns a `grant_id`; it does not dispatch or consume the request. The caller inserts `authorization={grant_id,action}` using `write_file` with the pending file's current SHA. The grant is not a bearer credential: private state binds owner/project/backend/target generations, exact action, operation ID/fingerprint and a finite expiry (maximum1hour). A different operation/payload/target cannot reuse it.

```sh
dotunnel-adapter-runner revoke --config /home/operator/private-adapter/config.json --grant-id GRANT_ID
```

Grant consumption and the prepared operation/job are committed together **before** backend dispatch. Revoking an unused grant prevents its admission. It does not undo an already admitted/dispatched effect. Identical recorded operation replay returns historical data without another backend call; changed fingerprint conflicts. A prepared/inflight record or ambiguous dispatch returns `outcome_unknown`, never an automatic retry. State is bounded (at most 1,000 rows per grants/operations/jobs table and database limits) and never evicts idempotency history; expired or revoked unused grants still count toward the grants cap. At capacity, new work/approval refuses until the operator reconciles state; there is no automatic pruning. Rotate ownership only explicitly after reconciling outstanding effects.

## Fixed JSON-stdio backend protocol

No backend is bundled. The common runner invokes only the exact operator-configured argv (`shell=False`) with one bounded JSON envelope on stdin. The executable must finish within the remaining whole-action deadline; stdout/stderr are drained concurrently and bounded. Stderr is discarded, not treated as a report. During ordinary cleanup, the runner kills/reaps its owned process group after normal exit too; this is not process/container/egress isolation. Linux parent-death signaling covers only the direct backend child: if the runner dies abruptly, descendants may continue, so an admitted mutation's outcome is unknown and must not be retried automatically.

Envelope:

```json
{
  "protocol": "dotunnel.adapter.backend/1",
  "phase": "capabilities",
  "request": {
    "protocol": "dotunnel.adapter/1",
    "request_id": "read-1",
    "action": "capabilities",
    "owner": {"instance_id": "example-owner", "epoch": 1},
    "project": {"id": "selected-project", "generation": "project-1"},
    "backend": {"id": "reviewed-adapter", "generation": "adapter-1"}
  },
  "context": {"owner": {"instance_id": "example-owner", "epoch": 1}}
}
```

The client authorization reference is removed before transmission. Context contains runner-assigned job/attempt IDs for a new mutation; cancel's target job/attempt remain in the request. Backend responses contain exact `protocol`, `phase`, `request_id`, `outcome` and full `binding` (owner/project/backend/target if present), plus phase data:

- `capabilities`: adapter id/version/digest matching config, nine operation booleans; identity booleans stable_target_id/target_incarnation/owned_process_identity/atomic_target_compare/prompt_compare_and_set; completion.authoritative_logical_result. Optional durable_idempotency boolean is informational; the common runner never auto-resends an ambiguous effect.
- `inspection`: exact target; optional prompt `{id,revision,choices}` and ownership `{owner,job_id,attempt_id}`. Mutation requires stable ID/incarnation plus backend-atomic expected-target comparison. Answer additionally requires exact prompt revision/choice and compare-and-set. Cancel additionally requires a persisted runner job/attempt and matching backend ownership.
- `result`: status, output and optional structured report/created target. Status distinguishes job_state from target_state and process `{state,exit_code/signal/identity}` and includes completion `{authoritative,source}`, observed_at UTC timestamp and revision. Output `{tail,truncated,cursor?}` is sanitized/bounded; the runner recomputes UTF-8 bytes/SHA. For start, return a created target of kind agent/owned-job.

Refusals/unknown replies use an allowlisted fixed `code`; arbitrary stderr/messages do not cross the boundary. A backend must compare expected target/prompt identity **inside dispatch before effects**, not merely echo inspected metadata. A generation change between inspection and dispatch must refuse. Capability booleans describe a reviewed contract; they are not proof against a malicious backend.

Only supported authoritative provider/owned-wrapper completion can report completed/failed/cancelled. Process exit0, terminal idle, heuristic prompts or silence become `outcome_unknown`, not logical success. TaskRunner completion only means the runner process finished; the report carries logical job state.

## Trust and compatibility limits

Configuration/state permissions restrict the MCP workspace caller, not the account owner or arbitrary same-UID code. The executable digest alone does not attest its interpreter, scripts, imported modules, or transitive dependencies. The consent profile fingerprint binds the configured argv and policy fields, but is not transitive dependency attestation; operators must review/pin the whole installed backend profile outside the workspace. There is no credential secrecy, sandbox, egress restriction, exactly-once external effects, generic terminal input or automatic provider compatibility guarantee. Output may contain prompt injection/secrets; byte/control filters are not redaction or authorization.

Herdr/Orca/tmux adapters are not installed/enabled here. No built-in discovery, workspace `orca.yaml`, PATH plugin search or provider credential copying exists. A guidance skill can explain the protocol but cannot mint consent or bypass registry policy.

## Contract tests

From repository root:

```sh
PYTHONPATH=adapter_runner/src python -m unittest discover -s adapter_runner/tests -t adapter_runner -v
```

Tests use an executable synthetic backend **under tests only** and real subprocess/SQLite/filesystem transitions: approval/refusal, replay/conflict/ambiguous effects, stale identities/prompts, protected policy, cancellation ownership, file replacement/escape and process/output bounds. They never call real providers or control existing sessions. Worker/CI routing follows the repository's project policy; do not run heavy checks on the coordinator.
