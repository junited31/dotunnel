"""In-memory permission draft and operator-visible review for setup."""

from __future__ import annotations

import copy
import shutil
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .file_access import FileAccess


@dataclass(frozen=True)
class Draft:
    directory: Path
    workspace: Path
    create_workspace: bool
    generation: str
    file_access: dict[str, list[dict[str, str]]]
    supervision: dict[str, Any] | None
    jobs: frozenset[str]
    requests: tuple[str, ...]
    legacy: bool


def _prompt(prompt_fn: Callable[[str], str] | None, label: str) -> str:
    value = (input if prompt_fn is None else prompt_fn)(label)
    if not isinstance(value, str):
        raise ValueError("A text value is required; nothing was changed")
    return value.strip()


def confirm(prompt_fn: Callable[[str], str] | None, label: str, *, default: bool = False) -> bool:
    value = _prompt(prompt_fn, label).casefold()
    if not value:
        return default
    if value in ("y", "yes"):
        return True
    if value in ("n", "no"):
        return False
    raise ValueError("Answer yes or no; no permission was changed")


def _absolute(value: str, label: str) -> Path:
    try:
        path = Path(value)
        if not path.is_absolute() or ".." in path.parts or "\x00" in value:
            raise ValueError
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError
        return Path(os.path.normpath(os.fspath(path)))
    except (TypeError, ValueError, UnicodeError):
        raise ValueError(f"Enter an absolute, non-traversing {label} path") from None


def collect_rules(prompt_fn: Callable[[str], str] | None, label: str) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    while True:
        path = _prompt(prompt_fn, f"{label} relative path (empty finishes): ")
        if not path:
            return rules
        kind = _prompt(prompt_fn, "Exact file or directory tree [file/tree]: ").casefold()
        candidate = rules + [{"path": path, "kind": kind}]
        FileAccess.parse({"read": candidate, "write": []})
        rules = candidate


def _rule_document(policy: FileAccess) -> dict[str, list[dict[str, str]]]:
    def values(rules):
        return [{"path": "." if not rule.parts else "/".join(rule.parts), "kind": rule.kind} for rule in rules]
    return {"read": values(policy.read), "write": values(policy.write)}


def _workspace(prompt_fn, directory: Path, current_root: Path | None, *, existing_setup: bool) -> tuple[Path, bool, Path]:
    if existing_setup:
        choice = _prompt(prompt_fn, "Workspace mode [k]eep current / [n]ew dedicated / [e]xisting project (default k): ").casefold() or "k"
        if choice == "k":
            if current_root is None:
                raise ValueError("Existing setup has no usable workspace root")
            root, create = current_root, False
        elif choice == "n":
            raw = _prompt(prompt_fn, f"New workspace directory (absolute; default {directory / 'workspace'}): ")
            root, create = (_absolute(raw, "workspace") if raw else directory / "workspace"), True
        elif choice == "e":
            root, create = _absolute(_prompt(prompt_fn, "Existing project directory (absolute): "), "project"), False
        else:
            raise ValueError("Choose keep, new, or existing project; nothing was changed")
    else:
        choice = _prompt(prompt_fn, "Workspace mode [n]ew dedicated / [e]xisting project (default n): ").casefold() or "n"
        if choice == "n":
            raw = _prompt(prompt_fn, f"New workspace directory (absolute; default {directory / 'workspace'}): ")
            root, create = (_absolute(raw, "workspace") if raw else directory / "workspace"), True
        elif choice == "e":
            root, create = _absolute(_prompt(prompt_fn, "Existing project directory (absolute): "), "project"), False
        else:
            raise ValueError("Choose new or existing project; nothing was changed")
    if not root.is_absolute() or ".." in root.parts or root in (Path("/"), Path.home()):
        raise ValueError("Use an explicit workspace, not filesystem root or home")
    if create:
        if os.path.lexists(root):
            raise ValueError("New workspace path already exists; choose an existing-project option instead")
        if root.parent != directory:
            try:
                from .setup import _trusted_parent
                parent_fd = _trusted_parent(root.parent)
                os.close(parent_fd)
            except (OSError, TypeError, ValueError):
                raise ValueError("New workspace parent must already exist and be protected from other users' writes") from None
    else:
        from .config import _open_absolute
        fd = _open_absolute(root, os.O_RDONLY | os.O_DIRECTORY)
        os.close(fd)
    if not create and directory.is_relative_to(root):
        if existing_setup:
            raise ValueError("The existing private setup is inside this project; it cannot be moved with its credentials")
        replacement = _absolute(_prompt(prompt_fn, "Choose an external private setup directory (absolute): "), "private setup")
        if replacement.is_relative_to(root) or root.is_relative_to(replacement) or os.path.lexists(replacement):
            raise ValueError("Private setup and project must remain separate; no credential was moved")
        directory = replacement
    if (directory / "config.json").is_relative_to(root):
        raise ValueError("Private setup configuration must remain outside the writable project")
    if not create and stat.S_IMODE(root.stat(follow_symlinks=False).st_mode) != 0o700:
        print("This existing project is not an operator-owned 0700 workspace. It will not be chmodded; fixed native CLI jobs are unavailable for this root.")
    return root, create, directory


def _file_access(prompt_fn, current: dict[str, Any] | None, *, legacy: bool) -> dict[str, list[dict[str, str]]]:
    if current is not None:
        policy = FileAccess.parse(current)
        if legacy and policy.allows("read", ()) and policy.allows("write", ()):
            print("Legacy configuration includes whole-workspace tree read/write access. It will be preserved unless you explicitly narrow it.")
        if confirm(prompt_fn, "Keep the existing MCP read/write rules exactly? [Y/n]: ", default=True):
            return _rule_document(policy)
    return _rule_document(FileAccess.parse({"read": collect_rules(prompt_fn, "MCP read"), "write": collect_rules(prompt_fn, "MCP write")}))


def _actions(value: str, allowed: set[str], label: str) -> list[str]:
    if not value:
        return []
    values = [part.strip() for part in value.split(",")]
    if any(not item for item in values) or len(values) != len(set(values)) or not set(values) <= allowed:
        raise ValueError(f"Invalid {label} selection; no permission was changed")
    return [item for item in ("read", "start", "prompt", "answer") if item in values]


def _choices(value: str, allowed: set[str], label: str) -> list[str]:
    if not value:
        return []
    values = [part.strip() for part in value.split(",")]
    if any(not item for item in values) or len(values) != len(set(values)) or not set(values) <= allowed:
        raise ValueError(f"Invalid {label} selection; no permission was changed")
    return values


def _has_live_mutations(supervision: dict[str, Any]) -> bool:
    mutation_actions = {"start", "prompt", "answer"}
    return any(
        not project.get("protected", False)
        and any(mutation_actions & set(project.get("allowed_actions", [])) & set(actions)
                for actions in project.get("profile_actions", {}).values())
        for project in supervision.get("projects", [])
    )


def _confirm_live_mutation_risk(prompt_fn, supervision: dict[str, Any]) -> None:
    if not _has_live_mutations(supervision):
        return
    print("Live profile actions use the native agent's OS filesystem and authentication boundary, not MCP file_access or fixed-job isolation.")
    if not confirm(prompt_fn, "I explicitly accept this live external-boundary risk for the selected mutations? [y/N]: ", default=False):
        raise ValueError("Live mutation grants require explicit external-boundary risk acknowledgment")


def _live_configuration(prompt_fn, root: Path, existing: dict[str, Any] | None, directory: Path,
                       generation: str, *, legacy: bool) -> dict[str, Any] | None:
    from . import integrations

    if existing is not None and confirm(
        prompt_fn, "Keep existing live connections, projects, profiles, and action grants unchanged? [Y/n]: ",
        default=True,
    ):
        value = copy.deepcopy(existing)
        profiles = value.get("profiles", [])
        old_projects = [project for project in value.get("projects", []) if legacy and "allowed_actions" not in project]
        if old_projects:
            print("Legacy live project permissions are converted to explicit observation-only read grants; no profile mutations are inferred.")
            for project in old_projects:
                project["allowed_actions"] = ["read"]
                project["profile_actions"] = {profile_id: [] for profile_id in project.get("profiles", [])}
        old_profiles = [profile for profile in profiles if legacy and "executable_policy" not in profile]
        if old_profiles:
            print("Legacy live profiles used implicit strict executable checks; choose their converted executable policy.")
            answer = _prompt(prompt_fn, "Effective policy [c]ompatible/[s]trict (default c): ").casefold()
            if answer not in ("", "c", "compatible", "s", "strict"):
                raise ValueError("Choose compatible or strict; nothing was changed")
            policy = "strict" if answer in ("s", "strict") else "compatible"
            for profile in old_profiles:
                profile["executable_policy"] = policy
        from .supervision_config import _trusted_executable
        for profile in profiles:
            policy = profile.get("executable_policy", "compatible")
            try:
                profile["executable"] = str(_trusted_executable(Path(profile["executable"]).resolve(strict=True), root, policy=policy))
            except (OSError, RuntimeError, TypeError, ValueError):
                raise ValueError("A live profile executable is unavailable or unsafe; nothing was changed") from None
        _confirm_live_mutation_risk(prompt_fn, value)
        return value
    if existing is not None:
        if not confirm(prompt_fn, "Configure replacement live supervision? [y/N]: ", default=False):
            return None
    elif not confirm(prompt_fn, "Configure live agent supervision (separate from fixed isolated CLI jobs)? [y/N]: ", default=False):
        return None

    from .supervision_config import _trusted_executable
    candidates: dict[str, Path] = {}
    for kind in ("codex", "claude", "omp"):
        candidate = shutil.which(kind)
        if candidate is None:
            continue
        try:
            candidates[kind] = _trusted_executable(Path(candidate).resolve(strict=True), root, policy="compatible")
        except (OSError, RuntimeError, TypeError, ValueError):
            continue
    connections_by_backend: dict[str, Path] = {}
    for backend in ("herdr", "tmux"):
        candidate = shutil.which(backend)
        if candidate is not None:
            resolved = integrations._inspect_launcher(candidate)
            if resolved is not None:
                connections_by_backend[backend] = resolved
    if not candidates or not connections_by_backend:
        raise ValueError("Live supervision requires a trusted agent CLI profile and Herdr or tmux executable")
    print("Trusted live profile candidates (metadata only; no native CLI is run):")
    for kind, executable in candidates.items():
        info = executable.stat(follow_symlinks=False)
        print(f"  {kind}: {executable} mode={stat.S_IMODE(info.st_mode):04o} links={info.st_nlink}")
    selected_backends = _choices(_prompt(prompt_fn, "Strict backend connections to configure (comma-separated herdr,tmux; empty disables): "),
                                 {"herdr", "tmux"}, "connection")
    if not set(selected_backends) <= set(connections_by_backend):
        raise ValueError("A selected live backend executable is unavailable or unsafe")
    if not selected_backends:
        return None
    connections = []
    for backend in selected_backends:
        item: dict[str, Any] = {"id": f"{backend}-main", "backend": backend, "executable": str(connections_by_backend[backend])}
        if backend == "herdr":
            session = _prompt(prompt_fn, "Herdr session selector (empty uses local): ")
            if session:
                item["session"] = session
        else:
            socket = _prompt(prompt_fn, f"Fixed tmux socket path (absolute; default /tmp/tmux-{os.getuid()}/default): ")
            item["socket"] = socket or f"/tmp/tmux-{os.getuid()}/default"
        connections.append(item)
    print("Available live profile kinds: " + ", ".join(sorted(candidates)))
    kinds = _choices(_prompt(prompt_fn, "Live profile kinds to register (comma-separated): "), set(candidates), "profile")
    if not kinds:
        return None
    profiles = []
    for kind in kinds:
        answer = _prompt(prompt_fn, f"{kind} live executable policy [c]ompatible/[s]trict (default c): ").casefold()
        if answer not in ("", "c", "compatible", "s", "strict"):
            raise ValueError("Choose compatible or strict; nothing was changed")
        policy = "strict" if answer in ("s", "strict") else "compatible"
        executable = _trusted_executable(candidates[kind], root, policy=policy)
        profiles.append({"id": f"{kind}-interactive", "kind": kind, "executable": str(executable),
                         "args": [], "backends": selected_backends, "executable_policy": policy})
    project_path = _absolute(_prompt(prompt_fn, "Live agent project directory (existing absolute path): "), "live project")
    from .config import _open_absolute
    project_fd = _open_absolute(project_path, os.O_RDONLY | os.O_DIRECTORY)
    os.close(project_fd)
    project_id = _prompt(prompt_fn, "Live project identifier (letters, digits, underscore, hyphen; default workspace): ") or "workspace"
    if not project_id.isascii() or not project_id.replace("_", "a").replace("-", "a").isalnum() or not 1 <= len(project_id) <= 64:
        raise ValueError("Live project identifier is invalid")
    allowed = _actions(_prompt(prompt_fn, "Project allowed actions (read,start,prompt,answer; empty means none): "),
                       {"read", "start", "prompt", "answer"}, "project action")
    profile_actions = {}
    for profile in profiles:
        actions = _actions(_prompt(prompt_fn, f"Actions for {profile['id']} (start,prompt,answer; empty means none): "),
                           {"start", "prompt", "answer"}, "profile action")
        if not set(actions) <= set(allowed) or (set(actions) & {"prompt", "answer"} and "read" not in allowed):
            raise ValueError("Per-profile actions exceed the project action ceiling")
        profile_actions[profile["id"]] = actions
    protected = confirm(prompt_fn, "Mark this live project protected/read-only? [y/N]: ", default=False)
    if protected and (set(allowed) - {"read"} or any(profile_actions.values())):
        raise ValueError("A protected live project cannot receive mutation grants")
    supervision = {
        "state_dir": str(existing["state_dir"] if existing is not None else directory / "supervision" / generation),
        "connections": connections, "projects": [{
            "id": project_id, "path": str(project_path),
            "connections": [item["id"] for item in connections],
            "profiles": [item["id"] for item in profiles],
            "allowed_actions": allowed, "profile_actions": profile_actions, "protected": protected,
        }], "profiles": profiles,
    }
    _confirm_live_mutation_risk(prompt_fn, supervision)
    return supervision


def collect_draft(prompt_fn, *, directory: Path, current_root: Path | None, current_file_access: dict[str, Any] | None,
                  current_supervision: dict[str, Any] | None, existing_setup: bool, legacy: bool,
                  selected_jobs: set[str] | frozenset[str], generation: str) -> Draft:
    root, create_workspace, directory = _workspace(prompt_fn, directory, current_root, existing_setup=existing_setup)
    access = _file_access(prompt_fn, current_file_access, legacy=legacy)
    supervision = _live_configuration(prompt_fn, root, current_supervision, directory, generation, legacy=legacy)
    return Draft(directory, root, create_workspace, generation, access, supervision, frozenset(selected_jobs), (), legacy)


def validate_draft_document(draft: Draft, document: dict[str, Any], config_path: Path) -> None:
    """Validate the complete explicit-policy setup without materializing future paths."""
    if "file_access" not in document:
        raise ValueError("Legacy setup conversion requires an explicit file-access policy")
    if document.get("file_access") != draft.file_access:
        raise ValueError("Setup document does not match the reviewed file-access draft")
    from .config import _parse_setup_draft_document
    _parse_setup_draft_document(document, config_path, future_workspace=draft.create_workspace)

def add_request_grants(access: dict[str, list[dict[str, str]]], requests: tuple[str, ...]) -> dict[str, list[dict[str, str]]]:
    FileAccess.parse(access)
    updated = {key: [dict(rule) for rule in rules] for key, rules in access.items()}
    for request in requests:
        for action in ("read", "write"):
            if not any(rule.get("path") == request and rule.get("kind") == "file" for rule in updated[action]):
                updated[action].append({"path": request, "kind": "file"})
    return _rule_document(FileAccess.parse(updated))


def print_summary(draft: Draft, *, tasks: list[dict[str, Any]], job_details: list[dict[str, Any]],
                  removed_jobs: list[dict[str, str]], key_reference: Path) -> None:
    print("\nPermission draft (nothing has been created, saved, or connected):")
    print(f"  MCP workspace: {draft.workspace} ({'new 0700 directory' if draft.create_workspace else 'existing directory; mode/owner unchanged'})")
    for action in ("read", "write"):
        rules = draft.file_access[action]
        print(f"  MCP {action}: " + ("; ".join(f"{rule['kind']} {rule['path']}" for rule in rules) if rules else "none"))
    if draft.requests:
        print("  Request control files with exact MCP read and write rules:")
        for request in draft.requests:
            print(f"    {draft.workspace / request}")
    print(f"  Private Tunnel key file: {key_reference} (existing reference preserved or created after approval; value is never shown)")
    if job_details:
        print("  Fixed isolated native CLI jobs:")
        for item in job_details:
            print(f"    {item['backend']}: source={item['root']} files={item['files']} editable={item['editable']}")
    else:
        print("  Fixed isolated native CLI jobs: none selected")
    if removed_jobs:
        print("  Setup-owned CLI task registrations removed or replaced:")
        for item in removed_jobs:
            print(f"    {item['backend']}: prior workspace={item['workspace']}")
    if draft.supervision:
        print("  Live supervision (native agent OS filesystem/authentication boundary):")
        print(f"    state path={draft.supervision['state_dir']}; a new state is initialized only after separate approval")
        for project in draft.supervision.get("projects", []):
            print(f"    project {project['id']} path={project['path']} protected={project.get('protected', False)} allowed_actions={project['allowed_actions']} profile_actions={project['profile_actions']}")
        for connection in draft.supervision.get("connections", []):
            print(f"    connection {connection['id']} backend={connection['backend']} executable={connection['executable']} session={connection.get('session')} socket={connection.get('socket')} read_targets={connection.get('read_targets', [])}")
        for profile in draft.supervision.get("profiles", []):
            executable = Path(profile["executable"])
            try:
                info = executable.stat(follow_symlinks=False)
                mode, links = stat.S_IMODE(info.st_mode), info.st_nlink
                metadata = f"mode={mode:04o} links={links}"
            except OSError:
                mode, links = 0, 0
                metadata = "metadata unavailable"
            policy = profile.get("executable_policy", "compatible")
            risk = " RISK: compatible permits shared-inode or writable executable code to tamper with native-agent code and auth." if policy == "compatible" else ""
            print(f"    profile {profile['id']} kind={profile['kind']} executable={executable} args={profile.get('args', [])} backends={profile.get('backends', ['herdr', 'tmux'])} policy={policy} {metadata}.{risk}")
        print("  Operator action grants do not approve runtime scopes or native confirmation dialogs.")
        print("  Runtime scope approvals and native confirmations remain separate.")
    else:
        print("  Live supervision: none selected; no agent actions are authorized")
    print("  Registered task commands (general tasks preserved; argv and cwd are not constrained by MCP file_access):")
    for task in tasks:
        print(f"    {task.get('name')}: argv={task.get('argv')} cwd={task.get('cwd', '.')} timeout={task.get('timeout_seconds', 60)}")
    print("  Saved permissions take effect only when a new MCP process starts.")
    print("  Tunnel connection start is a separate default-No choice after saving and doctor.")
