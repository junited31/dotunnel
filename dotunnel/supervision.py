"""Bounded, best-effort terminal supervision; never infers task success."""
from __future__ import annotations

import asyncio
import base64
from collections.abc import Mapping, Sequence
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import pwd
import re
import signal
import time
from typing import Any, Protocol
import uuid

from .supervision_config import SupervisionError, SupervisionSettings, canonical_sha256, protected
from .supervision_state import SupervisionState

_KEYS = frozenset(('enter', 'esc', 'up', 'down', 'left', 'right', 'tab', 'y', 'n', *map(str, range(1, 10))))
_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))')
_OPERATION = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
_NAME = re.compile(r'[a-z][a-z0-9_-]{0,31}\Z')
JSON = dict[str, Any]


class Backend(Protocol):
    async def inventory(self, projects: Sequence[Any], records: Sequence[JSON], *, deadline: float) -> list[JSON]: ...
    async def read(self, target: JSON, lines: int, *, deadline: float) -> JSON: ...
    async def start(self, project: Any, profile: Any, name: str, worktree_branch: str | None, attempt: JSON, *, deadline: float) -> JSON: ...
    async def prompt(self, target: JSON, text: str, profile: Any, *, deadline: float) -> JSON: ...
    async def answer(self, target: JSON, keys: list[str], *, deadline: float) -> JSON: ...


def _invalid(reason: str) -> SupervisionError:
    return SupervisionError('invalid_request', reason=reason)


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _OPERATION.fullmatch(value):
        raise _invalid('invalid_identifier')
    return value


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise _invalid('text_type')
    try:
        size = len(value.encode('utf-8', 'strict'))
    except UnicodeError:
        raise _invalid('invalid_unicode') from None
    if not 1 <= size <= 8192 or any((ord(c) < 32 and c not in '\n\t') or 127 <= ord(c) < 160 for c in value):
        raise _invalid('text_bounds_or_controls')
    return value


def _keys(value: object) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8 or any(not isinstance(k, str) or k not in _KEYS for k in value):
        raise _invalid('invalid_keys')
    return value


def _screen(value: object) -> tuple[str, bool]:
    if not isinstance(value, str):
        raise SupervisionError('backend_unavailable', reason='invalid_screen')
    clean = _ANSI.sub('', value)
    clean = ''.join(c for c in clean if (ord(c) >= 32 and not 127 <= ord(c) < 160) or c in '\n\t')
    encoded = clean.encode('utf-8', 'replace')
    return encoded[-16384:].decode('utf-8', 'ignore'), len(encoded) > 16384


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


async def _cleanup(process: asyncio.subprocess.Process, *, close_transport: bool = True) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), 1.0)
    except asyncio.TimeoutError:
        pass
    finally:
        if close_transport:
            # Even an exited child can leave its pipes held by a detached process.
            transport = getattr(process, '_transport', None)
            if transport is not None:
                transport.close()


def _environment(extra_paths: Sequence[Path] = ()) -> dict[str, str]:
    home = pwd.getpwuid(os.getuid()).pw_dir
    paths = [str(path) for path in extra_paths] + ['/usr/bin', '/bin', home + '/.local/bin', home + '/.bun/bin']
    if any(not Path(path).is_absolute() or ':' in path for path in paths):
        raise _invalid('unsafe_executable_search_path')
    return {'HOME': home, 'PATH': ':'.join(dict.fromkeys(paths)), 'LANG': 'C.UTF-8', 'TERM': 'xterm-256color'}


async def run_cli(argv: Sequence[str], *, cwd: Path | None = None, deadline: float | None = None, input: bytes | None = None) -> tuple[int, bytes, bytes]:
    return await _run_cli(argv, cwd=cwd, deadline=deadline, input=input, environment=_environment())


async def _run_cli(argv: Sequence[str], *, cwd: Path | None, deadline: float | None, input: bytes | None, environment: Mapping[str, str]) -> tuple[int, bytes, bytes]:
    """Fixed argv only; bounded streaming output and child-owned process group."""
    if not argv or not Path(argv[0]).is_absolute():
        raise _invalid('absolute_executable_required')
    deadline = time.monotonic() + 20 if deadline is None else deadline
    if deadline <= time.monotonic():
        raise SupervisionError('backend_unavailable', reason='deadline')
    try:
        process = await asyncio.create_subprocess_exec(*argv, cwd=cwd, env=environment, stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    except OSError:
        raise SupervisionError('backend_unavailable', reason='launch_failed') from None
    size = 0
    async def drain(stream):
        nonlocal size
        chunks = []
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return b''.join(chunks)
            size += len(chunk)
            if size > 4 * 1024 * 1024:
                raise SupervisionError('backend_unavailable', reason='output_limit')
            chunks.append(chunk)
    async def communicate():
        assert process.stdout is not None and process.stderr is not None
        async def leader_exit():
            # Process.wait() may remain pending until inherited pipes reach EOF.
            while process.returncode is None:
                await asyncio.sleep(0.01)
            returncode = process.returncode
            assert returncode is not None
            return returncode
        stdout_task = asyncio.create_task(drain(process.stdout))
        stderr_task = asyncio.create_task(drain(process.stderr))
        exit_task = asyncio.create_task(leader_exit())
        tasks = (exit_task, stdout_task, stderr_task)
        try:
            if input is not None:
                assert process.stdin is not None
                process.stdin.write(input)
                await process.stdin.drain()
                process.stdin.close()
            pending = set(tasks)
            while exit_task in pending:
                completed, _ = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in completed:
                    pending.remove(task)
                    if task is not exit_task:
                        task.result()
            code = exit_task.result()
            # Kill ordinary helpers promptly, but keep the transports open while drains consume buffered bytes.
            await _cleanup(process, close_transport=False)
            stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
            return code, stdout, stderr
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    try:
        return await asyncio.wait_for(communicate(), max(0.001, deadline - time.monotonic()))
    except asyncio.TimeoutError:
        raise SupervisionError('backend_unavailable', reason='deadline') from None
    finally:
        # Ordinary request helpers remain ours even after the CLI exits.
        # Detached backend servers and agents have their own process groups.
        cleanup = asyncio.create_task(_cleanup(process))
        end = time.monotonic() + 1.0
        cancelled = False
        while not cleanup.done() and time.monotonic() < end:
            try:
                await asyncio.wait_for(asyncio.shield(cleanup), max(0.001, end - time.monotonic()))
            except asyncio.CancelledError:
                cancelled = True
            except asyncio.TimeoutError:
                break
        if not cleanup.done():
            cleanup.cancel()
            transport = getattr(process, '_transport', None)
            if transport is not None:
                transport.close()
        elif not cleanup.cancelled():
            cleanup.result()
        if cancelled:
            raise asyncio.CancelledError


class CliRunner:
    """One configured process pool; no polling when idle and no inherited secrets."""
    def __init__(self, extra_paths: Sequence[Path] = ()):
        self._environment = _environment(extra_paths)
        self.trusted_path = self._environment['PATH']
        self._slots = asyncio.Semaphore(4)
        self._calls: set[asyncio.Task[Any]] = set()
        self._closed = False

    async def __call__(self, argv: Sequence[str], *, cwd: Path | None = None, deadline: float | None = None, input: bytes | None = None) -> tuple[int, bytes, bytes]:
        deadline = time.monotonic() + 20 if deadline is None else deadline
        if self._closed or deadline <= time.monotonic():
            raise SupervisionError('backend_unavailable', reason='closed_or_deadline')
        task = asyncio.current_task()
        assert task is not None
        self._calls.add(task)
        acquired = False
        try:
            try:
                await asyncio.wait_for(self._slots.acquire(), max(0.001, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                raise SupervisionError('backend_unavailable', reason='deadline') from None
            acquired = True
            if self._closed:
                raise SupervisionError('backend_unavailable', reason='closed')
            return await _run_cli(argv, cwd=cwd, deadline=deadline, input=input, environment=self._environment)
        finally:
            if acquired:
                self._slots.release()
            self._calls.discard(task)

    async def aclose(self) -> None:
        self._closed = True
        tasks = tuple(task for task in self._calls if task is not asyncio.current_task())
        for task in tasks:
            task.cancel()
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 2.0)
            except asyncio.TimeoutError:
                pass


def build_backends(settings: SupervisionSettings, runner: CliRunner) -> dict[str, Backend]:
    from .herdr import HerdrBackend
    from .tmux import TmuxBackend
    return {key: (HerdrBackend if connection.backend == 'herdr' else TmuxBackend)(connection, runner) for key, connection in settings.connections.items()}


class Supervisor:
    def __init__(self, settings: SupervisionSettings, state: SupervisionState, backends: Mapping[str, Backend]):
        self.settings = settings
        self.state = state
        self.backends = backends
        self.discovery = {key: uuid.uuid4().hex for key in backends}

    def _sign(self, kind: str, value: JSON) -> str:
        body = base64.urlsafe_b64encode(_json(value)).decode().rstrip('=')
        signature = hmac.new(self.state.key, (kind + '.' + body).encode(), hashlib.sha256).hexdigest()
        return kind + '.' + body + '.' + signature

    def _open(self, kind: str, token: object) -> JSON:
        if not isinstance(token, str) or len(token) > 8192:
            raise _invalid('invalid_token')
        try:
            prefix, body, signature = token.split('.')
            expected = hmac.new(self.state.key, (prefix + '.' + body).encode(), hashlib.sha256).hexdigest()
            if prefix != kind or not hmac.compare_digest(signature, expected):
                raise ValueError
            value = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
            if not isinstance(value, dict) or value.get('epoch') != self.state.epoch:
                raise ValueError
            return value
        except (ValueError, UnicodeError, KeyError, TypeError):
            raise _invalid('invalid_token') from None

    def _handle(self, connection: str, row: JSON) -> str:
        identity = row.get('identity')
        if not isinstance(identity, dict) or not identity or len(_json(identity)) > 1536:
            raise SupervisionError('stale_target', reason='unverified_identity')
        return self._sign('t', {'epoch': self.state.epoch, 'generation': self.settings.generation, 'connection': connection, 'project': row['project'], 'native_id': row['native_id'], 'identity': identity, 'discovery': self.discovery[connection] if self.settings.connections[connection].backend == 'herdr' else None})

    def _diagnostics(self, exclude: str | None = None) -> JSON:
        result = self.state.unresolved_predecessors()
        if exclude is not None:
            ids = result['unresolved_predecessor_ids']
            result = dict(result, unresolved_predecessor_ids=[value for value in ids if value != exclude], unresolved_predecessor_count=max(0, result['unresolved_predecessor_count'] - 1))
        return dict(result, ordering='best_effort')

    def _protected(self, row: JSON) -> bool:
        project = self.settings.projects[row['project']]
        return project.protected or any(protected(Path(path), self.settings) for path in (str(project.path), row.get('cwd'), row.get('original_repo')) if path)

    def _current_record(self, record: JSON) -> bool:
        binding = record.get('binding', {})
        project = self.settings.projects.get(binding.get('project'))
        connection = self.settings.connections.get(binding.get('connection'))
        profile = self.settings.profiles.get(binding.get('profile'))
        return bool(record.get('epoch') == self.state.epoch and binding.get('generation') == self.settings.generation and project is not None and connection is not None and connection.id in project.connections and profile is not None and profile.id in project.profiles and connection.backend in profile.backends)

    def _profile(self, row: JSON):
        project = self.settings.projects[row['project']]
        connection = self.settings.connections[row['connection']]
        profile_id = row.get('profile')
        if profile_id is not None:
            profile = self.settings.profiles.get(profile_id)
            if profile is not None and profile_id in project.profiles and connection.backend in profile.backends:
                if connection.backend != 'herdr' or row['identity'].get('agent') == profile.kind:
                    return profile
            return None
        if connection.backend == 'herdr':
            candidates = [self.settings.profiles[key] for key in project.profiles if 'herdr' in self.settings.profiles[key].backends and self.settings.profiles[key].kind == row['identity'].get('agent')]
            return candidates[0] if len(candidates) == 1 else None
        return None

    async def _inventory(self, *, connection: str | None = None, project: str | None = None, deadline: float | None = None) -> tuple[list[JSON], list[JSON]]:
        if connection is not None:
            _identifier(connection)
        if project is not None:
            _identifier(project)
        if connection is not None and connection not in self.settings.connections or project is not None and project not in self.settings.projects:
            raise _invalid('unknown_filter')
        deadline = time.monotonic() + 18 if deadline is None else deadline
        records = [record for record in self.state.list_targets() if self._current_record(record)]
        async def one(key):
            projects = [p for p in self.settings.projects.values() if key in p.connections and (project is None or p.id == project)]
            try:
                scoped_records = [record for record in records if record['binding']['connection'] == key and (project is None or record['binding']['project'] == project)]
                rows = await asyncio.wait_for(self.backends[key].inventory(projects, scoped_records, deadline=deadline), max(0.001, deadline - time.monotonic()))
                normalized = []
                for row in rows:
                    p = self.settings.projects.get(row.get('project'))
                    if p is None or key not in p.connections or project is not None and p.id != project:
                        continue
                    if not isinstance(row.get('native_id'), str) or not row['native_id'] or len(row['native_id']) > 256:
                        continue
                    if row.get('process_state') not in ('running', 'exited', 'unknown') or row.get('agent_state') not in ('idle', 'working', 'blocked', 'done', 'unknown'):
                        raise SupervisionError('backend_unavailable', reason='invalid_state')
                    row = dict(row, connection=key)
                    profile = self._profile(row)
                    if profile is not None:
                        row['profile'] = profile.id
                    row['target'] = self._handle(key, row)
                    row['scope'] = key + ':' + p.id
                    row['protected'] = self._protected(row)
                    row['approved'] = self.state.approved(row['scope'], self.settings.generation)
                    writable = profile is not None and not row.get('readonly', False) and row['process_state'] == 'running' and not row['protected'] and row['approved']
                    row['capabilities'] = {'read': True, 'prompt': writable, 'answer': writable, 'ordering': 'best_effort'}
                    normalized.append(row)
                return normalized, None
            except (SupervisionError, asyncio.TimeoutError, OSError):
                self.discovery[key] = uuid.uuid4().hex
                return [], {'connection': key, 'error': {'code': 'backend_unavailable'}}
        keys = [connection] if connection else list(self.settings.connections)
        tasks = [asyncio.create_task(one(key)) for key in keys]
        try:
            results = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        rows = [row for group, _ in results for row in group]
        errors = [error for _, error in results if error]
        rows.sort(key=lambda row: (row['connection'], row['project'], row['native_id']))
        return rows, errors

    async def status(self, connection: str | None = None, project: str | None = None, cursor: str | None = None) -> JSON:
        started = time.monotonic()
        rows, errors = await self._inventory(connection=connection, project=project, deadline=started + 18)
        observed = {(row['connection'], row['project'], row['native_id'], canonical_sha256(row['identity'])) for row in rows}
        recoveries = []
        for record in self.state.list_targets():
            binding, native = record.get('binding', {}), record.get('native') or {}
            verified = (binding.get('connection'), binding.get('project'), native.get('native_id'), canonical_sha256(native.get('identity', {}))) in observed
            selected = (connection is None or binding.get('connection') == connection) and (project is None or binding.get('project') == project)
            if record.get('state') != 'active' or not self._current_record(record) or (selected and not verified):
                recoveries.append({'attempt_id': record['target_id'], 'operation_id': record['operation_id'], 'state': 'unknown', 'actionable': False})
        diagnostics = self._diagnostics()
        scopes = {key + ':' + p.id: self.state.approved(key + ':' + p.id, self.settings.generation) for p in self.settings.projects.values() for key in p.connections}
        snapshot = canonical_sha256({'generation': self.settings.generation, 'scopes': scopes, 'targets': rows, 'errors': errors, 'recovery': recoveries, **diagnostics})
        filters = canonical_sha256({'connection': connection, 'project': project})
        offset = 0
        if cursor is not None:
            old = self._open('c', cursor)
            if old.get('snapshot') != snapshot or old.get('filters') != filters:
                raise _invalid('cursor_stale')
            offset = old.get('offset')
            if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= len(rows):
                raise _invalid('invalid_cursor_offset')
        result: JSON = {'targets': [], 'errors': errors, 'recovery': recoveries[:32], 'recovery_count': len(recoveries), **diagnostics}
        for row in rows[offset:offset + 100]:
            result['targets'].append(row)
            end = offset + len(result['targets'])
            result['next_cursor'] = self._sign('c', {'epoch': self.state.epoch, 'snapshot': snapshot, 'filters': filters, 'offset': end}) if end < len(rows) else None
            if len(_json(result)) > 65536:
                result['targets'].pop()
                break
        end = offset + len(result['targets'])
        result['next_cursor'] = self._sign('c', {'epoch': self.state.epoch, 'snapshot': snapshot, 'filters': filters, 'offset': end}) if end < len(rows) else None
        if len(_json(result)) > 65536 or end == offset and end < len(rows):
            raise SupervisionError('backend_unavailable', reason='status_item_too_large')
        return result

    async def _resolve(self, target: str, *, deadline: float) -> JSON:
        binding = self._open('t', target)
        connection = binding.get('connection')
        if binding.get('generation') != self.settings.generation or connection not in self.settings.connections:
            raise SupervisionError('stale_target')
        if binding.get('discovery') is not None and binding['discovery'] != self.discovery[connection]:
            raise SupervisionError('stale_target')
        rows, errors = await self._inventory(connection=connection, project=binding.get('project'), deadline=deadline)
        if errors:
            raise SupervisionError('backend_unavailable')
        for row in rows:
            if row['native_id'] == binding.get('native_id') and row['identity'] == binding.get('identity'):
                return row
        raise SupervisionError('stale_target')

    async def _read(self, target: str, lines: int, *, deadline: float) -> JSON:
        row = await self._resolve(target, deadline=deadline)
        current = await self.backends[row['connection']].read(row, lines, deadline=deadline)
        if current.get('identity') != row['identity']:
            raise SupervisionError('stale_target')
        text, truncated = _screen(current.get('text'))
        state = {key: current.get(key, row[key]) for key in ('process_state', 'agent_state', 'state_source')}
        digest = canonical_sha256({'text': text, **state, 'identity': row['identity']})
        observation = self._sign('o', {'epoch': self.state.epoch, 'target': target, 'digest': digest, 'state': state, 'lines': lines, 'time': time.monotonic()})
        return {'target': target, 'text': text, 'truncated': truncated or bool(current.get('truncated')), 'observation': observation, **state}

    async def read(self, target: str, lines: int = 80) -> JSON:
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= 200:
            raise _invalid('invalid_lines')
        return await self._read(target, lines, deadline=time.monotonic() + 20)

    def _observation(self, target: str, observation: str) -> JSON:
        value = self._open('o', observation)
        observed = value.get('time')
        if value.get('target') != target or isinstance(observed, bool) or not isinstance(observed, (int, float)) or not 0 <= time.monotonic() - observed <= 60:
            raise SupervisionError('stale_observation')
        return value

    def _scope(self, scope: object):
        if not isinstance(scope, str) or scope.count(':') != 1:
            raise _invalid('invalid_scope')
        connection, project = scope.split(':')
        p = self.settings.projects.get(project)
        if connection not in self.settings.connections or p is None or connection not in p.connections:
            raise _invalid('unknown_scope')
        return connection, p

    async def approve(self, scope: str) -> JSON:
        _, project = self._scope(scope)
        if project.protected or protected(project.path, self.settings):
            raise SupervisionError('protected_target')
        async with self.state.lock():
            self.state.set_approval(scope, self.settings.generation, True)
            self.state.audit({'event': 'scope_approved', 'scope': scope, 'generation': self.settings.generation})
        return {'scope': scope, 'approved': True}

    async def revoke(self, scope: str) -> JSON:
        self._scope(scope)
        async with self.state.lock():
            self.state.set_approval(scope, self.settings.generation, False)
            self.state.audit({'event': 'scope_revoked', 'scope': scope, 'generation': self.settings.generation})
        return {'scope': scope, 'approved': False}

    def _admit(self, row: JSON) -> None:
        if row.get('readonly') or row.get('process_state') != 'running':
            raise SupervisionError('unsupported_operation', reason='readonly_or_exited')
        if self._protected(row):
            raise SupervisionError('protected_target')
        if not self.state.approved(row['scope'], self.settings.generation):
            raise SupervisionError('not_approved')

    async def _finalize(self, operation_id: str, result: JSON, attempt: JSON | None = None) -> bool:
        async def write():
            if attempt is not None and result.get('delivery') != 'confirmed':
                self.state.update_target(attempt['target_id'], 'unknown' if result.get('delivery') == 'unknown' else 'refused')
            self.state.finish(operation_id, result)
            self.state.audit({'event': 'dispatch_finished', 'operation_id': operation_id, 'delivery': result.get('delivery'), 'generation': self.settings.generation})
        task = asyncio.create_task(write())
        end = time.monotonic() + 1.0
        cancelled = False
        while not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), max(0.001, end - time.monotonic()))
            except asyncio.CancelledError:
                cancelled = True
                if time.monotonic() >= end:
                    task.cancel()
                    break
            except (asyncio.TimeoutError, OSError, SupervisionError):
                task.cancel()
                break
        success = False
        if task.done() and not task.cancelled():
            try:
                task.result()
                success = True
            except (OSError, SupervisionError):
                pass
        if cancelled:
            raise asyncio.CancelledError
        return success

    async def _input(self, action: str, target: str, observation: str, value: Any, operation_id: str) -> JSON:
        _identifier(operation_id)
        if not isinstance(target, str) or not isinstance(observation, str) or len(target) > 8192 or len(observation) > 8192:
            raise _invalid('invalid_token_type_or_length')
        _text(value) if action == 'prompt' else _keys(value)
        request = {'action': action, 'target': target, 'observation': observation, 'value': value}
        fingerprint = canonical_sha256(request)
        async with self.state.lock():
            historical = self.state.lookup_receipt(operation_id, fingerprint)
            if historical is not None:
                return historical
            old = self._observation(target, observation)
            deadline = time.monotonic() + 20
            row = await self._resolve(target, deadline=deadline)
            self._admit(row)
            fresh = await self._read(target, old['lines'], deadline=deadline)
            if self._open('o', fresh['observation'])['digest'] != old.get('digest'):
                raise SupervisionError('stale_observation')
            profile = self._profile(row)
            if profile is None:
                raise SupervisionError('unsupported_operation', reason='profile_unavailable')
            self.state.prepare(operation_id, fingerprint, {'connection': row['connection'], 'project': row['project'], 'profile': profile.id, 'generation': self.settings.generation, 'target': target})
            try:
                self.state.audit({'event': 'dispatch_prepared', 'action': action, 'operation_id': operation_id, 'connection': row['connection'], 'project': row['project'], 'profile': profile.id, 'generation': self.settings.generation})
                backend = self.backends[row['connection']]
                result = await backend.prompt(row, value, profile, deadline=deadline) if action == 'prompt' else await backend.answer(row, value, deadline=deadline)
                if result.get('delivery') not in ('confirmed', 'refused', 'unknown'):
                    result = {'delivery': 'unknown', 'error': {'code': 'delivery_unknown'}}
                result = dict(result, operation_id=operation_id, **self._diagnostics(exclude=operation_id))
            except BaseException as error:
                result = {'delivery': 'unknown', 'error': {'code': 'delivery_unknown'}, 'operation_id': operation_id, **self._diagnostics(exclude=operation_id)}
                await self._finalize(operation_id, result)
                if isinstance(error, asyncio.CancelledError):
                    raise
                if not isinstance(error, (SupervisionError, OSError, asyncio.TimeoutError)):
                    raise
                return result
            if not await self._finalize(operation_id, result):
                return {'delivery': 'unknown', 'error': {'code': 'delivery_unknown'}, 'operation_id': operation_id, **self._diagnostics(exclude=operation_id)}
            return result

    async def prompt(self, target: str, observation: str, text: str, operation_id: str) -> JSON:
        return await self._input('prompt', target, observation, text, operation_id)

    async def answer(self, target: str, observation: str, keys: list[str], operation_id: str) -> JSON:
        return await self._input('answer', target, observation, keys, operation_id)

    async def start(self, project: str, profile: str, name: str, operation_id: str, connection: str | None = None, worktree_branch: str | None = None) -> JSON:
        deadline = time.monotonic() + 180
        if connection is not None:
            _identifier(connection)
        _identifier(operation_id)
        _identifier(project)
        _identifier(profile)
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise _invalid('invalid_agent_name')
        if worktree_branch is not None and (not isinstance(worktree_branch, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,127}', worktree_branch) or '..' in worktree_branch or '@{' in worktree_branch):
            raise _invalid('invalid_branch')
        request = {'action': 'start', 'project': project, 'profile': profile, 'name': name, 'connection': connection, 'worktree_branch': worktree_branch}
        fingerprint = canonical_sha256(request)
        async with self.state.lock():
            historical = self.state.lookup_receipt(operation_id, fingerprint)
            if historical is not None:
                if historical.get('delivery') == 'unknown' and 'attempt_id' not in historical:
                    for record in self.state.list_targets():
                        if record['operation_id'] == operation_id:
                            historical = dict(historical, attempt_id=record['target_id'], actionable=False)
                            historical.pop('target', None)
                            break
                return historical
            connection = connection or self.settings.default_connection
            if connection is None and len(self.settings.connections) == 1:
                connection = next(iter(self.settings.connections))
            if connection is None:
                raise _invalid('ambiguous_connection')
            key, p = self._scope(str(connection) + ':' + project)
            c = self.settings.connections[key]
            profile_settings = self.settings.profiles.get(profile)
            if profile not in p.profiles or profile_settings is None or c.backend not in profile_settings.backends:
                raise SupervisionError('unsupported_operation', reason='profile_unavailable')
            if worktree_branch is not None and c.backend != 'herdr':
                raise SupervisionError('unsupported_operation', reason='worktree_requires_herdr')
            if p.protected or protected(p.path, self.settings):
                raise SupervisionError('protected_target')
            scope = key + ':' + project
            if not self.state.approved(scope, self.settings.generation):
                raise SupervisionError('not_approved')
            binding = {'connection': key, 'project': project, 'profile': profile, 'generation': self.settings.generation}
            self.state.check_target_capacity()
            self.state.prepare(operation_id, fingerprint, binding)
            attempt = None
            try:
                attempt = self.state.allocate_target(operation_id, binding)
                self.state.audit({'event': 'dispatch_prepared', 'action': 'start', 'operation_id': operation_id, 'attempt_id': attempt['target_id'], **binding})
                row = await self.backends[key].start(p, profile_settings, name, worktree_branch, attempt, deadline=deadline)
                if not row.get('native_id') or not row.get('identity') or row.get('delivery') == 'unknown' or row.get('process_state') != 'running':
                    result = {'delivery': 'unknown', 'error': {'code': 'delivery_unknown'}, 'attempt_id': attempt['target_id'], 'actionable': False}
                else:
                    row = dict(row, project=project, profile=profile, connection=key, managed=True, nonce=attempt['nonce'])
                    self.state.activate_target(attempt['target_id'], row)
                    result = {'delivery': 'confirmed', 'target': self._handle(key, row), 'process_state': row['process_state'], 'agent_state': row['agent_state'], 'state_source': row['state_source']}
                result = dict(result, operation_id=operation_id, **self._diagnostics(exclude=operation_id))
            except BaseException as error:
                result = {'delivery': 'unknown', 'error': {'code': 'delivery_unknown'}, 'operation_id': operation_id, 'recovery_id': operation_id, 'actionable': False, **self._diagnostics(exclude=operation_id)}
                if attempt is not None:
                    result['attempt_id'] = attempt['target_id']
                await self._finalize(operation_id, result, attempt)
                if isinstance(error, asyncio.CancelledError):
                    raise
                if not isinstance(error, (SupervisionError, OSError, asyncio.TimeoutError)):
                    raise
                return result
            if not await self._finalize(operation_id, result, attempt):
                return {'delivery': 'unknown', 'error': {'code': 'delivery_unknown'}, 'operation_id': operation_id, 'attempt_id': attempt['target_id'], 'actionable': False, **self._diagnostics(exclude=operation_id)}
            return result

    async def wait(self, target: str, observation: str, timeout_seconds: float = 60) -> JSON:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 0 <= timeout_seconds <= 110:
            raise _invalid('invalid_timeout')
        previous = self._observation(target, observation)
        end = time.monotonic() + timeout_seconds
        while True:
            latest = await self._read(target, previous['lines'], deadline=end + 10)
            current = self._open('o', latest['observation'])
            if latest['process_state'] == 'exited':
                reason = 'exited'
            elif current['state'] != previous['state']:
                reason = 'state_changed'
            elif current['digest'] != previous['digest']:
                reason = 'output_changed'
            elif time.monotonic() >= end:
                reason = 'timed_out'
            else:
                await asyncio.sleep(min(0.25, max(0, end - time.monotonic())))
                continue
            return dict(latest, reason=reason)
