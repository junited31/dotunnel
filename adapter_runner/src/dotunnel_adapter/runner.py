"""One fixed request lane; logical completion lives in bounded report files."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import signal
import time
import uuid
from typing import Any

from .backend import invoke
from .configuration import RunnerConfig, load_config, profile_fingerprint
from .filesystem import Workspace
from .protocol import (
    RunnerError, binding, canonical_json, decode_json, normalize_result,
    validate_capabilities, validate_inspection, validate_request,
)
from .state import Store


MUTATIONS = frozenset({'start', 'submit', 'answer', 'cancel'})


def check_registration(request: dict[str, Any], config: RunnerConfig, owner: dict[str, Any],
                       *, historical: bool = False) -> None:
    if request['owner'] != owner:
        raise RunnerError('stale_target')
    if request['project']['id'] != config.project['id']:
        raise RunnerError('protected_project')
    if request['backend']['id'] != config.backend['id']:
        raise RunnerError('backend_unavailable')
    if not historical and (
        request['project']['generation'] != config.project['generation']
        or request['backend']['generation'] != config.backend['generation']
    ):
        raise RunnerError('stale_target')


def _policy(request: dict[str, Any], config: RunnerConfig) -> None:
    action = request['action']
    if action not in config.project['operations']:
        raise RunnerError('unsupported')
    if action in MUTATIONS:
        if config.project['protected']:
            raise RunnerError('protected_project')
        if not config.project['write_enabled']:
            raise RunnerError('approval_required')


def _base(request: dict[str, Any], outcome: str = 'ok') -> dict[str, Any]:
    return {'protocol': 'dotunnel.adapter/1', 'request_id': request['request_id'],
            'outcome': outcome, 'binding': binding(request)}


def _refused(request: dict[str, Any], code: str) -> dict[str, Any]:
    report = _base(request, 'refused')
    report['code'] = code
    return report


def exchange(config: RunnerConfig, request: dict[str, Any], phase: str,
             deadline: float, context: dict[str, Any] | None = None) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RunnerError('resource_limit')
    transmitted = deepcopy(request)
    transmitted.pop('authorization', None)
    context = dict(context or {'owner': request['owner']})
    envelope = {'protocol': 'dotunnel.adapter.backend/1', 'phase': phase,
                'request': transmitted, 'context': context}
    response = invoke(tuple(config.backend['argv']), envelope,
                      cwd=config.state_dir, timeout_seconds=remaining)
    allowed = {'protocol', 'phase', 'request_id', 'outcome', 'binding',
               {'capabilities': 'capabilities', 'inspect': 'inspection',
                'dispatch': 'result'}[phase], 'code'}
    if (
        not isinstance(response, dict) or set(response) - allowed
        or response.get('protocol') != 'dotunnel.adapter.backend/1'
        or response.get('phase') != phase
        or response.get('request_id') != request['request_id']
        or response.get('binding') != binding(request)
        or response.get('outcome') not in ('ok', 'refused', 'unknown')
    ):
        raise RunnerError('backend_unavailable')
    if response['outcome'] != 'ok':
        code = response.get('code')
        if not isinstance(code, str) or code not in {'unsupported', 'stale_target', 'target_identity_unverifiable',
                        'protected_project', 'approval_required', 'resource_limit',
                        'backend_unavailable', 'outcome_unknown'}:
            code = 'outcome_unknown' if response['outcome'] == 'unknown' else 'backend_unavailable'
        raise RunnerError(code)
    key = {'capabilities': 'capabilities', 'inspect': 'inspection',
           'dispatch': 'result'}[phase]
    if key not in response:
        raise RunnerError('backend_unavailable')
    return response[key]


def capabilities(config: RunnerConfig, request: dict[str, Any], deadline: float) -> dict[str, Any]:
    declaration = validate_capabilities(exchange(config, request, 'capabilities', deadline))
    adapter = declaration['adapter']
    if any(adapter[key] != config.backend[key] for key in ('id', 'version', 'digest')):
        raise RunnerError('backend_unavailable')
    return declaration


def allowed_capabilities(config: RunnerConfig, declaration: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(declaration)
    for action, supported in result['operations'].items():
        allowed = supported and action in config.project['operations']
        if action in MUTATIONS:
            identity = declaration['identity']
            allowed = allowed and config.project['write_enabled'] and not config.project['protected']
            allowed = allowed and identity['stable_target_id'] and identity['target_incarnation']
            allowed = allowed and identity['atomic_target_compare']
            if action == 'answer':
                allowed = allowed and identity['prompt_compare_and_set']
            if action == 'cancel':
                allowed = allowed and identity['owned_process_identity']
        result['operations'][action] = bool(allowed)
    return result


def inspect_target(config: RunnerConfig, request: dict[str, Any], declaration: dict[str, Any],
                   deadline: float, store: Store) -> dict[str, Any]:
    identity = declaration['identity']
    if request['action'] in MUTATIONS and not (
        identity['stable_target_id'] and identity['target_incarnation']
        and identity['atomic_target_compare']
    ):
        raise RunnerError('target_identity_unverifiable')
    context = {'owner': request['owner']}
    if request['action'] == 'cancel':
        context.update(job_id=request['job_id'], attempt_id=request['attempt_id'])
    inspected = validate_inspection(exchange(config, request, 'inspect', deadline, context), request)
    if request['action'] == 'answer':
        if not identity['prompt_compare_and_set']:
            raise RunnerError('target_identity_unverifiable')
        prompt = inspected.get('prompt')
        expected = request['prompt']
        if not prompt or prompt['id'] != expected['id'] or prompt['revision'] != expected['revision']:
            raise RunnerError('stale_target')
        if expected['choice'] not in prompt['choices']:
            raise RunnerError('invalid_request')
    if request['action'] == 'cancel':
        if not identity['owned_process_identity']:
            raise RunnerError('target_identity_unverifiable')
        job = store.get_job(request['job_id'], request['attempt_id'])
        if not job:
            raise RunnerError('target_identity_unverifiable')
        original = job['binding']
        if any(original.get(key) != request[key] for key in ('owner', 'project', 'backend')):
            raise RunnerError('stale_target')
        actual_target = (job.get('report') or {}).get('job', {}).get('target', original.get('target'))
        if actual_target != request['target']:
            raise RunnerError('stale_target')
        expected_ownership = {'owner': request['owner'], 'job_id': request['job_id'],
                              'attempt_id': request['attempt_id']}
        if inspected.get('ownership') != expected_ownership:
            raise RunnerError('target_identity_unverifiable')
    return inspected


def _result(config: RunnerConfig, request: dict[str, Any], declaration: dict[str, Any],
            deadline: float, context: dict[str, Any] | None = None) -> dict[str, Any]:
    normalized = normalize_result(exchange(config, request, 'dispatch', deadline, context), request)
    if not declaration['completion']['authoritative_logical_result']:
        normalized['status']['completion']['authoritative'] = False
        if normalized['status']['job_state'] in ('completed', 'failed', 'cancelled'):
            normalized['status']['job_state'] = 'outcome_unknown'
    return normalized


def _historical(request: dict[str, Any], config: RunnerConfig, report: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(report)
    result['request_id'] = request['request_id']
    result['historical'] = True
    result['binding_stale'] = (
        request['project']['generation'] != config.project['generation']
        or request['backend']['generation'] != config.backend['generation']
        or report.get('profile_fingerprint') != profile_fingerprint(config)
    )
    return result


def _read_job(request: dict[str, Any], config: RunnerConfig, store: Store) -> dict[str, Any]:
    job = store.get_job(request['job_id'], request['attempt_id'])
    if not job:
        raise RunnerError('unsupported')
    stored = job['binding']
    if any(stored.get(key) != request[key] for key in ('owner', 'project', 'backend')):
        raise RunnerError('stale_target')
    actual_target = (job.get('report') or {}).get('job', {}).get('target', stored.get('target'))
    if actual_target != request['target']:
        raise RunnerError('stale_target')
    recorded = job.get('report') or {}
    if 'revision' in request and recorded.get('status', {}).get('revision') != request['revision']:
        raise RunnerError('unsupported')
    if 'cursor' in request and recorded.get('output', {}).get('cursor') != request['cursor']:
        raise RunnerError('unsupported')
    if job.get('report'):
        report = _historical(request, config, job['report'])
        report['binding'] = binding(request)
        return report
    report = _base(request, 'unknown')
    report['profile_fingerprint'] = job['profile_fingerprint']
    report.update(code='outcome_unknown', job={'job_id': request['job_id'],
                                             'attempt_id': request['attempt_id']})
    return report


def _unknown(request: dict[str, Any], job: dict[str, Any], profile: str) -> dict[str, Any]:
    report = _base(request, 'unknown')
    report.update(code='outcome_unknown', job=job, profile_fingerprint=profile)
    return report


def _check_history_budget(report: dict[str, Any]) -> None:
    # Reserve actual history metadata and both replay/report binding variants.
    future = {**report, 'request_id': 'r' * 64, 'historical': True, 'binding_stale': False}
    if len(canonical_json(future)) > 65536:
        raise RunnerError('resource_limit')
    future['binding'] = {**report['binding'], 'target': report['job']['target']}
    if len(canonical_json(future)) > 65536:
        raise RunnerError('resource_limit')


def _mutation(request: dict[str, Any], config: RunnerConfig, store: Store,
              declaration: dict[str, Any], deadline: float) -> dict[str, Any]:
    inspect_target(config, request, declaration, deadline, store)
    fresh = load_config(config.config_path)
    if fresh != config:
        raise RunnerError('stale_target')
    _policy(request, fresh)
    if time.monotonic() >= deadline:
        raise RunnerError('resource_limit')
    job_id, attempt_id = uuid.uuid4().hex, uuid.uuid4().hex
    profile = profile_fingerprint(fresh)
    job = {'job_id': job_id, 'attempt_id': attempt_id, **binding(request)}
    uncertain = _unknown(request, job, profile)
    previous_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGHUP, signal.SIGINT},
    )
    try:
        try:
            replay = store.begin_operation(
                request, job_id, attempt_id, time.time(), profile_fingerprint=profile,
            )
        except RunnerError as error:
            if error.code == 'outcome_unknown':
                return uncertain
            raise
        if replay is not None:
            return _historical(request, config, replay)
        try:
            # Pending termination is delivered only inside post-admission handling.
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            context = {'owner': request['owner'], 'job_id': job_id, 'attempt_id': attempt_id}
            report = _base(request)
            report.update(job=job, profile_fingerprint=profile)
            normalized = _result(config, request, declaration, deadline, context)
            report.update(normalized)
            if request['action'] == 'start':
                created = normalized.get('target')
                if not created or created['kind'] not in ('agent', 'owned-job'):
                    raise RunnerError('target_identity_unverifiable')
                report['job']['target'] = created
            if report['status']['job_state'] == 'outcome_unknown':
                report.update(outcome='unknown', code='outcome_unknown')
            _check_history_budget(report)
            store.finish_operation(request, report)
        except BaseException:
            # The durable prepared row is already sufficient to prevent redispatch.
            report = uncertain
            try:
                store.finish_operation(request, report)
            except BaseException:
                pass
        return report
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def process_request(request: dict[str, Any], config: RunnerConfig, store: Store) -> dict[str, Any]:
    check_registration(request, config, store.owner, historical=True)
    if request['action'] in MUTATIONS:
        recorded = store.lookup_operation(request)
        if recorded is not None:
            return _historical(request, config, recorded)
    if request['action'] == 'report':
        _policy(request, config)
        return _read_job(request, config, store)
    check_registration(request, config, store.owner)
    _policy(request, config)
    deadline = time.monotonic() + config.backend['timeout_seconds']
    declaration = capabilities(config, request, deadline)
    if request['action'] == 'capabilities':
        report = _base(request)
        report['capabilities'] = allowed_capabilities(config, declaration)
        return report
    if not declaration['operations'][request['action']]:
        raise RunnerError('unsupported')
    if request['action'] in MUTATIONS:
        return _mutation(request, config, store, declaration, deadline)
    if 'target' in request:
        inspect_target(config, request, declaration, deadline, store)
    report = _base(request)
    report.update(_result(config, request, declaration, deadline))
    return report


def run(config: RunnerConfig) -> tuple[dict[str, Any], int]:
    store = Store(config.state_dir)
    workspace: Workspace | None = None
    try:
        workspace = Workspace(config.workspace)
        raw, digest = workspace.read_request(config.request)
        request = validate_request(decode_json(raw))
        check_registration(request, config, store.owner, historical=True)
        workspace.ensure_report_available(config.reports, request['request_id'])
        claimed = workspace.claim_request(config.request, digest)
        if hashlib.sha256(claimed).hexdigest() != digest:
            raise RunnerError('request_conflict')
        report = None
        try:
            report = process_request(request, config, store)
            if len(canonical_json(report)) > 65536:
                if report.get('job'):
                    report = _unknown(request, report['job'], report['profile_fingerprint'])
                else:
                    raise RunnerError('resource_limit')
        except (RunnerError, KeyboardInterrupt) as error:
            code = error.code if isinstance(error, RunnerError) else 'outcome_unknown'
            if code == 'outcome_unknown':
                if report is None and request['action'] in MUTATIONS:
                    try:
                        report = store.lookup_operation(request)
                    except RunnerError:
                        pass
                if report and report.get('job'):
                    report = _unknown(request, report['job'], report['profile_fingerprint'])
                else:
                    report = _base(request, 'unknown')
                    report['code'] = code
            else:
                report = _refused(request, code)
        try:
            path, report_digest = workspace.write_report(config.reports, request['request_id'], report)
        except (RunnerError, OSError, KeyboardInterrupt):
            if report.get('job'):
                raise RunnerError('outcome_unknown') from None
            raise
        summary = {'request_id': request['request_id'], 'report': path, 'sha256': report_digest}
        return summary, 0 if report['outcome'] == 'ok' else 2
    finally:
        if workspace is not None:
            workspace.close()
        store.close()
