"""Synthetic JSON-stdio backend for tests; excluded from the runner wheel."""

import hashlib
import json
from pathlib import Path
import sys


state_path = Path(sys.argv[1])
state = json.loads(state_path.read_text())
envelope = json.load(sys.stdin)
request = envelope['request']
phase = envelope['phase']
context = envelope['context']
mode = state.get('mode', 'normal')
binding = {key: request[key] for key in ('owner', 'project', 'backend', 'target') if key in request}
response = {
    'protocol': 'dotunnel.adapter.backend/1', 'phase': phase,
    'request_id': request['request_id'], 'outcome': 'ok', 'binding': binding,
}
state['calls'] = state.get('calls', 0) + 1
if phase == 'capabilities':
    response['capabilities'] = {
        'adapter': {'id': 'fixture-backend', 'version': '1.0.0',
                    'digest': 'sha256:' + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()},
        'operations': {name: True for name in (
            'capabilities', 'list_targets', 'inspect', 'read_output', 'report',
            'start', 'submit', 'answer', 'cancel')},
        'identity': {'stable_target_id': True, 'target_incarnation': True,
                     'owned_process_identity': True, 'atomic_target_compare': True,
                     'prompt_compare_and_set': True},
        'completion': {'authoritative_logical_result': True},
    }
elif phase == 'inspect':
    target = dict(request['target'])
    if target['kind'] != 'profile':
        target['incarnation'] = state.get('generation', 'generation-1')
    response['inspection'] = {
        'target': target,
        'prompt': {'id': 'prompt-1', 'revision': state.get('prompt_revision', 1),
                   'choices': ['approve', 'reject']},
    }
    if request['action'] == 'cancel':
        job = state.get('jobs', {}).get(request['job_id'])
        if job:
            response['inspection']['target'] = job['target']
            response['inspection']['ownership'] = {
                'owner': job['owner'], 'job_id': request['job_id'],
                'attempt_id': job['attempt_id'],
            }
else:
    action = request['action']
    mutation = action in ('start', 'submit', 'answer', 'cancel')
    expected = request.get('target', {})
    if mutation and mode == 'race':
        state['generation'] = 'generation-2'
    stale = mutation and expected.get('kind') != 'profile' and action != 'cancel' and (
        expected.get('incarnation') != state.get('generation', 'generation-1')
    )
    stale_prompt = action == 'answer' and (
        request['prompt']['revision'] != state.get('prompt_revision', 1)
    )
    if stale or stale_prompt:
        response.update(outcome='refused', code='stale_target')
    else:
        if mutation:
            state['effects'] = state.get('effects', 0) + 1
        if mutation and mode == 'effect_then_fail':
            state_path.write_text(json.dumps(state))
            raise SystemExit(7)
        authoritative = mode != 'zero_exit_only'
        result = {
            'status': {'job_state': 'completed', 'target_state': 'ready',
                       'process': {'state': 'exited', 'exit_code': 0},
                       'completion': {'authoritative': authoritative,
                                      'source': 'owned_wrapper' if authoritative else 'owned_process'},
                       'observed_at': '2026-10-06T00:00:00Z', 'revision': 1},
            'output': {'tail': state.get('tail', 'synthetic result\n'), 'truncated': False},
            'report': {'synthetic_effects': state.get('effects', 0)},
        }
        if mode == 'padded_report':
            result['report'] = {'text': 'x' * state.get('padding', 100)}
        if mutation and mode == 'replace_state_after_effect':
            database = Path.cwd() / 'state.sqlite3'
            database.rename(Path.cwd() / 'state.previous')
            database.write_bytes(b'replaced during dispatch')
            database.chmod(0o600)
        if action == 'start':
            target = {'kind': 'owned-job', 'id': context['job_id'],
                      'incarnation': context['attempt_id']}
            result['target'] = target
            state.setdefault('jobs', {})[context['job_id']] = {
                'target': target, 'owner': request['owner'],
                'attempt_id': context['attempt_id'],
            }
        response['result'] = result
        if mode == 'edge_report':
            result['report'] = {'text': ''}
            encoded = json.dumps(response, separators=(',', ':')).encode('utf-8')
            result['report']['text'] = 'x' * (65536 - len(encoded) - 1)
state_path.write_text(json.dumps(state))
print(json.dumps(response, separators=(',', ':')))
