import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'src'
BOOTSTRAP = "import sys; sys.path.insert(0, sys.argv.pop(1)); from dotunnel_adapter.cli import main; raise SystemExit(main())"


class RunnerConsumerTests(unittest.TestCase):
    def test_read_report_is_correlated_and_zero_exit_is_not_logical_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            private = base / 'private'
            workspace = base / 'workspace'
            state = private / 'state'
            private.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            executable = Path('/usr/bin/python3').resolve(strict=True)
            digest = 'sha256:' + hashlib.sha256(executable.read_bytes()).hexdigest()
            backend = private / 'backend.py'
            backend.write_text('''import json, sys
value = json.load(sys.stdin)
request = value['request']
phase = value['phase']
binding = {key: request[key] for key in ('owner', 'project', 'backend', 'target') if key in request}
response = dict(protocol='dotunnel.adapter.backend/1', phase=phase, request_id=request['request_id'], outcome='ok', binding=binding)
if phase == 'capabilities':
    response['capabilities'] = {
        'adapter': {'id': 'fixture-backend', 'version': '1.0.0', 'digest': sys.argv[1]},
        'operations': {name: name in ('capabilities', 'list_targets', 'inspect', 'read_output', 'report') for name in ('capabilities', 'list_targets', 'inspect', 'read_output', 'report', 'start', 'submit', 'answer', 'cancel')},
        'identity': dict(stable_target_id=True, target_incarnation=True, owned_process_identity=False, atomic_target_compare=False, prompt_compare_and_set=False),
        'completion': {'authoritative_logical_result': False}
    }
elif phase == 'inspect':
    response['inspection'] = {'target': request['target']}
else:
    response['result'] = {
        'status': {'job_state': 'completed', 'target_state': 'ready', 'process': {'state': 'exited', 'exit_code': 0}, 'completion': {'authoritative': False, 'source': 'owned_process'}, 'observed_at': '2026-10-06T00:00:00Z', 'revision': 1},
        'output': {'tail': 'read-only result\\n', 'truncated': False}
    }
print(json.dumps(response))
''')
            backend.chmod(0o600)
            configuration = private / 'config.json'
            configuration.write_text(json.dumps({
                'protocol': 'dotunnel.adapter.config/1',
                'workspace': str(workspace), 'request': 'pending.json',
                'reports': 'reports', 'state_dir': str(state),
                'project': {'id': 'demo', 'generation': 'project-1',
                            'protected': False, 'write_enabled': False,
                            'operations': ['capabilities', 'inspect', 'read_output', 'report']},
                'backend': {'id': 'fixture-backend', 'generation': 'backend-1',
                            'version': '1.0.0', 'digest': digest,
                            'argv': [str(executable), '-I', str(backend), digest],
                            'timeout_seconds': 5},
            }))
            configuration.chmod(0o600)
            initialized = subprocess.run(
                [sys.executable, '-I', '-c', BOOTSTRAP, str(SOURCE),
                 'initialize', '--config', str(configuration)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            owner = json.loads(initialized.stdout)['owner']
            request = {
                'protocol': 'dotunnel.adapter/1', 'request_id': 'read-1',
                'action': 'read_output', 'owner': owner,
                'project': {'id': 'demo', 'generation': 'project-1'},
                'backend': {'id': 'fixture-backend', 'generation': 'backend-1'},
                'target': {'kind': 'agent', 'id': 'agent-1', 'incarnation': 'generation-1'},
            }
            pending = workspace / 'pending.json'
            pending.write_text(json.dumps(request))
            pending.chmod(0o600)
            invoked = subprocess.run(
                [sys.executable, '-I', '-c', BOOTSTRAP, str(SOURCE),
                 'run', '--config', str(configuration)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(invoked.returncode, 0, invoked.stderr)
            summary = json.loads(invoked.stdout)
            self.assertEqual(summary['request_id'], 'read-1')
            report_bytes = (workspace / summary['report']).read_bytes()
            self.assertEqual(hashlib.sha256(report_bytes).hexdigest(), summary['sha256'])
            report = json.loads(report_bytes)
            self.assertEqual(report['request_id'], 'read-1')
            self.assertEqual(report['status']['job_state'], 'outcome_unknown')
            self.assertEqual(report['output']['tail'], 'read-only result\n')
            self.assertFalse(pending.exists())


if __name__ == '__main__':
    unittest.main()
