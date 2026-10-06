import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any


SOURCE = Path(__file__).resolve().parents[1] / 'src'
BOOTSTRAP = "import sys; sys.path.insert(0, sys.argv.pop(1)); from dotunnel_adapter.cli import main; raise SystemExit(main())"


class Fixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.private = self.base / 'private'
        self.workspace = self.base / 'workspace'
        self.state_dir = self.private / 'state'
        self.private.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.state_dir.mkdir(mode=0o700)
        self.backend_state = self.private / 'backend-state.json'
        self.backend_state.write_text(json.dumps({'effects': 0, 'calls': 0}))
        self.backend_state.chmod(0o600)
        executable = Path('/usr/bin/python3').resolve(strict=True)
        self.backend_file = self.private / 'backend.py'
        self.backend_file.write_bytes((Path(__file__).parent / 'backend_fixture.py').read_bytes())
        self.backend_file.chmod(0o400)
        self.config_path = self.private / 'config.json'
        self.configuration: dict[str, Any] = {
            'protocol': 'dotunnel.adapter.config/1',
            'workspace': str(self.workspace), 'request': 'pending.json',
            'reports': 'reports', 'state_dir': str(self.state_dir),
            'project': {'id': 'demo', 'generation': 'project-1', 'protected': False,
                        'write_enabled': True, 'operations': [
                            'capabilities', 'list_targets', 'inspect', 'read_output', 'report',
                            'start', 'submit', 'answer', 'cancel']},
            'backend': {'id': 'fixture-backend', 'generation': 'backend-1',
                        'version': '1.0.0',
                        'digest': 'sha256:' + hashlib.sha256(executable.read_bytes()).hexdigest(),
                        'argv': [str(executable), '-I', str(self.backend_file), str(self.backend_state)],
                        'timeout_seconds': 5},
        }
        self.save_config()
        initialized = self.command('initialize')
        if initialized.returncode != 0:
            self.temporary.cleanup()
            raise AssertionError(initialized.stderr)
        self.owner: dict[str, Any] = json.loads(initialized.stdout)['owner']

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.temporary.cleanup()

    def save_config(self):
        self.config_path.write_text(json.dumps(self.configuration))
        self.config_path.chmod(0o600)

    def mode(self, **values):
        state = json.loads(self.backend_state.read_text())
        state.update(values)
        self.backend_state.write_text(json.dumps(state))

    def backend_snapshot(self):
        return json.loads(self.backend_state.read_text())

    def command(self, command: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, '-I', '-c', BOOTSTRAP, str(SOURCE), command,
             '--config', str(self.config_path), *extra],
            capture_output=True, text=True, timeout=30,
        )

    def request(self, action: str = 'submit', request_id: str = 'request-1',
                operation_id: str = 'operation-1', **fields: Any) -> dict[str, Any]:
        if str(SOURCE) not in sys.path:
            sys.path.insert(0, str(SOURCE))
        from dotunnel_adapter.protocol import fingerprint
        value: dict[str, Any] = {
            'protocol': 'dotunnel.adapter/1', 'request_id': request_id, 'action': action,
            'owner': self.owner, 'project': {'id': 'demo', 'generation': 'project-1'},
            'backend': {'id': 'fixture-backend', 'generation': 'backend-1'},
        }
        if action not in ('capabilities', 'list_targets'):
            value['target'] = {'kind': 'agent', 'id': 'agent-1', 'incarnation': 'generation-1'}
        if action == 'start':
            value['target'] = {'kind': 'profile', 'id': 'profile-1', 'incarnation': 'profile-generation-1'}
        if action in ('submit', 'start'):
            value['instruction'] = 'Perform the selected synthetic operation.'
        if action == 'answer':
            value['prompt'] = {'id': 'prompt-1', 'revision': 1, 'choice': 'approve'}
        value.update(fields)
        if action in ('start', 'submit', 'answer', 'cancel'):
            value['operation'] = {'id': operation_id, 'fingerprint': fingerprint(value)}
            value['authorization'] = {'grant_id': 'not-granted', 'action': action}
        return value

    def grant(self, request):
        if str(SOURCE) not in sys.path:
            sys.path.insert(0, str(SOURCE))
        from dotunnel_adapter.state import Store
        from dotunnel_adapter.configuration import load_config, profile_fingerprint
        store = Store(self.state_dir)
        try:
            grant_id = store.issue_grant(
                request, time.time() + 300,
                profile_fingerprint=profile_fingerprint(load_config(self.config_path)),
            )
        finally:
            store.close()
        request['authorization'] = {'grant_id': grant_id, 'action': request['action']}
        return grant_id

    def stage(self, request):
        path = self.workspace / 'pending.json'
        if path.exists():
            raise AssertionError('previous request was not consumed')
        path.write_text(json.dumps(request))
        path.chmod(0o600)

    def execute(self, request: dict[str, Any]) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        self.stage(request)
        result = self.command('run')
        if not result.stdout.strip():
            raise AssertionError('validated request produced no report: ' + result.stderr)
        summary = json.loads(result.stdout)
        raw = (self.workspace / summary['report']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != summary['sha256']:
            raise AssertionError('report bytes do not match task summary')
        report = json.loads(raw)
        if report['request_id'] != request['request_id']:
            raise AssertionError('request/report correlation lost')
        return result, report
