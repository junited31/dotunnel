import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CliJobAdmissionTests(unittest.TestCase):
    def test_caller_cli_arguments_are_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            workspace = base / 'workspace'
            workspace.mkdir()
            source = base / 'source'
            source.mkdir()
            (source / 'logic.py').write_text('value = 1\n')
            auth = base / 'auth.json'
            auth.write_text('{}')
            auth.chmod(0o600)
            request = workspace / 'request.json'
            request.write_text(json.dumps({'target': 'fixture', 'mode': 'edit', 'instruction': 'Change value to 2', 'argv': ['/bin/sh']}))
            config = base / 'job.json'
            config.write_text(json.dumps({
                'backend': 'codex', 'workspace': str(workspace), 'request': 'request.json',
                'runtime': {'executable': '/usr/bin/true', 'companion': '/usr/bin/true', 'auth': str(auth)},
                'targets': {'fixture': {'root': str(source), 'files': ['logic.py'], 'editable': ['logic.py']}},
            }))
            config.chmod(0o600)
            response = subprocess.run(
                [sys.executable, '-m', 'dotunnel', 'cli-job', '--config', str(config)],
                cwd=Path(__file__).absolute().parent.parent, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(response.returncode, 2)
            self.assertTrue(response.stdout.strip(), 'CLI job rejection must return a structured result')
            report = json.loads(response.stdout)
            self.assertEqual(report['status'], 'rejected')
            self.assertEqual(report['error_code'], 'INVALID_REQUEST')
            self.assertEqual((source / 'logic.py').read_text(), 'value = 1\n')
            self.assertEqual(sorted(p.name for p in workspace.iterdir()), ['request.json'])


if __name__ == '__main__':
    unittest.main()
