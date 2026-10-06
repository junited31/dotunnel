"""Operator commands do not start a tunnel or native model implicitly."""
import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from unittest.mock import patch
from dotunnel.operator import main


class OperatorTests(unittest.TestCase):
    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_no_command_points_to_help_without_entering_setup(self):
        code, stdout, stderr = self.invoke([])
        self.assertEqual(code, 2)
        self.assertIn('dotunnel help', stdout + stderr)
        self.assertNotIn('Runtime API key', stdout + stderr)


    def test_setup_without_interactive_terminal_does_not_create_state(self):
        if os.sys.platform != 'linux' or os.getuid() == 0:
            self.skipTest('setup requires Linux and a non-root user')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'new-setup'
            with patch('sys.stdin', io.StringIO('')):
                code, stdout, stderr = self.invoke(['setup', '--directory', str(directory)])
            self.assertEqual(code, 2)
            self.assertFalse(directory.exists())

    def test_unknown_command_does_not_echo_sensitive_argument(self):
        argument = 'secret-shaped-mistake'
        code, stdout, stderr = self.invoke([argument])
        self.assertEqual(code, 2)
        self.assertNotIn(argument, stdout + stderr)

    @staticmethod
    def write_private(path, contents, mode=0o600):
        path.write_text(contents, encoding='utf-8')
        path.chmod(mode)

    def make_setup(self, base, tasks=None):
        directory = base / 'setup'
        directory.mkdir(mode=0o700)
        workspace = base / 'workspace'
        workspace.mkdir(mode=0o700)
        config = directory / 'config.json'
        self.write_private(config, json.dumps({'root': str(workspace), 'tasks': tasks or []}) + '\n')
        profile = directory / 'profile.yaml'
        self.write_private(profile, '{}\n')
        client = base / 'tunnel-client'
        self.write_private(client, '#!/usr/bin/env python3\nprint(\'{"result":"ok"}\')\n', 0o700)
        return directory, config, profile, client

    def make_managed_cli_task(self, base, directory, backend):
        launcher = base / 'dotunnel'
        self.write_private(launcher, '#!/usr/bin/env python3\nraise SystemExit(0)\n', 0o700)
        job_config = directory / 'cli-jobs' / f'{backend}.json'
        task = {
            'name': f'dotunnel-{backend}',
            'description': f'{backend.title()} integration',
            'argv': [str(launcher.resolve()), 'cli-job', '--config', str(job_config)],
            'cwd': '.',
            'timeout_seconds': 240,
        }
        return task, job_config

    def create_valid_managed_job(self, base, job_config, backend='codex'):
        workspace = base / 'workspace'
        source_root = base / 'source'
        source_root.mkdir(mode=0o700)
        self.write_private(source_root / 'source.py', 'print("fixture")\n')
        runtime = base / 'native-runtime'
        runtime.mkdir(mode=0o700)
        executable = runtime / 'codex'
        companion = runtime / 'codex-code-mode-host'
        auth_reference = runtime / 'auth-reference'
        self.write_private(executable, '#!/bin/sh\nexit 0\n', 0o700)
        self.write_private(companion, '#!/bin/sh\nexit 0\n', 0o700)
        self.write_private(auth_reference, '')
        request_path = workspace / 'dotunnel-requests' / f'{backend}.json'
        request_path.parent.mkdir(mode=0o700)
        self.write_private(request_path, json.dumps({
            'target': 'project',
            'mode': 'review',
            'instruction': 'Review the fixture source.',
        }) + '\n')
        job_config.parent.mkdir(mode=0o700)
        self.write_private(job_config, json.dumps({
            'backend': backend,
            'workspace': str(workspace),
            'request': f'dotunnel-requests/{backend}.json',
            'runtime': {
                'executable': str(executable),
                'companion': str(companion),
                'auth': str(auth_reference),
            },
            'targets': {
                'project': {
                    'root': str(source_root),
                    'files': ['source.py'],
                    'editable': [],
                },
            },
        }) + '\n')

    def start_ready_tunnel(self, directory):
        class ReadyHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({
                    'live': True,
                    'ready': True,
                    'components': {
                        'control-plane': {
                            'status': 'ok',
                            'details': {
                                'consecutive_failures': 0,
                                'last_success': 'synthetic-success',
                            },
                        },
                    },
                }).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), ReadyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(server.shutdown)
        health_url = directory / 'health-url'
        self.write_private(health_url, f'http://127.0.0.1:{server.server_port}\n')
        return health_url

    def test_invalid_doctor_configuration_is_non_destructive(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'setup'
            directory.mkdir(mode=0o700)
            config = directory / 'config.json'
            self.write_private(config, '{broken json')
            before = config.read_bytes()
            code, stdout, stderr = self.invoke(['doctor', '--directory', str(directory)])
            self.assertEqual(code, 2)
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(list(directory.iterdir()), [config])

    def test_configuration_alone_does_not_count_as_local_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory, config, profile, client = self.make_setup(base)
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            with patch('dotunnel.integrations.discover_clis', return_value={}):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 2)
            self.assertTrue(config.exists())
            self.assertTrue(profile.exists())
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)

    def test_doctor_observes_valid_configuration_and_live_local_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory, config, profile, client = self.make_setup(base)
            health_url = self.start_ready_tunnel(directory)
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            with patch('dotunnel.integrations.discover_clis', return_value={}):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 0)
            self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
            self.assertTrue(config.exists())
            self.assertTrue(profile.exists())
            self.assertTrue(health_url.exists())

    def test_doctor_rejects_selected_cli_with_missing_job_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            task, backend = self.make_managed_cli_task(base, base / 'setup', 'codex')
            directory, _, _, client = self.make_setup(base, [task])
            self.start_ready_tunnel(directory)
            with patch('dotunnel.integrations.discover_clis', return_value={'codex': Path('/usr/bin/codex')}), \
                    patch('dotunnel.operator._bwrap_available', return_value=True):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 2)
            self.assertNotIn(str(backend), stdout + stderr)

    def test_doctor_rejects_invalid_managed_job_config_without_echoing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            task, backend = self.make_managed_cli_task(base, base / 'setup', 'codex')
            directory, _, _, client = self.make_setup(base, [task])
            backend.parent.mkdir(mode=0o700)
            invalid_config = '{"backend":"codex","runtime":"not-a-real-config"}\n'
            self.write_private(backend, invalid_config)
            before = backend.read_bytes()
            self.start_ready_tunnel(directory)
            with patch('dotunnel.integrations.discover_clis', return_value={'codex': Path('/usr/bin/codex')}), \
                    patch('dotunnel.operator._bwrap_available', return_value=True):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 2)
            self.assertNotIn(str(backend), stdout + stderr)
            self.assertNotIn('not-a-real-config', stdout + stderr)
            self.assertEqual(backend.read_bytes(), before)

    def test_doctor_accepts_valid_managed_job_without_exposing_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            task, job_config = self.make_managed_cli_task(base, base / 'setup', 'codex')
            directory, _, _, client = self.make_setup(base, [task])
            self.create_valid_managed_job(base, job_config)
            health_url = self.start_ready_tunnel(directory)
            request_path = base / 'workspace' / 'dotunnel-requests' / 'codex.json'
            auth_reference = base / 'native-runtime' / 'auth-reference'
            job_before = job_config.read_bytes()
            request_before = request_path.read_bytes()
            auth_created = auth_reference.stat()
            os.utime(auth_reference, ns=(1, auth_created.st_mtime_ns))
            auth_before = auth_reference.stat()
            with patch('dotunnel.integrations.discover_clis', return_value={'codex': Path('/usr/bin/codex')}), \
                    patch('dotunnel.integrations._check_bwrap'), \
                    patch('dotunnel.operator._bwrap_available', return_value=True):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            auth_after = auth_reference.stat()
            self.assertEqual(code, 0)
            self.assertNotIn(str(job_config), stdout + stderr)
            self.assertNotIn(str(auth_reference), stdout + stderr)
            self.assertEqual(job_config.read_bytes(), job_before)
            self.assertEqual(request_path.read_bytes(), request_before)
            self.assertEqual(
                (auth_after.st_atime_ns, auth_after.st_ino, auth_after.st_size, auth_after.st_mtime_ns, auth_after.st_mode),
                (auth_before.st_atime_ns, auth_before.st_ino, auth_before.st_size, auth_before.st_mtime_ns, auth_before.st_mode),
            )
            self.assertTrue(health_url.exists())

    def test_doctor_rejects_reserved_task_name_pointing_to_another_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            task, job_config = self.make_managed_cli_task(base, base / 'setup', 'codex')
            task['argv'][-1] = str(base / 'unrelated-config.json')
            directory, _, _, client = self.make_setup(base, [task])
            self.create_valid_managed_job(base, job_config)
            self.start_ready_tunnel(directory)
            with patch('dotunnel.integrations.discover_clis', return_value={'codex': Path('/usr/bin/codex')}), \
                    patch('dotunnel.integrations.validate_managed_job', return_value=True), \
                    patch('dotunnel.operator._bwrap_available', return_value=True):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 2)
            self.assertNotIn(str(job_config), stdout + stderr)
            self.assertNotIn('unrelated-config.json', stdout + stderr)

    def test_doctor_does_not_execute_group_or_world_writable_client(self):
        if os.getuid() == 0:
            self.skipTest('operator doctor requires a non-root user')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory, _, _, client = self.make_setup(base)
            marker = base / 'executed'
            script = (
                '#!/usr/bin/env python3\n'
                'from pathlib import Path\n'
                f'Path({str(marker)!r}).touch()\n'
                'print(\'{"result":"ok"}\')\n'
            )
            self.write_private(client, script, 0o777)
            with patch('dotunnel.integrations.discover_clis', return_value={}):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 2)
            self.assertFalse(marker.exists())

    def test_doctor_does_not_execute_client_through_untrusted_ancestor(self):
        if os.getuid() == 0:
            self.skipTest('operator doctor requires a non-root user')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory, _, _, _ = self.make_setup(base)
            unsafe_parent = base / 'world-writable'
            unsafe_parent.mkdir(mode=0o777)
            unsafe_parent.chmod(0o777)
            client = unsafe_parent / 'tunnel-client'
            marker = base / 'executed'
            script = (
                '#!/usr/bin/env python3\n'
                'from pathlib import Path\n'
                f'Path({str(marker)!r}).touch()\n'
                'print(\'{"result":"ok"}\')\n'
            )
            self.write_private(client, script, 0o700)
            with patch('dotunnel.integrations.discover_clis', return_value={}):
                code, stdout, stderr = self.invoke([
                    'doctor', '--directory', str(directory), '--tunnel-client', str(client),
                ])
            self.assertEqual(code, 2)
            self.assertFalse(marker.exists())

    def test_doctor_argument_errors_do_not_echo_secret_like_values(self):
        secret = 'sk-test-argument-must-not-be-echoed'
        code, stdout, stderr = self.invoke(['doctor', '--unexpected', secret])
        self.assertEqual(code, 2)
        self.assertNotIn(secret, stdout + stderr)

    def test_doctor_rejects_missing_setup_without_creating_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'absent'
            code, stdout, stderr = self.invoke(['doctor', '--directory', str(directory)])
            self.assertEqual(code, 2)
            self.assertFalse(directory.exists())

    def test_doctor_does_not_execute_a_cwd_only_client(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            directory, _config, _profile, _client = self.make_setup(base)
            local_bin = base / '.tunnel-client'
            local_bin.mkdir(mode=0o700)
            marker = base / 'unexpected-client'
            self.write_private(local_bin / 'tunnel-client',
                               f"#!/bin/sh\nprintf ran > '{marker}'\nprintf '{{\"result\":\"ok\"}}\\n'\n",
                               0o700)
            with contextlib.chdir(base), patch('shutil.which', return_value=None):
                code, _stdout, _stderr = self.invoke(['doctor', '--directory', str(directory)])
            self.assertEqual(code, 2)
            self.assertFalse(marker.exists())
