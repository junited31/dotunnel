"""Actual stdio admission boundaries for the shared supervision surface."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

from mcp import Client, StdioServerParameters
from dotunnel.supervision_state import SupervisionState
from tests.test_herdr import FAKE_BACKEND_HERDR, _pane


class SupervisionProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_start_arguments_never_execute_approved_backend(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / 'workspace'
            root.mkdir()
            executable = base / 'fixture'
            effect = base / 'executed'
            executable.write_text('#!/usr/bin/python3\nimport pathlib\npathlib.Path(' + repr(str(effect)) + ').touch()\nprint("%1")\n')
            executable.chmod(0o700)
            state = SupervisionState.initialize(base / 'state')
            state.close()
            config = base / 'config.json'
            config.write_text(json.dumps({
                'file_access': {'read': [], 'write': []},
                'root': str(root), 'tasks': [],
                'supervision': {
                    'state_dir': str(base / 'state'),
                    'connections': [
                        {'id': 'a', 'backend': 'tmux', 'executable': str(executable), 'socket': str(base / 'a.sock')},
                        {'id': 'b', 'backend': 'tmux', 'executable': str(executable), 'socket': str(base / 'b.sock')},
                    ],
                    'projects': [{
                        'id': 'p',
                        'path': str(root),
                        'connections': ['a', 'b'],
                        'profiles': ['omp'],
                        'allowed_actions': [],
                        'profile_actions': {},
                    }],
                    'profiles': [{'id': 'omp', 'kind': 'omp', 'executable': '/usr/bin/true'}],
                },
            }))
            config.chmod(0o600)
            server = StdioServerParameters(command=sys.executable, args=['-m', 'dotunnel', 'serve', '--config', str(config)], cwd=Path(__file__).absolute().parent.parent)
            async with Client(server) as client:
                listed = await client.list_tools()
                self.assertEqual(
                    {tool.name for tool in listed.tools},
                    {
                        "list_files", "read_file", "search_files", "write_file",
                        "list_tasks", "run_task", "get_task_result",
                        "agent_status", "agent_read", "agent_approve", "agent_revoke",
                        "agent_start", "agent_prompt", "agent_answer", "agent_wait",
                    },
                )
                approved = await client.call_tool('agent_approve', {'scope': 'a:p'})
                self.assertFalse(approved.is_error)
                rejected = await client.call_tool('agent_start', {
                    'project': 'p', 'profile': 'omp', 'name': 'new-agent',
                    'operation_id': 'start-one', 'connection': 'a', 'argv': ['/bin/sh'],
                })
                self.assertTrue(rejected.is_error)
                self.assertEqual(json.loads(rejected.content[0].text)['error']['code'], 'invalid_request')
                self.assertFalse(effect.exists(), 'Ignored extra fields must not launch even an approved fixed backend')
                ambiguous = await client.call_tool('agent_start', {
                    'project': 'p', 'profile': 'omp', 'name': 'new-agent', 'operation_id': 'start-two',
                })
                self.assertTrue(ambiguous.is_error)
                self.assertEqual(json.loads(ambiguous.content[0].text)['error']['code'], 'invalid_request')
                self.assertFalse(effect.exists(), 'A defaultless two-connection start must not execute either backend')
                status = await client.call_tool('agent_status', {})
                self.assertFalse(status.is_error)
                self.assertEqual(json.loads(status.content[0].text)['targets'], [])

    async def test_stdio_pagination_admission_and_replay_preserve_consumer_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / 'workspace'
            root.mkdir()
            runtime = base / 'runtime'
            runtime.mkdir()
            bun = runtime / 'bun'
            bun.write_text('#!/bin/sh\nexit 0\n')
            bun.chmod(0o700)
            omp = runtime / 'omp'
            omp.write_text('#!/usr/bin/env bun\n')
            omp.chmod(0o700)
            executable = base / 'herdr'
            executable.write_text(f'#!{sys.executable}\n' + FAKE_BACKEND_HERDR)
            executable.chmod(0o700)
            panes = [_pane(f'wA:p{index}', str(root), 'omp', 'idle') for index in range(101)]
            scenario = {
                'workspaces': [{'workspace_id': 'wA', 'label': 'fixture'}],
                'panes': panes,
                'agents': [dict(pane, name=f'worker-{index}') for index, pane in enumerate(panes)],
                'screen': 'Allow the candidate write?\\n',
            }
            scenario_path = base / 'scenario.json'
            scenario_path.write_text(json.dumps(scenario))
            state = SupervisionState.initialize(base / 'state')
            state.close()
            config = base / 'config.json'
            config.write_text(json.dumps({
                'file_access': {'read': [], 'write': []},
                'root': str(root), 'tasks': [],
                'supervision': {
                    'state_dir': str(base / 'state'),
                    'connections': [{'id': 'h', 'backend': 'herdr', 'executable': str(executable), 'session': 'fixture'}],
                    'projects': [{
                        'id': 'p',
                        'path': str(root),
                        'connections': ['h'],
                        'profiles': ['omp'],
                        'allowed_actions': ['read', 'prompt', 'answer'],
                        'profile_actions': {'omp': ['prompt', 'answer']},
                    }],
                    'profiles': [{'id': 'omp', 'kind': 'omp', 'executable': str(bun), 'backends': ['herdr']}],
                },
            }))
            config.chmod(0o600)
            server = StdioServerParameters(command=sys.executable, args=['-m', 'dotunnel', 'serve', '--config', str(config)], cwd=Path(__file__).absolute().parent.parent)

            def data(response):
                text = json.loads(response.content[0].text)
                if not response.is_error:
                    self.assertEqual(response.structured_content, text)
                    self.assertEqual(
                        response.content[0].text,
                        json.dumps(text, ensure_ascii=False, separators=(',', ':'), allow_nan=False),
                    )
                    self.assertLessEqual(len(response.content[0].text.encode()), 65536)
                    return response.structured_content
                return text

            def effects():
                path = base / 'calls.jsonl'
                return [
                    call['args'] for call in (json.loads(line) for line in path.read_text().splitlines())
                    if call['args'][:2] in (['agent', 'prompt'], ['agent', 'send-keys'], ['agent', 'start'])
                ] if path.exists() else []

            async with Client(server) as client:
                first = await client.call_tool('agent_status', {})
                self.assertFalse(first.is_error)
                snapshot = data(first)
                self.assertIsNotNone(snapshot['next_cursor'])
                saved_cursor = snapshot['next_cursor']
                rows = list(snapshot['targets'])
                page = first
                while snapshot['next_cursor'] is not None:
                    self.assertLessEqual(len(snapshot['targets']), 100)
                    self.assertLessEqual(len(page.content[0].text.encode()), 65536)
                    page = await client.call_tool('agent_status', {'cursor': snapshot['next_cursor']})
                    self.assertFalse(page.is_error)
                    snapshot = data(page)
                    rows.extend(snapshot['targets'])
                self.assertLessEqual(len(page.content[0].text.encode()), 65536)
                self.assertEqual(len(rows), 101)
                self.assertEqual(len({row['target'] for row in rows}), 101)
                target = rows[0]['target']
                cursor_read = await client.call_tool('agent_read', {'target': saved_cursor})
                self.assertTrue(cursor_read.is_error)
                self.assertEqual(data(cursor_read)['error']['code'], 'invalid_request')
                malformed = await client.call_tool('agent_read', {'target': 't.not-a-valid-token'})
                self.assertTrue(malformed.is_error)
                read = await client.call_tool('agent_read', {'target': target})
                self.assertFalse(read.is_error)
                observation = data(read)['observation']
                denied = await client.call_tool('agent_prompt', {
                    'target': target, 'observation': observation, 'text': 'candidate instruction',
                    'operation_id': 'prompt-once',
                })
                self.assertTrue(denied.is_error)
                self.assertEqual(data(denied)['error']['code'], 'not_approved')
                self.assertEqual(effects(), [])
                wrong_scope = await client.call_tool('agent_approve', {'scope': 'h:foreign'})
                self.assertTrue(wrong_scope.is_error)
                approved = await client.call_tool('agent_approve', {'scope': 'h:p'})
                self.assertFalse(approved.is_error)
                stale_cursor = await client.call_tool('agent_status', {'cursor': saved_cursor})
                self.assertTrue(stale_cursor.is_error)
                self.assertEqual(data(stale_cursor)['error']['reason'], 'cursor_stale')
                read = await client.call_tool('agent_read', {'target': target})
                prompt_arguments = {
                    'target': target, 'observation': data(read)['observation'],
                    'text': 'candidate instruction', 'operation_id': 'prompt-once',
                }
                sent = await client.call_tool('agent_prompt', prompt_arguments)
                self.assertFalse(sent.is_error)
                self.assertEqual(data(sent)['delivery'], 'confirmed')
                self.assertEqual(len(effects()), 1)
                replay = await client.call_tool('agent_prompt', prompt_arguments)
                self.assertFalse(replay.is_error)
                self.assertTrue(data(replay)['historical'])
                self.assertEqual(data(replay)['delivery'], 'confirmed')
                self.assertEqual(data(replay)['operation_id'], 'prompt-once')
                self.assertEqual(len(effects()), 1)
                changed = await client.call_tool('agent_prompt', dict(prompt_arguments, text='different instruction'))
                self.assertTrue(changed.is_error)
                self.assertEqual(data(changed)['error']['code'], 'operation_conflict')
                self.assertEqual(len(effects()), 1)
                latest = await client.call_tool('agent_read', {'target': target})
                scenario['screen'] = 'A different approval question\\n'
                scenario_path.write_text(json.dumps(scenario))
                stale_answer = await client.call_tool('agent_answer', {
                    'target': target, 'observation': data(latest)['observation'],
                    'keys': ['enter'], 'operation_id': 'answer-stale',
                })
                self.assertTrue(stale_answer.is_error)
                self.assertEqual(data(stale_answer)['error']['code'], 'stale_observation')
                self.assertEqual(len(effects()), 1)
                revoked = await client.call_tool('agent_revoke', {'scope': 'h:p'})
                self.assertFalse(revoked.is_error)
            async with Client(server) as restarted:
                replay = await restarted.call_tool('agent_prompt', prompt_arguments)
                self.assertFalse(replay.is_error)
                self.assertTrue(data(replay)['historical'])
                self.assertEqual(data(replay)['delivery'], 'confirmed')
                self.assertEqual(data(replay)['operation_id'], 'prompt-once')
                self.assertEqual(len(effects()), 1)

    async def test_mixed_backends_register_the_shared_agent_surface_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "workspace"
            root.mkdir(mode=0o700)
            executable = base / "configured-executable"
            executable.write_text("#!/usr/bin/python3\nraise SystemExit(0)\n", encoding="utf-8")
            executable.chmod(0o700)
            state = SupervisionState.initialize(base / "state")
            state.close()
            config = base / "config.json"
            config.write_text(json.dumps({
                "root": str(root),
                "file_access": {"read": [], "write": []},
                "tasks": [],
                "supervision": {
                    "state_dir": str(base / "state"),
                    "connections": [
                        {
                            "id": "herdr",
                            "backend": "herdr",
                            "executable": str(executable),
                            "session": "fixture",
                        },
                        {
                            "id": "tmux",
                            "backend": "tmux",
                            "executable": str(executable),
                            "socket": str(base / "tmux.sock"),
                        },
                    ],
                    "projects": [{
                        "id": "project",
                        "path": str(root),
                        "connections": ["herdr", "tmux"],
                        "profiles": ["omp"],
                        "allowed_actions": ["read", "start", "prompt", "answer"],
                        "profile_actions": {"omp": ["start", "prompt", "answer"]},
                    }],
                    "profiles": [{
                        "id": "omp",
                        "kind": "omp",
                        "executable": str(executable),
                        "backends": ["herdr", "tmux"],
                    }],
                },
            }))
            config.chmod(0o600)
            server = StdioServerParameters(
                command=sys.executable,
                args=["-m", "dotunnel", "serve", "--config", str(config)],
                cwd=Path(__file__).absolute().parent.parent,
            )
            async with Client(server) as client:
                listed = await client.list_tools()
                names = {tool.name for tool in listed.tools}
                self.assertEqual(len(names), 15)
                self.assertEqual(len({name for name in names if name.startswith("agent_")}), 8)
