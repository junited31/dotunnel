"""Consumer-visible supervision state and real child-effect regressions."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from dotunnel.supervision_config import Connection, Project, Profile, SupervisionSettings, SupervisionError
from dotunnel.supervision_state import SupervisionState
from dotunnel.supervision import Supervisor, run_cli


class ProcessBackend:
    def __init__(self, directory):
        self.directory = directory
        self.screen = directory / 'screen'
        self.screen.write_text('approval ready\n')
        self.effects = directory / 'effects'
        self.program = directory / 'fixture.py'
        self.program.write_text("import pathlib,sys\np=pathlib.Path(sys.argv[1]);p.write_text(p.read_text()+'effect\\n' if p.exists() else 'effect\\n')\n")
        self.rows = [{
            'native_id': '%1', 'project': 'p', 'name': 'agent',
            'identity': {'native_id': '%1', 'generation': 'one'},
            'process_state': 'running', 'agent_state': 'unknown',
            'state_source': 'backend', 'readonly': False,
            'cwd': str(directory), 'profile': 'omp', 'managed': True,
        }]

    async def inventory(self, projects, records, *, deadline):
        return self.rows

    async def read(self, target, lines, *, deadline):
        return dict(target, text=self.screen.read_text())

    async def prompt(self, target, text, profile, *, deadline):
        code, _, _ = await run_cli([sys.executable, str(self.program), str(self.effects)], deadline=deadline)
        if getattr(self, 'lose_response', False):
            raise SupervisionError('delivery_unknown')
        return {'delivery': 'confirmed' if code == 0 else 'unknown'}

    async def answer(self, target, keys, *, deadline):
        return await self.prompt(target, 'answer', None, deadline=deadline)

    async def start(self, project, profile, name, worktree_branch, attempt, *, deadline):
        await self.prompt({}, '', profile, deadline=deadline)
        return dict(self.rows[0], nonce=attempt['nonce'])

    def effect_count(self):
        return len(self.effects.read_text().splitlines()) if self.effects.exists() else 0


class SupervisionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        agent_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(agent_temporary.cleanup)
        executable = Path(agent_temporary.name) / 'agent-cli'
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        self.state = SupervisionState.initialize(self.base / 'state')
        self.addCleanup(self.state.close)
        connection = Connection('c', 'tmux', Path(sys.executable), socket=self.base / 'socket')
        self.project = Project(
            'p', self.base, ('c',), ('omp',),
            allowed_actions=frozenset(('read', 'start', 'prompt', 'answer')),
            profile_actions={'omp': frozenset(('start', 'prompt', 'answer'))},
        )
        profile = Profile('omp', 'omp', executable)
        self.settings = SupervisionSettings(
            state_dir=self.base / 'state',
            workspace_root=self.base,
            connections={'c': connection},
            projects={'p': self.project},
            profiles={'omp': profile},
            protected_paths=(),
            default_connection='c',
            generation='fixture',
        )
        self.backend = ProcessBackend(self.base)
        self.supervisor = Supervisor(self.settings, self.state, {'c': self.backend})

    async def observed(self):
        status = await self.supervisor.status()
        target = status['targets'][0]['target']
        read = await self.supervisor.read(target)
        return target, read['observation']

    async def test_unapproved_input_has_no_child_effect(self):
        target, observation = await self.observed()
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.prompt(target, observation, 'do work', 'op-one')
        self.assertEqual(caught.exception.code, 'not_approved')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_replay_after_restart_does_not_repeat_effect_or_require_old_handle(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        first = await self.supervisor.prompt(target, observation, 'do work', 'op-one')
        self.assertEqual(first['delivery'], 'confirmed')
        restarted = SupervisionState(self.base / 'state')
        try:
            supervisor = Supervisor(self.settings, restarted, {'c': self.backend})
            result = await supervisor.prompt(target, observation, 'do work', 'op-one')
            self.assertTrue(result['historical'])
            self.assertEqual(result['delivery'], 'confirmed')
            self.assertEqual(self.backend.effect_count(), 1)
            with self.assertRaises(SupervisionError) as caught:
                await supervisor.prompt(target, observation, 'different work', 'op-one')
            self.assertEqual(caught.exception.code, 'operation_conflict')
        finally:
            restarted.close()

    async def test_screen_change_refuses_old_observation_before_dispatch(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        self.backend.screen.write_text('different approval question\n')
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.answer(target, observation, ['enter'], 'op-answer')
        self.assertEqual(caught.exception.code, 'stale_observation')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_revocation_prevents_new_dispatch_but_keeps_historical_result(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        await self.supervisor.prompt(target, observation, 'do work', 'op-one')
        await self.supervisor.revoke('c:p')
        result = await self.supervisor.prompt(target, observation, 'do work', 'op-one')
        self.assertTrue(result['historical'])
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.prompt(target, observation, 'do work', 'op-two')
        self.assertEqual(caught.exception.code, 'not_approved')
        self.assertEqual(self.backend.effect_count(), 1)

    async def test_status_cursor_is_invalidated_when_other_target_changes(self):
        self.backend.rows = [dict(self.backend.rows[0], native_id=f'%{i}', identity={'generation': str(i)}) for i in range(105)]
        first = await self.supervisor.status()
        pages = list(first['targets'])
        cursor = first['next_cursor']
        while cursor is not None:
            page = await self.supervisor.status(cursor=cursor)
            self.assertLessEqual(len(page['targets']), 100)
            self.assertLessEqual(len(json.dumps(page, ensure_ascii=False, separators=(',', ':')).encode()), 65536)
            pages.extend(page['targets'])
            cursor = page['next_cursor']
        self.assertEqual({row['native_id'] for row in pages}, {f'%{i}' for i in range(105)})
        self.assertEqual(len(pages), 105)
        self.backend.rows[-1]['agent_state'] = 'blocked'
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.status(cursor=first['next_cursor'])
        self.assertEqual(caught.exception.code, 'invalid_request')

    async def test_cursor_tracks_approval_of_scope_without_visible_targets(self):
        settings = replace(self.settings, projects={**self.settings.projects, 'empty': replace(self.project, id='empty')})
        supervisor = Supervisor(settings, self.state, {'c': self.backend})
        self.backend.rows = [dict(self.backend.rows[0], native_id=f'%{i}', identity={'generation': str(i)}) for i in range(105)]
        first = await supervisor.status()
        await supervisor.approve('c:empty')
        with self.assertRaises(SupervisionError) as caught:
            await supervisor.status(cursor=first['next_cursor'])
        self.assertEqual(caught.exception.code, 'invalid_request')

    async def test_audit_preserves_operation_evidence_without_prompt_or_screen(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        secret = 'sensitive-prompt-content'
        await self.supervisor.prompt(target, observation, secret, 'audited-operation')
        await self.supervisor.prompt(target, observation, secret, 'audited-operation')
        events = [json.loads(line) for line in (self.base / 'state' / 'audit.current').read_text().splitlines()]
        dispatches = [event for event in events if event.get('operation_id') == 'audited-operation' and event.get('event') == 'dispatch_prepared']
        self.assertEqual(len(dispatches), 1)
        self.assertTrue(any(event.get('operation_id') == 'audited-operation' and event.get('delivery') == 'confirmed' for event in events))
        self.assertNotIn(secret, json.dumps(events))
        self.assertNotIn(self.backend.screen.read_text().strip(), json.dumps(events))
        self.assertEqual(self.backend.effect_count(), 1)

    async def test_full_target_capacity_refuses_without_orphan_receipt(self):
        await self.supervisor.approve('c:p')
        binding = {'connection': 'c', 'project': 'p', 'profile': 'omp', 'generation': self.settings.generation}
        with patch('dotunnel.supervision_state._MAX_RECORDS', 2):
            self.state.allocate_target('occupied-one', binding)
            self.state.allocate_target('occupied-two', binding)
            for _ in range(2):
                with self.assertRaises(SupervisionError) as caught:
                    await self.supervisor.start('p', 'omp', 'agent', 'capacity-refusal')
                self.assertEqual(caught.exception.code, 'state_full')
        self.assertEqual(self.state.unresolved_predecessors()['unresolved_predecessor_count'], 0)
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_unverified_active_target_exposes_operation_correlated_recovery(self):
        await self.supervisor.approve('c:p')
        await self.supervisor.start('p', 'omp', 'agent', 'managed-start')
        self.backend.rows = []
        status = await self.supervisor.status()
        self.assertEqual(status['targets'], [])
        self.assertEqual(status['recovery_count'], 1)
        self.assertEqual(status['recovery'][0]['operation_id'], 'managed-start')
        self.assertFalse(status['recovery'][0]['actionable'])

    async def test_unfinished_start_replay_retains_attempt_identity_without_resending(self):
        await self.supervisor.approve('c:p')
        with patch.object(SupervisionState, 'finish', side_effect=OSError('storage unavailable')):
            first = await self.supervisor.start('p', 'omp', 'agent', 'unfinished-start')
        self.assertEqual(first['delivery'], 'unknown')
        replay = await self.supervisor.start('p', 'omp', 'agent', 'unfinished-start')
        self.assertTrue(replay['historical'])
        self.assertEqual(replay['attempt_id'], first['attempt_id'])
        self.assertFalse(replay['actionable'])
        self.assertNotIn('target', replay)
        self.assertEqual(self.backend.effect_count(), 1)

    async def test_bounded_screen_keeps_latest_question_and_detects_its_change(self):
        await self.supervisor.approve('c:p')
        prefix = ('오래된 출력 ' * 100 + '\n') * 100
        self.backend.screen.write_text(prefix + 'CURRENT QUESTION A\n')
        target, observation = await self.observed()
        read = await self.supervisor.read(target, 200)
        self.assertLessEqual(len(read['text'].encode('utf-8')), 16384)
        self.assertTrue(read['text'].endswith('CURRENT QUESTION A\n'))
        self.backend.screen.write_text(prefix + 'CURRENT QUESTION B\n')
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.answer(target, observation, ['enter'], 'latest-question')
        self.assertEqual(caught.exception.code, 'stale_observation')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_start_missing_approval_has_no_effect_and_no_target(self):
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.start('p', 'omp', 'new-agent', 'start-one')
        self.assertEqual(caught.exception.code, 'not_approved')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_invalid_prompt_bytes_and_keys_refused_before_effect(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        for text in ('', 'x' * 8193, 'hello\x1b[31m', 'zero\x00', 'c1\x9b31m'):
            with self.assertRaises(SupervisionError):
                await self.supervisor.prompt(target, observation, text, 'bad-prompt')
        for keys in ([], ['ctrl+c'], ['enter'] * 9):
            with self.assertRaises(SupervisionError):
                await self.supervisor.answer(target, observation, keys, 'bad-answer')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_lost_response_never_resends_and_new_id_is_not_globally_fenced(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        self.backend.lose_response = True
        first = await self.supervisor.prompt(target, observation, 'work', 'unknown-one')
        self.assertEqual(first['delivery'], 'unknown')
        historical = await self.supervisor.prompt(target, observation, 'work', 'unknown-one')
        self.assertTrue(historical['historical'])
        self.assertEqual(historical['delivery'], 'unknown')
        self.assertEqual(self.backend.effect_count(), 1)
        self.backend.lose_response = False
        later = await self.supervisor.prompt(target, observation, 'separate work', 'later-one')
        self.assertEqual(later['delivery'], 'confirmed')
        self.assertEqual(later['unresolved_predecessor_count'], 1)
        self.assertIn('unknown-one', later['unresolved_predecessor_ids'])
        self.assertEqual(self.backend.effect_count(), 2)

    async def test_expired_observation_refuses_new_id_but_not_historical_replay(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        await self.supervisor.prompt(target, observation, 'work', 'once')
        future = time.monotonic() + 61
        with patch('dotunnel.supervision.time.monotonic', return_value=future):
            self.assertTrue((await self.supervisor.prompt(target, observation, 'work', 'once'))['historical'])
            with self.assertRaises(SupervisionError) as caught:
                await self.supervisor.prompt(target, observation, 'work', 'new')
            self.assertEqual(caught.exception.code, 'stale_observation')
        self.assertEqual(self.backend.effect_count(), 1)

    async def test_changed_config_and_native_incarnation_cannot_receive_old_handle_input(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        changed = Supervisor(replace(self.settings, generation='new-generation'), self.state, {'c': self.backend})
        with self.assertRaises(SupervisionError) as caught:
            await changed.prompt(target, observation, 'work', 'new-config')
        self.assertEqual(caught.exception.code, 'stale_target')
        self.backend.rows[0]['identity'] = {'native_id': '%1', 'generation': 'replacement'}
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.prompt(target, observation, 'work', 'respawn')
        self.assertEqual(caught.exception.code, 'stale_target')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_readonly_target_never_inherits_scope_approval(self):
        await self.supervisor.approve('c:p')
        self.backend.rows[0]['readonly'] = True
        target, observation = await self.observed()
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.answer(target, observation, ['enter'], 'readonly')
        self.assertEqual(caught.exception.code, 'unsupported_operation')
        self.assertEqual(self.backend.effect_count(), 0)


    async def test_project_profile_allowlist_is_rechecked_before_input(self):
        extra = Profile('other', 'omp', Path(sys.executable).resolve())
        settings = replace(self.settings, profiles={**self.settings.profiles, 'other': extra})
        self.supervisor = Supervisor(settings, self.state, {'c': self.backend})
        await self.supervisor.approve('c:p')
        self.backend.rows[0]['profile'] = 'other'
        target, observation = await self.observed()
        with self.assertRaises(SupervisionError) as caught:
            await self.supervisor.prompt(target, observation, 'work', 'foreign-profile')
        self.assertEqual(caught.exception.code, 'unsupported_operation')
        self.assertEqual(self.backend.effect_count(), 0)

    async def test_held_start_makes_cross_connection_revoke_busy_without_blocking_reads(self):
        class HoldingBackend(ProcessBackend):
            async def start(self, project, profile, name, worktree_branch, attempt, *, deadline):
                await self.prompt({}, '', profile, deadline=deadline)
                entered.set()
                await release.wait()
                return dict(self.rows[0], nonce=attempt['nonce'])
        entered, release = asyncio.Event(), asyncio.Event()
        held = HoldingBackend(self.base)
        settings = replace(self.settings, connections={**self.settings.connections, 'd': Connection('d', 'herdr', Path(sys.executable), session='fixture')}, projects={'p': replace(self.project, connections=('c', 'd'))})
        supervisor = Supervisor(settings, self.state, {'c': held, 'd': self.backend})
        await supervisor.approve('c:p')
        await supervisor.approve('d:p')
        pending = asyncio.create_task(supervisor.start('p', 'omp', 'held', 'held-start', connection='c'))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            with self.assertRaises(SupervisionError) as caught:
                await supervisor.revoke('d:p')
            self.assertEqual(caught.exception.code, 'busy')
            status = await supervisor.status(connection='d')
            target = status['targets'][0]['target']
            read = await supervisor.read(target)
            waited = await supervisor.wait(target, read['observation'], 0)
            self.assertEqual(waited['reason'], 'timed_out')
        finally:
            release.set()
            result = await pending
        self.assertEqual(result['delivery'], 'confirmed')
        self.assertEqual(held.effect_count(), 1)
        self.assertFalse((await supervisor.revoke('d:p'))['approved'])


    async def test_changed_generation_cannot_refresh_old_managed_record_handles(self):
        await self.supervisor.approve('c:p')
        await self.supervisor.start('p', 'omp', 'agent', 'start-one')
        class RecordBackend(ProcessBackend):
            async def inventory(self, projects, records, *, deadline):
                return [record['native'] for record in records if record.get('state') == 'active']
        backend = RecordBackend(self.base)
        changed = Supervisor(replace(self.settings, generation='replacement'), self.state, {'c': backend})
        status = await changed.status()
        self.assertEqual(status['targets'], [])
        self.assertEqual(status['recovery_count'], 1)
        self.assertFalse(status['recovery'][0]['actionable'])

    async def test_healthy_connection_remains_visible_after_other_cli_deadline(self):
        class HeldBackend(ProcessBackend):
            async def inventory(self, projects, records, *, deadline):
                await run_cli([sys.executable, '-c', 'import time;time.sleep(60)'], deadline=deadline)
                return []
        settings = replace(self.settings, connections={**self.settings.connections, 'd': Connection('d', 'herdr', Path(sys.executable), session='fixture')}, projects={'p': replace(self.project, connections=('c', 'd'))})
        supervisor = Supervisor(settings, self.state, {'c': self.backend, 'd': HeldBackend(self.base)})
        started = time.monotonic()
        status = await supervisor.status()
        self.assertLess(time.monotonic() - started, 20.5)
        self.assertEqual({row['connection'] for row in status['targets']}, {'c'})
        self.assertEqual(status['errors'][0]['connection'], 'd')
        self.assertEqual(status['errors'][0]['error']['code'], 'backend_unavailable')


    async def test_repeated_cancel_during_final_publication_preserves_receipt_and_releases_lock(self):
        await self.supervisor.approve('c:p')
        target, observation = await self.observed()
        original = SupervisionState.finish
        def finish(state, operation_id, result):
            original(state, operation_id, result)
            if state is self.state and operation_id == 'cancelled':
                pending.cancel()
                pending.cancel()
        with patch.object(SupervisionState, 'finish', finish):
            pending = asyncio.create_task(self.supervisor.prompt(target, observation, 'work', 'cancelled'))
            with self.assertRaises(asyncio.CancelledError):
                await pending
        replay = await self.supervisor.prompt(target, observation, 'work', 'cancelled')
        self.assertTrue(replay['historical'])
        self.assertEqual(replay['delivery'], 'confirmed')
        self.assertEqual(self.backend.effect_count(), 1)
        next_result = await self.supervisor.prompt(target, observation, 'separate work', 'after-cancel')
        self.assertEqual(next_result['delivery'], 'confirmed')
        self.assertEqual(self.backend.effect_count(), 2)


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_reaps_ordinary_helpers_inheriting_pipes_but_preserves_detached_backend(self):
        import signal
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / 'pids'
            pids = []

            def live(pid):
                try:
                    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('Z', 'X', 'x')
                except (FileNotFoundError, ProcessLookupError):
                    return False

            command = (
                "import os,pathlib,subprocess,sys\n"
                "pathlib.Path(sys.argv[1]).write_text(f'{os.getpid()}\\n')\n"
                "ordinary=subprocess.Popen(['/usr/bin/sleep','30'])\n"
                "with open(sys.argv[1], 'a') as record: record.write(f'{ordinary.pid}\\n')\n"
                "detached=subprocess.Popen(['/usr/bin/sleep','30'],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                "with open(sys.argv[1], 'a') as record: record.write(f'{detached.pid}\\n')\n"
                "sys.stdout.buffer.write(b'o' * (512 * 1024) + b'leader-stdout-tail')\n"
                "sys.stdout.flush()\n"
                "sys.stderr.buffer.write(b'e' * (512 * 1024) + b'leader-stderr-tail')\n"
                "sys.stderr.flush()\n"
            )
            try:
                code, output, error = await run_cli([sys.executable, '-I', '-c', command, str(pid_file)], deadline=time.monotonic() + 5)
                leader, ordinary, detached = map(int, pid_file.read_text().split())
                pids.extend((leader, ordinary, detached))
                stdout = b'o' * (512 * 1024) + b'leader-stdout-tail'
                stderr = b'e' * (512 * 1024) + b'leader-stderr-tail'
                self.assertEqual((code, output, error), (0, stdout, stderr))
                self.assertNotEqual(os.getpgid(detached), leader)
                end = time.monotonic() + 1
                while live(ordinary) and time.monotonic() < end:
                    await asyncio.sleep(.01)
                self.assertFalse(live(ordinary), 'ordinary request helper survived successful completion')
                self.assertTrue(live(detached), 'detached backend lifetime must not be ended by request cleanup')
            finally:
                if pid_file.exists():
                    pids.extend(map(int, pid_file.read_text().split()))
                for pid in set(pids):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    async def test_cancellation_reaps_ordinary_helpers_inheriting_pipes(self):
        import signal
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / 'pids'
            pids = []

            def live(pid):
                try:
                    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] not in ('Z', 'X', 'x')
                except (FileNotFoundError, ProcessLookupError):
                    return False

            command = (
                "import os,pathlib,subprocess,sys,time\n"
                "helper=subprocess.Popen(['/usr/bin/sleep','30'])\n"
                "pid_file=pathlib.Path(sys.argv[1])\n"
                "pending=pid_file.with_suffix('.pending')\n"
                "pending.write_text(f'{os.getpid()} {helper.pid}')\n"
                "pending.replace(pid_file)\n"
                "time.sleep(30)\n"
            )
            task = asyncio.create_task(run_cli([sys.executable, '-I', '-c', command, str(pid_file)], deadline=time.monotonic() + 5))
            try:
                end = time.monotonic() + 2
                while not pid_file.exists():
                    if task.done():
                        await task
                    if time.monotonic() >= end:
                        self.fail('the CLI leader did not record its inherited-pipe helper')
                    await asyncio.sleep(.01)
                pids.extend(map(int, pid_file.read_text().split()))
                helper = pids[-1]
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                end = time.monotonic() + 1
                while live(helper) and time.monotonic() < end:
                    await asyncio.sleep(.01)
                self.assertFalse(live(helper), 'ordinary helper survived cancellation cleanup')
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                if pid_file.exists():
                    pids.extend(map(int, pid_file.read_text().split()))
                for pid in set(pids):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    async def test_bounded_output_does_not_wait_for_unbounded_child(self):
        with self.assertRaises(SupervisionError):
            await run_cli([sys.executable, '-c', "import sys;sys.stdout.buffer.write(b'x'*5000000)"], deadline=time.monotonic()+5)

    async def test_timeout_reaps_owned_child_and_next_run_works(self):
        with self.assertRaises(SupervisionError):
            await run_cli([sys.executable, '-c', 'import time;time.sleep(10)'], deadline=time.monotonic()+0.1)
        code, output, _ = await run_cli([sys.executable, '-c', "print('next')"], deadline=time.monotonic()+5)
        self.assertEqual((code, output.strip()), (0, b'next'))

    async def test_shared_runner_does_not_spawn_fifth_cli_after_queue_deadline(self):
        from dotunnel.supervision import CliRunner
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            release = base / 'release'
            program = base / 'held.py'
            program.write_text("import pathlib,sys,time\npathlib.Path(sys.argv[1]).touch()\nwhile not pathlib.Path(sys.argv[2]).exists():time.sleep(.01)\n")
            runner = CliRunner()
            tasks = [asyncio.create_task(runner([sys.executable, str(program), str(base / str(i)), str(release)], deadline=time.monotonic()+5)) for i in range(4)]
            try:
                deadline = time.monotonic() + 2
                while not all((base / str(i)).exists() for i in range(4)):
                    if time.monotonic() >= deadline:
                        self.fail('the first four bounded CLI children did not start')
                    await asyncio.sleep(.01)
                with self.assertRaises(SupervisionError) as caught:
                    await runner([sys.executable, str(program), str(base / 'fifth'), str(release)], deadline=time.monotonic()+.1)
                self.assertEqual(caught.exception.code, 'backend_unavailable')
                self.assertFalse((base / 'fifth').exists())
            finally:
                release.touch()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                await runner.aclose()
            self.assertTrue(all(isinstance(result, tuple) and result[0] == 0 for result in results))
