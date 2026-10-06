import hashlib
import json
import subprocess
import sys
import unittest
from unittest import mock

from .adapter_support import Fixture, SOURCE


class MutationContractTests(unittest.TestCase):
    def test_fixed_task_workspace_home_does_not_reject_operator_registry(self):
        with Fixture() as fixture:
            with mock.patch.dict('os.environ', {'HOME': str(fixture.workspace)}):
                result, report = fixture.execute(fixture.request(action='read_output'))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['status']['job_state'], 'completed')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_project_opt_in_without_exact_grant_has_no_effect(self):
        with Fixture() as fixture:
            result, report = fixture.execute(fixture.request())
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report['code'], 'approval_required')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_granted_operation_replay_returns_same_job_without_second_effect(self):
        with Fixture() as fixture:
            request = fixture.request()
            fixture.grant(request)
            first_result, first = fixture.execute(request)
            self.assertEqual(first_result.returncode, 0, first_result.stderr)
            self.assertEqual(first['status']['job_state'], 'completed')
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)
            calls = fixture.backend_snapshot()['calls']
            request['request_id'] = 'replay-1'
            fixture.configuration['project']['protected'] = True
            fixture.save_config()
            replay_result, replay = fixture.execute(request)
            self.assertEqual(replay_result.returncode, 0, replay_result.stderr)
            self.assertEqual(replay['job']['job_id'], first['job']['job_id'])
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)
            self.assertEqual(fixture.backend_snapshot()['calls'], calls)

    def test_reusing_operation_id_with_changed_payload_refuses_new_effect(self):
        with Fixture() as fixture:
            request = fixture.request()
            fixture.grant(request)
            result, _ = fixture.execute(request)
            self.assertEqual(result.returncode, 0, result.stderr)
            changed = fixture.request(request_id='changed-1', instruction='Different selected operation.')
            changed['authorization'] = request['authorization']
            changed_result, report = fixture.execute(changed)
            self.assertNotEqual(changed_result.returncode, 0)
            self.assertEqual(report['code'], 'operation_conflict')
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)

    def test_ambiguous_dispatch_is_not_repeated_after_runner_restart(self):
        with Fixture() as fixture:
            fixture.mode(mode='effect_then_fail')
            request = fixture.request()
            fixture.grant(request)
            first_result, first = fixture.execute(request)
            self.assertNotEqual(first_result.returncode, 0)
            self.assertEqual(first['outcome'], 'unknown')
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)
            calls = fixture.backend_snapshot()['calls']
            request['request_id'] = 'unknown-replay'
            fixture.mode(mode='normal')
            second_result, second = fixture.execute(request)
            self.assertNotEqual(second_result.returncode, 0)
            self.assertEqual(second['outcome'], 'unknown')
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)
            self.assertEqual(fixture.backend_snapshot()['calls'], calls)

    def test_protected_project_denies_previously_granted_mutation(self):
        with Fixture() as fixture:
            request = fixture.request()
            fixture.grant(request)
            fixture.configuration['project']['protected'] = True
            fixture.save_config()
            result, report = fixture.execute(request)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report['code'], 'protected_project')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_stale_target_and_prompt_refuse_before_effect(self):
        for action, change in (
            ('submit', {'generation': 'generation-2'}),
            ('answer', {'prompt_revision': 2}),
        ):
            with self.subTest(action=action), Fixture() as fixture:
                request = fixture.request(action=action)
                fixture.grant(request)
                fixture.mode(**change)
                result, report = fixture.execute(request)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report['code'], 'stale_target')
                self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_target_replaced_between_inspect_and_dispatch_cannot_receive_effect(self):
        with Fixture() as fixture:
            fixture.mode(mode='race')
            request = fixture.request()
            fixture.grant(request)
            result, report = fixture.execute(request)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(report['outcome'], ('refused', 'unknown'))
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_revoked_exact_grant_cannot_dispatch(self):
        with Fixture() as fixture:
            request = fixture.request()
            grant_id = fixture.grant(request)
            sys.path.insert(0, str(SOURCE))
            from dotunnel_adapter.state import Store
            store = Store(fixture.state_dir)
            try:
                self.assertTrue(store.revoke_grant(grant_id))
            finally:
                store.close()
            result, report = fixture.execute(request)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report['code'], 'approval_required')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_cancel_requires_owned_record_and_exact_attempt(self):
        with Fixture() as fixture:
            foreign = fixture.request(action='cancel', job_id='foreign-job', attempt_id='foreign-attempt')
            fixture.grant(foreign)
            denied, report = fixture.execute(foreign)
            self.assertNotEqual(denied.returncode, 0)
            self.assertEqual(report['code'], 'target_identity_unverifiable')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)
            start = fixture.request(action='start', request_id='start-1', operation_id='start-operation')
            fixture.grant(start)
            started_result, started = fixture.execute(start)
            self.assertEqual(started_result.returncode, 0, started_result.stderr)
            job = started['job']
            cancel = fixture.request(
                action='cancel', request_id='cancel-1', operation_id='cancel-operation',
                target=job['target'], job_id=job['job_id'], attempt_id=job['attempt_id'],
            )
            fixture.grant(cancel)
            cancelled_result, cancelled = fixture.execute(cancel)
            self.assertEqual(cancelled_result.returncode, 0, cancelled_result.stderr)
            self.assertEqual(cancelled['outcome'], 'ok')
            self.assertEqual(fixture.backend_snapshot()['effects'], 2)

    def test_state_loss_after_effect_is_unknown_and_restored_prepared_replay_never_dispatches(self):
        with Fixture() as fixture:
            fixture.mode(mode='replace_state_after_effect')
            request = fixture.request()
            fixture.grant(request)
            result, report = fixture.execute(request)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report['outcome'], 'unknown')
            self.assertEqual(report['code'], 'outcome_unknown')
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)
            job = report['job']
            (fixture.state_dir / 'state.sqlite3').unlink()
            (fixture.state_dir / 'state.previous').rename(fixture.state_dir / 'state.sqlite3')
            fixture.mode(mode='normal')
            request['request_id'] = 'replay-after-state-loss'
            replayed, replay = fixture.execute(request)
            self.assertNotEqual(replayed.returncode, 0)
            self.assertEqual(replay['outcome'], 'unknown')
            self.assertEqual(replay['job']['job_id'], job['job_id'])
            self.assertEqual(fixture.backend_snapshot()['effects'], 1)

    def test_signal_at_prepared_return_is_unknown_with_owned_job_and_no_redispatch(self):
        with Fixture() as fixture:
            request = fixture.request()
            fixture.grant(request)
            fixture.stage(request)
            entry = (
                "import os,signal,sys\n"
                "sys.path.insert(0,sys.argv.pop(1))\n"
                "from dotunnel_adapter.state import Store\n"
                "original=Store.begin_operation\n"
                "def interrupted(self,*args,**kwargs):\n"
                " result=original(self,*args,**kwargs)\n"
                " if result is None: os.kill(os.getpid(),signal.SIGTERM)\n"
                " return result\n"
                "Store.begin_operation=interrupted\n"
                "from dotunnel_adapter.cli import main\n"
                "raise SystemExit(main())\n"
            )
            invoked = subprocess.run(
                [sys.executable, '-I', '-c', entry, str(SOURCE), 'run',
                 '--config', str(fixture.config_path)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(invoked.returncode, 0)
            summary = json.loads(invoked.stdout)
            raw = (fixture.workspace / summary['report']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), summary['sha256'])
            report = json.loads(raw)
            self.assertEqual(report['outcome'], 'unknown')
            self.assertEqual(report['code'], 'outcome_unknown')
            job = report['job']
            calls = fixture.backend_snapshot()['calls']
            request['request_id'] = 'replay-after-signal'
            _, replay = fixture.execute(request)
            self.assertEqual(replay['job']['job_id'], job['job_id'])
            self.assertEqual(replay['outcome'], 'unknown')
            self.assertEqual(fixture.backend_snapshot()['calls'], calls)
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_termination_after_effect_preserves_owned_job_in_unknown_report(self):
        for signum in ('SIGTERM', 'SIGINT'):
            with self.subTest(signum=signum), Fixture() as fixture:
                request = fixture.request()
                fixture.grant(request)
                fixture.stage(request)
                entry = (
                    "import os,signal,sys\n"
                    "sys.path.insert(0,sys.argv.pop(1))\n"
                    "from dotunnel_adapter import runner\n"
                    "original=runner.process_request\n"
                    "def interrupted(*args,**kwargs):\n"
                    " result=original(*args,**kwargs)\n"
                    f" os.kill(os.getpid(),signal.{signum})\n"
                    " return result\n"
                    "runner.process_request=interrupted\n"
                    "from dotunnel_adapter.cli import main\n"
                    "raise SystemExit(main())\n"
                )
                invoked = subprocess.run(
                    [sys.executable, '-I', '-c', entry, str(SOURCE), 'run',
                     '--config', str(fixture.config_path)],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertNotEqual(invoked.returncode, 0)
                summary = json.loads(invoked.stdout)
                report = json.loads((fixture.workspace / summary['report']).read_bytes())
                self.assertEqual(report['outcome'], 'unknown')
                self.assertEqual(report['code'], 'outcome_unknown')
                job = report['job']
                self.assertEqual(fixture.backend_snapshot()['effects'], 1)
                request['request_id'] = 'replay-after-post-effect-signal'
                _, replay = fixture.execute(request)
                self.assertEqual(replay['job'], job)
                self.assertEqual(fixture.backend_snapshot()['effects'], 1)

    def test_existing_or_unsafe_report_destination_preserves_pending_and_never_dispatches(self):
        for collision in (True, False):
            with self.subTest(collision=collision), Fixture() as fixture:
                reports = fixture.workspace / 'reports'
                reports.mkdir(mode=0o700 if collision else 0o755)
                existing = reports / 'request-1.json'
                if collision:
                    existing.write_text('preserve existing report')
                    existing.chmod(0o600)
                request = fixture.request()
                fixture.grant(request)
                fixture.stage(request)
                result = fixture.command('run')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('request_conflict', result.stderr)
                self.assertTrue((fixture.workspace / 'pending.json').exists())
                self.assertEqual(fixture.backend_snapshot()['effects'], 0)
                if collision:
                    self.assertEqual(existing.read_text(), 'preserve existing report')

    def test_changed_fixed_profile_or_policy_cannot_admit_an_old_grant(self):
        for change in ('argv', 'policy'):
            with self.subTest(change=change), Fixture() as fixture:
                request = fixture.request()
                fixture.grant(request)
                if change == 'argv':
                    fixture.configuration['backend']['argv'].append('new-reviewed-profile')
                else:
                    fixture.configuration['project']['operations'].remove('answer')
                fixture.save_config()
                result, report = fixture.execute(request)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report['code'], 'approval_required')
                self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_private_config_under_owner_readable_nonwritable_ancestor_runs(self):
        with Fixture() as fixture:
            fixture.base.chmod(0o750)
            result, report = fixture.execute(fixture.request(action='read_output'))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['status']['job_state'], 'completed')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_near_limit_effect_report_reserves_replay_overhead_and_never_claims_refusal(self):
        with Fixture() as fixture:
            fixture.mode(mode='padded_report', padding=100)
            trial = fixture.request(request_id='a', operation_id='trial-operation')
            fixture.grant(trial)
            result, _ = fixture.execute(trial)
            self.assertEqual(result.returncode, 0, result.stderr)
            overhead = len((fixture.workspace / 'reports' / 'a.json').read_bytes()) - 100
            fixture.mode(padding=65536 - overhead - 20)
            request = fixture.request(request_id='b', operation_id='edge-operation')
            fixture.grant(request)
            _, saved = fixture.execute(request)
            self.assertEqual(saved['outcome'], 'unknown')
            calls = fixture.backend_snapshot()['calls']
            request['request_id'] = 'r' * 64
            _, replay = fixture.execute(request)
            self.assertEqual(replay['outcome'], 'unknown')
            self.assertEqual(replay['job']['job_id'], saved['job']['job_id'])
            self.assertEqual(fixture.backend_snapshot()['calls'], calls)
            self.assertEqual(fixture.backend_snapshot()['effects'], 2)

    def test_report_frame_overhead_produces_a_bounded_resource_refusal(self):
        with Fixture() as fixture:
            fixture.mode(mode='edge_report')
            result, report = fixture.execute(fixture.request(action='read_output'))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report['outcome'], 'refused')
            self.assertEqual(report['code'], 'resource_limit')
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)

    def test_historical_report_never_substitutes_a_different_revision_or_cursor(self):
        with Fixture() as fixture:
            start = fixture.request(action='start', request_id='start-1')
            fixture.grant(start)
            result, saved = fixture.execute(start)
            self.assertEqual(result.returncode, 0, result.stderr)
            job = saved['job']
            calls = fixture.backend_snapshot()['calls']
            for index, selector in enumerate((
                {'revision': saved['status']['revision'] + 1},
                {'cursor': 'missing-page'},
            )):
                selected = fixture.request(
                    action='report', request_id=f'history-miss-{index}',
                    target=job['target'], job_id=job['job_id'],
                    attempt_id=job['attempt_id'], **selector,
                )
                denied, report = fixture.execute(selected)
                self.assertNotEqual(denied.returncode, 0)
                self.assertEqual(report['code'], 'unsupported')
            selected = fixture.request(
                action='report', request_id='history-exact', target=job['target'],
                job_id=job['job_id'], attempt_id=job['attempt_id'],
                revision=saved['status']['revision'],
            )
            retrieved, report = fixture.execute(selected)
            self.assertEqual(retrieved.returncode, 0, retrieved.stderr)
            self.assertTrue(report['historical'])
            self.assertEqual(report['status'], saved['status'])
            self.assertEqual(fixture.backend_snapshot()['calls'], calls)

    def test_piped_operator_approval_cannot_mint_a_grant(self):
        with Fixture() as fixture:
            request = fixture.request()
            fixture.stage(request)
            denied = fixture.command('approve')
            self.assertNotEqual(denied.returncode, 0)
            invoked = fixture.command('run')
            self.assertNotEqual(invoked.returncode, 0)
            self.assertEqual(fixture.backend_snapshot()['effects'], 0)


if __name__ == '__main__':
    unittest.main()
