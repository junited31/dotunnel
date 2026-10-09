import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from dotunnel.cli_backend import (
    _OmpStreamCollector,
    _parse_omp_stream,
    _run_process,
    _validate_runtime,
    run_native,
)


class NativeStreamTests(unittest.TestCase):
    def parse(self, text, exit_code=0):
        return _parse_omp_stream(text.encode("utf-8"), exit_code)

    def test_omp_preserves_summary_text_after_osc_terminators(self):
        cases = (
            ("before \x1b]0;title\x1b\\ after", "before  after"),
            ("before \x1b]0;title\x07 after", "before  after"),
            (
                "before \x1b]8;;https://example.invalid\x1b\\label\x1b]8;;\x1b\\ after",
                "before label after",
            ),
            ("before\x1b]0;first\x1b\\middle\x1b]0;second\x07after", "beforemiddleafter"),
            ("before \x1b]0;unfinished", "before"),
        )
        for summary, expected in cases:
            with self.subTest(summary=summary):
                terminal = {
                    "type": "agent_end",
                    "isTerminal": True,
                    "messages": [{
                        "role": "assistant", "stopReason": "stop",
                        "content": [{"type": "text", "text": summary}],
                    }],
                }
                self.assertEqual(self.parse(json.dumps(terminal) + "\n"), expected)

    def test_omp_rejects_oversized_visible_summary_after_osc_st(self):
        terminal = {
            "type": "agent_end",
            "isTerminal": True,
            "messages": [{
                "role": "assistant", "stopReason": "stop",
                "content": [{"type": "text", "text": "prefix \x1b]0;title\x1b\\" + "x" * 2049}],
            }],
        }
        with self.assertRaises(ValueError):
            self.parse(json.dumps(terminal) + "\n")

    def test_omp_requires_a_completed_agent_with_final_assistant_text(self):
        self.assertEqual(
            self.parse(
                '{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
                '"stopReason":"stop","content":[{"type":"text",'
                '"text":"review complete"}]}]}\n',
            ),
            "review complete",
        )
        for stream in (
            '{"type":"agent_end","messages":[]}\n',
            '{"type":"message_end","message":{"role":"assistant",'
            '"content":[{"type":"text","text":"not terminal"}]}}\n',
            '{"type":"agent_end","isTerminal":false,"messages":[{"role":"assistant",'
            '"content":[{"type":"text","text":"not terminal"}]}]}\n',
            '{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
            '"stopReason":"stop","content":[{"type":"text","text":"   "}]}]}\n',
        ):
            with self.subTest(stream=stream), self.assertRaises(ValueError):
                self.parse(stream)

    def test_omp_aborted_turn_fails_even_when_cli_exits_zero(self):
        stream = (
            '{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
            '"stopReason":"aborted","content":[{"type":"text",'
            '"text":"partial response"}]}]}\n'
        )
        with self.assertRaises(ValueError):
            self.parse(stream, exit_code=0)

    def test_omp_recovery_requires_a_successful_final_terminal_snapshot(self):
        retry = (
            '{"type":"notice","level":"error","message":"auxiliary diagnostic"}\n'
            '{"type":"message_update","assistantMessageEvent":{"type":"error","reason":"attempt failed"}}\n'
            '{"type":"turn_end","message":{"role":"assistant","stopReason":"error"}}\n'
            '{"type":"agent_end","isTerminal":false,"messages":[]}\n'
            '{"type":"auto_retry_start","attempt":1}\n'
        )
        completed = (
            '{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
            '"stopReason":"stop","content":[{"type":"text","text":"recovered review"}]}]}\n'
        )
        self.assertEqual(self.parse(retry + completed), "recovered review")
        for incomplete in (
            retry,
            retry + completed.replace('"stopReason":"stop"', '"stopReason":"error"'),
            retry + completed + '{"type":"agent_end","isTerminal":false,"messages":[]}\n',
        ):
            with self.subTest(stream=incomplete), self.assertRaises(ValueError):
                self.parse(incomplete)

    def test_omp_rejects_completion_followed_by_unfinished_new_agent(self):
        completion = (
            '{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
            '"stopReason":"stop","content":[{"type":"text","text":"old completion"}]}]}\n'
        )
        for start_event in ('{"type":"agent_start"}\n', '{"type":"turn_start"}\n'):
            with self.subTest(start_event=start_event), self.assertRaises(ValueError):
                self.parse(completion + start_event)


    def test_native_stream_rejects_malformed_utf8_json_duplicate_nonfinite_and_nonzero_exit(self):
        for stream, exit_code in (
            (b"\xff\n", 0),
            (b"not-json\n", 0),
            (b'{"type":"progress","type":"message_update"}\n', 0),
            (b'{"type":"progress","value":NaN}\n', 0),
            (b'{"type":"progress","value":1e9999}\n', 0),
            (b"[]\n", 0),
            (b'{"value":"missing event type"}\n', 0),
            (b'{"type":1}\n', 0),
            (b'{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
             b'"stopReason":"stop","content":[{"type":"text","text":"done"}]}]}\n', 3),
        ):
            with self.subTest(stream=stream, exit_code=exit_code), self.assertRaises(ValueError):
                _parse_omp_stream(stream, exit_code)

    def test_oversized_completed_review_is_rejected_instead_of_truncated(self):
        stream = json.dumps(
            {
                "type": "agent_end",
                "isTerminal": True,
                "messages": [{"role": "assistant", "stopReason": "stop", "content": [{"type": "text", "text": "é" * 1500}]}],
            }
        ) + "\n"

        with self.assertRaises(ValueError):
            self.parse(stream)


    def test_json_unicode_line_characters_do_not_split_native_frames(self):
        summary = "first\u0085second\u2028third\u2029fourth"
        stream = json.dumps(
            {
                "type": "agent_end", "isTerminal": True,
                "messages": [{"role": "assistant", "stopReason": "stop",
                              "content": [{"type": "text", "text": summary}]}],
            },
            ensure_ascii=False,
        ) + "\n"
        self.assertEqual(self.parse(stream), summary.replace("\u0085", ""))

    def test_omp_accepts_complete_final_frame_without_newline_and_rejects_invalid_tail(self):
        completion = (
            '{"type":"agent_end","isTerminal":true,"messages":[{"role":"assistant",'
            '"stopReason":"stop","content":[{"type":"text","text":"complete"}]}]}'
        )
        self.assertEqual(self.parse(completion), "complete")
        for tail in ('{"type":', '{"type":"progress","value":'):
            with self.subTest(tail=tail), self.assertRaises(ValueError):
                self.parse(completion + "\n" + tail)

    def test_omp_requires_explicit_native_stop_reason(self):
        for stop_reason in (None, "error", "aborted", "toolUse", "length", "unknown"):
            assistant = {"role": "assistant", "content": [{"type": "text", "text": "partial"}]}
            if stop_reason is not None:
                assistant["stopReason"] = stop_reason
            stream = json.dumps(
                {"type": "agent_end", "isTerminal": True, "messages": [assistant]}
            )
            with self.subTest(stop_reason=stop_reason), self.assertRaises(ValueError):
                self.parse(stream)

    def test_omp_later_terminal_success_recovers_from_failed_terminal(self):
        failed = {
            "type": "agent_end",
            "isTerminal": True,
            "messages": [{"role": "assistant", "stopReason": "error", "content": [{"type": "text", "text": "failed"}]}],
        }
        completed = {
            "type": "agent_end",
            "isTerminal": True,
            "messages": [{"role": "assistant", "stopReason": "stop", "content": [{"type": "text", "text": "recovered"}]}],
        }
        stream = "\n".join((json.dumps(failed), json.dumps({"type": "auto_retry_start"}), json.dumps(completed)))
        self.assertEqual(self.parse(stream), "recovered")

    def test_omp_collector_handles_utf8_and_newline_split_across_chunks(self):
        progress = b'{"type":"message_update","value":"progress"}'
        completion = json.dumps(
            {
                "type": "agent_end",
                "isTerminal": True,
                "messages": [{"role": "assistant", "stopReason": "stop", "content": [{"type": "text", "text": "café"}]}],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        stream = progress + b"\n" + completion
        newline = len(progress)
        utf8_split = stream.index("é".encode("utf-8")) + 1
        collector = _OmpStreamCollector()
        collector.feed(stream[:newline])
        collector.feed(stream[newline:utf8_split])
        collector.feed(stream[utf8_split:])
        self.assertEqual(collector.finish(0), "café")


class NativeProcessTests(unittest.TestCase):
    def test_deadline_kills_and_reaps_the_owned_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid_file = Path(directory) / "child.pid"
            child_code = "import time; time.sleep(60)"
            parent_code = (
                "import subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                f"open({str(child_pid_file)!r},'w').write(str(child.pid)); "
                "time.sleep(60)"
            )
            result = _run_process(
                [sys.executable, "-c", parent_code],
                b"",
                deadline_seconds=0.2,
            )
            self.assertTrue(result.timed_out)
            self.assertIsNotNone(result.exit_code)
            child_pid = int(child_pid_file.read_text())
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    state = Path(f"/proc/{child_pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
                except (FileNotFoundError, ProcessLookupError):
                    break
                if state in {"Z", "X"}:
                    break
                time.sleep(0.02)
            else:
                self.fail("owned process-group descendant survived deadline cleanup")
    def test_process_output_capture_is_bounded_and_reports_truncation(self):
        code = "import os; os.write(1,b'x'*1100000); os.write(2,b'y'*100000)"
        result = _run_process(
            [sys.executable, "-c", code],
            b"",
            deadline_seconds=5,
        )

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 1024 * 1024)

    def run_omp_child(self, code):
        collector = _OmpStreamCollector()
        result = _run_process(
            [sys.executable, "-c", code],
            b"",
            deadline_seconds=5,
            stdout_collector=collector,
        )
        return result, collector

    def test_omp_process_accepts_cumulative_stream_over_one_megabyte(self):
        progress_frame = b'{"type":"progress","payload":"' + b"x" * 60_000 + b'"}\n'
        completion = json.dumps(
            {
                "type": "agent_end",
                "isTerminal": True,
                "messages": [{"role": "assistant", "stopReason": "stop", "content": [{"type": "text", "text": "done"}]}],
            }
        ).encode("utf-8") + b"\n"
        self.assertGreater(len(progress_frame) * 20 + len(completion), 1024 * 1024)
        code = (
            "import json,sys\n"
            "progress={'type':'progress','payload':'x'*60000}\n"
            "completion={'type':'agent_end','isTerminal':True,'messages':["
            "{'role':'assistant','stopReason':'stop','content':[{'type':'text','text':'done'}]}]}\n"
            "frame=json.dumps(progress).encode()+b'\\n'\n"
            "terminal=json.dumps(completion).encode()+b'\\n'\n"
            "sys.stdout.buffer.write(frame*20+terminal)\n"
        )
        result, collector = self.run_omp_child(code)
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.truncated)
        self.assertEqual(collector.finish(result.exit_code), "done")

    def test_omp_process_rejects_single_oversized_final_frame(self):
        code = (
            "import json,sys\n"
            "event={'type':'agent_end','isTerminal':True,'messages':["
            "{'role':'user','content':[{'type':'text','text':'x'*1100000}]},"
            "{'role':'assistant','stopReason':'stop','content':[{'type':'text','text':'small'}]}]}\n"
            "sys.stdout.buffer.write(json.dumps(event,separators=(',',':')).encode())\n"
        )
        result, collector = self.run_omp_child(code)
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.truncated)
        with self.assertRaises(ValueError):
            collector.finish(result.exit_code)


    @unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/bwrap").is_file(), "bubblewrap is required")
    def test_bubblewrap_keeps_review_readonly_and_only_editable_candidate_writable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir(mode=0o700)
            editable = snapshot / "editable.txt"
            protected = snapshot / "protected.txt"
            editable.write_text("original candidate\n")
            protected.write_text("protected candidate\n")
            host_source = root / "source-host.txt"
            host_source.write_text("must never be visible\n")

            modules = root / "modules"
            modules.mkdir()
            (modules / "cli.js").write_text("// runtime fixture\n")
            config = root / "config.yml"
            auth = root / "agent.db"
            config.write_text("models: {}\n")
            auth.write_bytes(b"opaque test fixture")
            executable = root / "fixture-bun"
            executable.write_text(
                "#!/usr/bin/python3\n"
                "from pathlib import Path\n"
                f"hidden = not Path({str(host_source)!r}).exists()\n"
                "protected = False\n"
                "try:\n"
                "    Path('/workspace/protected.txt').write_text('changed')\n"
                "except OSError:\n"
                "    protected = True\n"
                "editable_writable = False\n"
                "try:\n"
                "    Path('/workspace/editable.txt').write_text('edited candidate\\n')\n"
                "    editable_writable = True\n"
                "except OSError:\n"
                "    pass\n"
                "import json\n"
                "expected_writable = Path('/workspace/expect-edit').exists()\n"
                "ok = hidden and protected and editable_writable == expected_writable\n"
                "text = 'sandbox boundary exercised' if ok else 'sandbox boundary violated'\n"
                "message = {'role':'assistant','stopReason':'stop','content':[{'type':'text','text':text}]}\n"
                "print(json.dumps({'type':'agent_end','isTerminal':True,'messages':[message]}), flush=True)\n"
            )
            executable.chmod(0o700)
            runtime = {
                "executable": str(executable),
                "cli": str(modules / "cli.js"),
                "modules": str(modules),
                "config": str(config),
                "auth": str(auth),
            }

            reviewed = run_native("omp", runtime, snapshot, (), "review", "Check files.")
            self.assertEqual(reviewed["status"], "completed")
            self.assertEqual(reviewed["summary"], "sandbox boundary exercised")
            self.assertEqual(editable.read_text(), "original candidate\n")
            self.assertEqual(protected.read_text(), "protected candidate\n")

            (snapshot / "expect-edit").write_text("This candidate file is not editable.\n")
            edited = run_native("omp", runtime, snapshot, ("editable.txt",), "edit", "Update candidate.")
            self.assertEqual(edited["status"], "completed")
            self.assertEqual(edited["summary"], "sandbox boundary exercised")
            self.assertEqual(editable.read_text(), "edited candidate\n")
            self.assertEqual(protected.read_text(), "protected candidate\n")
            self.assertEqual(host_source.read_text(), "must never be visible\n")

    @unittest.skipUnless(sys.platform == "linux" and Path("/usr/bin/bwrap").is_file(), "bubblewrap is required")
    def test_claude_bubblewrap_passes_token_by_environment_and_exposes_only_approved_candidate_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir(mode=0o700)
            editable = snapshot / "editable.txt"
            protected = snapshot / "tests" / "protected.txt"
            protected.parent.mkdir(mode=0o700)
            unlisted = snapshot / "unlisted.txt"
            editable.write_text("original candidate\n")
            protected.write_text("protected candidate\n")
            unlisted.write_text("unlisted candidate\n")

            host_source = root / "host-source.txt"
            original = root / "original.py"
            token_file = root / "claude-oauth-token"
            host_source.write_text("host source must stay hidden\n")
            original.write_text("original source must stay unchanged\n")
            token_file.write_text("sk-ant-oat01-synthetic_TOKEN-value\n")
            token_file.chmod(0o600)
            host_home = root / "host-home"
            markers = [
                host_home / ".claude.json",
                host_home / ".claude" / "settings.json",
                host_home / ".claude" / "settings.local.json",
                host_home / ".claude" / "hooks" / "pre-tool.py",
                host_home / ".claude" / "skills" / "sample" / "SKILL.md",
                host_home / ".claude" / "plugins" / "sample" / "plugin.json",
                host_home / ".claude" / "mcp.json",
                host_home / ".claude" / "projects" / "session.jsonl",
                host_home / ".config" / "google-chrome" / "Default" / "Cookies",
            ]
            for marker in markers:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text("synthetic host-only fixture\n")

            executable = root / "claude-fixture"
            executable.write_text(
                "#!/usr/bin/python3\n"
                "import json\n"
                "import os\n"
                "from pathlib import Path\n"
                "def write(path, text):\n"
                "    try:\n"
                "        Path(path).write_text(text, encoding='utf-8')\n"
                "        return True\n"
                "    except OSError:\n"
                "        return False\n"
                "def atomic_write(path, text):\n"
                "    destination = Path(path)\n"
                "    temporary = destination.with_name(destination.name + '.owned-tmp')\n"
                "    try:\n"
                "        temporary.write_text(text, encoding='utf-8')\n"
                "        temporary.replace(destination)\n"
                "        return True\n"
                "    except OSError:\n"
                "        return False\n"
                "    finally:\n"
                "        try:\n"
                "            temporary.unlink()\n"
                "        except OSError:\n"
                "            pass\n"
                f"host_paths = {tuple(map(str, (host_source, original, token_file, *markers)))!r}\n"
                "observations = {\n"
                "    'home_isolated': os.environ.get('HOME') == '/home/job',\n"
                "    'host_paths_hidden': all(not Path(path).exists() for path in host_paths),\n"
                "    'docker_hidden': not Path('/run/docker.sock').exists(),\n"
                "    'home_has_no_global_config': not Path('/home/job/.claude.json').exists(),\n"
                "    'home_has_no_settings': not Path('/home/job/.claude/settings.json').exists(),\n"
                "    'home_has_no_hooks': not Path('/home/job/.claude/hooks').exists(),\n"
                "    'home_has_no_skills': not Path('/home/job/.claude/skills').exists(),\n"
                "    'home_has_no_plugins': not Path('/home/job/.claude/plugins').exists(),\n"
                "    'home_has_no_mcp': not Path('/home/job/.claude/mcp.json').exists(),\n"
                "    'home_has_no_sessions': not Path('/home/job/.claude/projects').exists(),\n"
                "    'home_has_no_chrome': not Path('/home/job/.config/google-chrome').exists(),\n"
                "    'editable_write': atomic_write('/workspace/editable.txt', 'changed candidate\\n'),\n"
                "    'protected_write': write('/workspace/tests/protected.txt', 'changed protected'),\n"
                "    'unlisted_write': write('/workspace/unlisted.txt', 'changed unlisted'),\n"
                "    'unlisted_atomic_write': atomic_write('/workspace/unlisted.txt', 'changed unlisted'),\n"
                "    'protected_directory_write': write('/workspace/tests/new.txt', 'new protected entry'),\n"
                "    'new_entry_write': write('/workspace/new.txt', 'new candidate'),\n"
                "}\n"
                "observations['token_in_environment'] = os.environ.get('CLAUDE_CODE_OAUTH_TOKEN') == 'sk-ant-oat01-synthetic_TOKEN-value'\n"
                "observations['no_credentials_file'] = not Path('/home/job/.claude/.credentials.json').exists()\n"
                "result = json.dumps(observations, sort_keys=True)\n"
                "print(json.dumps({'type':'result','subtype':'success','is_error':False,"
                "'terminal_reason':'completed','api_error_status':None,'permission_denials':[],"
                "'queued_turn_count':0,'result_index':0,'result':result}), flush=True)\n"
            )
            executable.chmod(0o700)
            runtime = {"executable": str(executable), "oauth_token": str(token_file)}
            initial_files = {
                "editable.txt": b"original candidate\n",
                "protected.txt": b"protected candidate\n",
                "unlisted.txt": b"unlisted candidate\n",
            }
            initial_root_entries = sorted(path.name for path in snapshot.iterdir())

            reviewed = run_native("claude", runtime, snapshot, ("editable.txt",), "review", "Review files.")
            self.assertEqual(reviewed["status"], "completed")
            review_observations = json.loads(reviewed["summary"])
            self.assertFalse(review_observations["editable_write"])

            edited = run_native("claude", runtime, snapshot, ("editable.txt",), "edit", "Update candidate.")
            self.assertEqual(edited["status"], "completed")
            edit_observations = json.loads(edited["summary"])
            self.assertTrue(edit_observations["editable_write"])
            self.assertFalse(review_observations["new_entry_write"])
            self.assertTrue(edit_observations["new_entry_write"])

            for observations in (review_observations, edit_observations):
                self.assertFalse(observations["protected_write"])
                self.assertFalse(observations["unlisted_write"])
                self.assertFalse(observations["unlisted_atomic_write"])
                self.assertFalse(observations["protected_directory_write"])
                self.assertTrue(observations["token_in_environment"])
                self.assertTrue(observations["no_credentials_file"])
                self.assertTrue(observations["home_isolated"])
                self.assertTrue(observations["host_paths_hidden"])
                self.assertTrue(observations["docker_hidden"])
                self.assertTrue(observations["home_has_no_global_config"])
                self.assertTrue(observations["home_has_no_settings"])
                self.assertTrue(observations["home_has_no_hooks"])
                self.assertTrue(observations["home_has_no_skills"])
                self.assertTrue(observations["home_has_no_plugins"])
                self.assertTrue(observations["home_has_no_mcp"])
                self.assertTrue(observations["home_has_no_sessions"])
                self.assertTrue(observations["home_has_no_chrome"])
            self.assertEqual(editable.read_bytes(), b"changed candidate\n")
            self.assertEqual(protected.read_bytes(), initial_files["protected.txt"])
            self.assertEqual(unlisted.read_bytes(), initial_files["unlisted.txt"])
            self.assertEqual(sorted(path.name for path in snapshot.iterdir()), sorted([*initial_root_entries, "new.txt"]))
            self.assertEqual(host_source.read_text(), "host source must stay hidden\n")
            self.assertEqual(original.read_text(), "original source must stay unchanged\n")
            self.assertEqual(token_file.read_text(), "sk-ant-oat01-synthetic_TOKEN-value\n")

    def test_claude_oauth_token_file_must_be_private_single_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            executable = root / "claude"
            executable.write_text("#!/bin/sh\n")
            executable.chmod(0o700)
            token_file = root / "token"

            def runtime():
                return {"executable": str(executable), "oauth_token": str(token_file)}

            token_file.write_text("  sk-ant-oat01-valid_token-1234567890\n")
            token_file.chmod(0o600)
            validated = _validate_runtime("claude", runtime(), snapshot)
            self.assertEqual(validated["oauth_token"], "sk-ant-oat01-valid_token-1234567890")

            rejected = {
                "group_readable": ("sk-ant-oat01-valid_token-1234567890\n", 0o640),
                "world_readable": ("sk-ant-oat01-valid_token-1234567890\n", 0o604),
                "empty": ("\n", 0o600),
                "two_values": ("sk-ant-oat01-first_value-123 second\n", 0o600),
                "two_lines": ("sk-ant-oat01-first_value-123\nsecond_value\n", 0o600),
                "oversized": ("a" * 5000, 0o600),
            }
            for name, (content, mode) in rejected.items():
                with self.subTest(case=name):
                    token_file.write_text(content)
                    token_file.chmod(mode)
                    with self.assertRaises(ValueError) as raised:
                        _validate_runtime("claude", runtime(), snapshot)
                    self.assertNotIn("sk-ant", str(raised.exception))

            token_file.write_text("sk-ant-oat01-valid_token-1234567890\n")
            token_file.chmod(0o600)
            link = root / "token-link"
            link.symlink_to(token_file)
            hardlink = root / "token-hardlink"
            os.link(token_file, hardlink)
            for path in (link, token_file):
                with self.subTest(path=path.name), self.assertRaises(ValueError):
                    _validate_runtime("claude", {"executable": str(executable), "oauth_token": str(path)}, snapshot)


    def test_invalid_instruction_is_rejected_before_runtime_paths_are_opened(self):
        class RuntimeProbe(dict):
            def keys(self):
                raise AssertionError("runtime metadata was accessed")

        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory)
            runtime = RuntimeProbe(executable="", cli="", modules="", config="", auth="")
            for instruction in ("bad\x00prompt", "\ud800", "x" * 8193):
                with self.subTest(instruction=repr(instruction)), self.assertRaises(ValueError):
                    run_native("omp", runtime, snapshot, (), "review", instruction)


if __name__ == "__main__":
    unittest.main()
