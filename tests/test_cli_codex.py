import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time
import unittest

from dotunnel.cli_codex import run_codex


_PEER = textwrap.dedent(
    r'''
    import json
    import os
    import sys
    import time

    scenario = sys.argv[1]
    def send(message):
        sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    def receive():
        line = sys.stdin.readline()
        if not line:
            return None
        return json.loads(line)
    def respond(request, result):
        send({"id": request["id"], "result": result})
    def send_dynamic_item(method, call_id, tool, arguments, status, success=None):
        item = {
            "id": call_id,
            "type": "dynamicToolCall",
            "namespace": None,
            "tool": tool,
            "arguments": arguments,
            "status": status,
        }
        if success is not None:
            item["success"] = success
        send({
            "method": method,
            "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": item},
        })
    def write_all(fd, payload):
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]

    if scenario == "hang-with-descendant":
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        with open(sys.argv[2], "w", encoding="ascii") as file:
            file.write(str(child.pid))
        time.sleep(60)
        raise SystemExit
    if scenario == "flood":
        write_all(1, b"x" * (1100 * 1024))
        write_all(2, b"y" * (80 * 1024))
        raise SystemExit
    if scenario == "stderr-flood":
        write_all(2, b"y" * (80 * 1024))
        raise SystemExit
    if scenario == "oversized-frame":
        write_all(1, b"{" + b" " * (950 * 1024))
        time.sleep(60)
        raise SystemExit
    if scenario == "malformed-json":
        write_all(1, b"{not-json}\n")
        raise SystemExit
    if scenario == "invalid-utf8":
        os.write(1, b"\xff\n")
        raise SystemExit
    if scenario == "start-marker":
        with open(sys.argv[2], "w", encoding="ascii") as file:
            file.write("started")

    initialize = receive()
    assert initialize["method"] == "initialize"
    assert initialize["params"]["capabilities"]["experimentalApi"] is True
    respond(initialize, {"userAgent": "synthetic-test"})
    initialized = receive()
    assert initialized["method"] == "initialized"
    thread_request = receive()
    assert thread_request["method"] == "thread/start"
    thread_params = thread_request["params"]
    assert thread_params["ephemeral"] is True
    assert thread_params["cwd"] == "/workspace"
    assert thread_params["approvalPolicy"] == "never"
    assert thread_params["sandbox"] == "danger-full-access"
    expected_tools = {"candidate_read_file"} if scenario == "review" else {"candidate_read_file", "candidate_write_file"}
    assert {tool["name"] for tool in thread_params["dynamicTools"]} == expected_tools
    assert thread_params["config"]["web_search"] == "disabled"
    disabled_features = (
        "shell_tool", "apps", "plugins", "browser_use", "browser_use_full_cdp_access",
        "browser_use_external", "computer_use", "multi_agent", "multi_agent_v2", "view_image",
        "js_repl", "web_search_request", "web_search_cached", "standalone_web_search", "search_tool",
        "apply_patch_freeform", "request_permissions_tool", "request_rule", "hooks", "plugin_hooks",
        "remote_plugin", "codex_git_commit", "sleep_tool", "memories",
    )
    feature_names = {
        "code_mode": True,
        "code_mode_only": True,
        **{name: False for name in disabled_features},
    }
    assert thread_params["config"]["features"] == feature_names
    assert not {"model", "modelProvider", "effort"} & set(thread_params)
    if scenario == "malformed-thread-response":
        respond(thread_request, {"thread": {"id": 7}})
        raise SystemExit
    respond(thread_request, {"thread": {"id": "thr-owned", "ephemeral": True}})
    feature_request = receive()
    assert feature_request["method"] == "experimentalFeature/list"
    assert feature_request["params"]["threadId"] == "thr-owned"
    feature_names = {
        "code_mode": True,
        "code_mode_only": True,
        **{name: False for name in disabled_features},
    }
    feature_data = [{"name": name, "enabled": enabled} for name, enabled in feature_names.items()]
    if scenario == "callback":
        feature_data.extend({"name": "owned_other_feature_" + str(i), "enabled": False} for i in range(128))
    next_cursor = "more" if scenario == "feature-paginated" else None
    if scenario == "feature-missing":
        feature_data.pop()
    if scenario == "feature-enabled":
        feature_data[2]["enabled"] = True
    requested_limit = feature_request["params"]["limit"]
    if len(feature_data) > requested_limit:
        feature_data = feature_data[:requested_limit]
        next_cursor = str(requested_limit)
    respond(feature_request, {"data": feature_data, "nextCursor": next_cursor})
    if scenario in {"feature-paginated", "feature-missing", "feature-enabled"}:
        assert receive() is None, "turn started with an incompatible native feature surface"
        raise SystemExit
    turn_request = receive()
    assert turn_request["method"] == "turn/start"
    turn_params = turn_request["params"]
    assert turn_params["threadId"] == "thr-owned"
    assert len(turn_params["input"]) == 1 and turn_params["input"][0]["type"] == "text"
    assert not {"model", "modelProvider", "effort"} & set(turn_params)
    turn_response = {"id": turn_request["id"], "result": {"turn": {"id": "turn-owned", "status": "inProgress", "items": [], "error": None}}}
    if scenario != "callback":
        send(turn_response)

    if scenario in {"wrong-thread", "wrong-turn", "protected-write", "approval"}:
        params = {
            "arguments": {"path": "protected.txt", "content": "must stay protected", "expected_sha256": "0" * 64},
            "callId": "call-owned",
            "threadId": "not-owned" if scenario == "wrong-thread" else "thr-owned",
            "tool": "candidate_write_file",
            "turnId": "not-owned" if scenario == "wrong-turn" else "turn-owned",
        }
        if scenario != "approval":
            send_dynamic_item("item/started", "call-owned", "candidate_write_file", params["arguments"], "inProgress")
        request = {"method": "item/tool/call", "id": "tool-request", "params": params}
        if scenario == "approval":
            request = {"method": "item/commandExecution/requestApproval", "id": "approval-request", "params": {"threadId": "thr-owned", "turnId": "turn-owned"}}
        send(request)
        response = receive()
        if scenario == "protected-write":
            assert response["id"] == "tool-request"
            assert response["result"]["success"] is False
            send({"method": "item/completed", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": {"id": "msg", "type": "agentMessage", "text": "misleading final"}}})
            send({"method": "turn/completed", "params": {"threadId": "thr-owned", "turn": {"id": "turn-owned", "status": "completed", "error": None}}})
            raise SystemExit
        assert response is None, "foreign or approval request was answered"
        raise SystemExit

    request = {
        "method": "item/tool/call",
        "id": "tool-request",
        "params": {
            "arguments": {"path": "editable.txt", "content": "new candidate\n", "expected_sha256": sys.argv[2]},
            "callId": "call-owned",
            "threadId": "thr-owned",
            "tool": "candidate_write_file",
            "turnId": "turn-owned",
        },
    }
    if scenario in {"callback", "unexpected-function-call-output"}:
        if scenario == "callback":
            started = {
                "method": "item/started",
                "params": {
                    "threadId": "thr-owned", "turnId": "turn-owned",
                    "item": {
                        "id": "call-owned", "type": "dynamicToolCall", "namespace": None,
                        "tool": "candidate_write_file", "arguments": request["params"]["arguments"],
                        "status": "inProgress",
                    },
                },
            }
            # One pipe write makes the response/callback state transition deterministic.
            batch = "".join(json.dumps(frame) + "\n" for frame in (turn_response, started, request))
            os.write(1, batch.encode("utf-8"))
        else:
            send_dynamic_item("item/started", "call-owned", "candidate_write_file", request["params"]["arguments"], "inProgress")
            send(request)
        response = receive()
        assert response["id"] == "tool-request"
        assert response["result"]["success"] is True
        send_dynamic_item("item/completed", "call-owned", "candidate_write_file", request["params"]["arguments"], "completed", True)
    if scenario == "review":
        send_dynamic_item("item/started", "read-call", "candidate_read_file", {"path": "editable.txt"}, "inProgress")
        send({
            "method": "item/tool/call",
            "id": "read-request",
            "params": {
                "arguments": {"path": "editable.txt"},
                "callId": "read-call",
                "threadId": "thr-owned",
                "tool": "candidate_read_file",
                "turnId": "turn-owned",
            },
        })
        response = receive()
        assert response["id"] == "read-request" and response["result"]["success"] is True
        read_result = json.loads(response["result"]["contentItems"][0]["text"])
        assert read_result["content"] == "original candidate\n"
        send_dynamic_item("item/completed", "read-call", "candidate_read_file", {"path": "editable.txt"}, "completed", True)
    if scenario == "failed-turn":
        send({"method": "item/completed", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": {"id": "msg", "type": "agentMessage", "text": "partial response"}}})
        send({"method": "turn/completed", "params": {"threadId": "thr-owned", "turn": {"id": "turn-owned", "status": "failed", "error": {"message": "private native failure"}}}})
        raise SystemExit
    if scenario == "reasoning-section":
        send({"method": "item/reasoning/summaryPartAdded", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "itemId": "reasoning", "summaryIndex": 0}})
    if scenario in {"recoverable-error", "terminal-error", "foreign-error"}:
        send({"method": "error", "params": {
            "threadId": "foreign" if scenario == "foreign-error" else "thr-owned",
            "turnId": "turn-owned", "willRetry": scenario != "terminal-error",
            "error": {"message": "owned synthetic provider error"},
        }})
    send({"method": "item/completed", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": {"id": "exec-output", "type": "functionCallOutput", "name": "exec", "namespace": None, "output": "candidate tool call completed"}}})
    if scenario == "unexpected-function-call-output":
        send({"method": "item/completed", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": {"id": "shell-output", "type": "functionCallOutput", "name": "shell", "namespace": None, "output": "must reject"}}})
        raise SystemExit
    if scenario in {"missing-summary", "oversized-summary"}:
        final = "" if scenario == "missing-summary" else "é" * 1025
    elif scenario == "review":
        final = "Candidate review complete"
    else:
        final = "Candidate edited successfully"
    final_item = {"id": "msg", "type": "agentMessage", "phase": "final_answer", "text": final}
    if scenario in {"unphased-answer", "null-phase-answer", "commentary-only"}:
        send({"method": "item/completed", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": {"id": "commentary", "type": "agentMessage", "phase": "commentary", "text": "not a final answer"}}})
        if scenario == "unphased-answer":
            final_item.pop("phase")
        elif scenario == "null-phase-answer":
            final_item["phase"] = None
        else:
            final_item["phase"] = "commentary"
    send({"method": "item/completed", "params": {"threadId": "thr-owned", "turnId": "turn-owned", "item": final_item}})
    send({"method": "turn/completed", "params": {"threadId": "thr-owned", "turn": {"id": "turn-owned", "status": "completed", "error": None}}})
    if scenario == "nonzero-exit":
        raise SystemExit(7)
    if scenario == "completed-with-descendant":
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        with open(sys.argv[2], "w", encoding="ascii") as file:
            file.write(str(child.pid))
        time.sleep(60)
        raise SystemExit
    '''
)


class NativeCodexTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir(mode=0o700)
        self.editable = self.snapshot / "editable.txt"
        self.editable.write_text("original candidate\n", encoding="utf-8")
        self.protected = self.snapshot / "protected.txt"
        self.protected.write_text("protected candidate\n", encoding="utf-8")
        self.digest = hashlib.sha256(self.editable.read_bytes()).hexdigest()

    def invoke(self, scenario, *, mode="edit", deadline=5.0, extra=(), prompt="Apply the bounded candidate update."):
        command = [sys.executable, "-u", "-c", _PEER, scenario, *extra]
        return run_codex(
            command,
            {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"},
            self.snapshot,
            ("editable.txt", "protected.txt"),
            ("editable.txt",) if mode == "edit" else (),
            mode,
            prompt,
            deadline_seconds=deadline,
        )

    def test_callback_mutates_only_candidate_and_returns_own_completed_summary(self):
        result = self.invoke("callback", extra=(self.digest,))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"], "Candidate edited successfully")
        self.assertEqual(self.editable.read_text(encoding="utf-8"), "new candidate\n")
        self.assertEqual(self.protected.read_text(encoding="utf-8"), "protected candidate\n")


    def test_nonzero_process_exit_after_completed_turn_fails(self):
        result = self.invoke("nonzero-exit", extra=(self.digest,))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")

    def test_unrecognized_function_output_tool_fails_closed(self):
        result = self.invoke("unexpected-function-call-output", extra=(self.digest,))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")

    def test_review_exposes_read_only_callback_without_candidate_mutation(self):
        result = self.invoke("review", mode="review", extra=(self.digest,))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"], "Candidate review complete")
        self.assertEqual(self.editable.read_text(encoding="utf-8"), "original candidate\n")

    def test_protected_candidate_callback_is_denied_and_cannot_pass_completion(self):
        result = self.invoke("protected-write", extra=(self.digest,))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")
        self.assertEqual(self.protected.read_text(encoding="utf-8"), "protected candidate\n")

    def test_foreign_thread_or_turn_tool_requests_are_never_answered(self):
        for scenario in ("wrong-thread", "wrong-turn"):
            with self.subTest(scenario=scenario):
                result = self.invoke(scenario, extra=(self.digest,))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(self.protected.read_text(encoding="utf-8"), "protected candidate\n")

    def test_approval_requests_are_not_granted(self):
        result = self.invoke("approval", extra=(self.digest,))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")

    def test_failed_turn_cannot_pass_with_partial_agent_message(self):
        result = self.invoke("failed-turn", extra=(self.digest,))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")

    def test_owned_reasoning_metadata_does_not_discard_successful_completion(self):
        result = self.invoke("reasoning-section", extra=(self.digest,))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"], "Candidate edited successfully")

    def test_only_owned_transient_error_can_recover_to_completed_turn(self):
        result = self.invoke("recoverable-error", extra=(self.digest,))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"], "Candidate edited successfully")
        for scenario in ("terminal-error", "foreign-error"):
            with self.subTest(scenario=scenario):
                result = self.invoke(scenario, extra=(self.digest,))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["summary"], "")

    def test_completed_unphased_answer_is_eligible_but_commentary_is_not(self):
        for scenario in ("unphased-answer", "null-phase-answer"):
            with self.subTest(scenario=scenario):
                result = self.invoke(scenario, extra=(self.digest,))
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["summary"], "Candidate edited successfully")
        result = self.invoke("commentary-only", extra=(self.digest,))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")

    def test_missing_or_oversized_authoritative_summary_fails_closed(self):
        for scenario in ("missing-summary", "oversized-summary"):
            with self.subTest(scenario=scenario):
                result = self.invoke(scenario, extra=(self.digest,))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["summary"], "")

    def test_malformed_thread_response_fails_closed(self):
        result = self.invoke("malformed-thread-response", extra=(self.digest,))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["summary"], "")

    def test_turn_does_not_start_when_native_tool_features_are_missing_enabled_or_paginated(self):
        for scenario in ("feature-missing", "feature-enabled", "feature-paginated"):
            with self.subTest(scenario=scenario):
                result = self.invoke(scenario, extra=(self.digest,))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["summary"], "")

    def test_oversized_prompt_is_rejected_before_native_process_start(self):
        marker = self.root / "started.txt"
        result = self.invoke("start-marker", extra=(str(marker),), prompt="x" * (64 * 1024 + 1))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "INVALID_NATIVE_STREAM")
        self.assertFalse(marker.exists())

    def test_completed_turn_cleans_descendant_holding_stdout_without_timeout(self):
        pid_file = self.root / "escaped-pipe.pid"
        result = self.invoke("completed-with-descendant", extra=(str(pid_file),))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["summary"], "Candidate edited successfully")
        child_pid = int(pid_file.read_text(encoding="ascii"))
        end = time.monotonic() + 2
        while time.monotonic() < end:
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state in {"Z", "X"}:
                break
            time.sleep(0.02)
        else:
            self.fail("completed native turn left a descendant holding its pipes")


    def test_invalid_json_utf8_oversized_frame_and_output_flood_fail_closed(self):
        for scenario in ("malformed-json", "invalid-utf8", "oversized-frame", "stderr-flood", "flood"):
            with self.subTest(scenario=scenario):
                result = self.invoke(scenario)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["summary"], "")
                self.assertIn(result["error_code"], {"OUTPUT_LIMIT", "INVALID_NATIVE_STREAM", "NATIVE_FAILURE"})

    def test_deadline_kills_owned_group_with_descendant_holding_pipes(self):
        pid_file = self.root / "descendant.pid"
        result = self.invoke("hang-with-descendant", deadline=0.3, extra=(str(pid_file),))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "TIMEOUT")
        child_pid = int(pid_file.read_text(encoding="ascii"))
        end = time.monotonic() + 2
        while time.monotonic() < end:
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii").rsplit(") ", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state in {"Z", "X"}:
                break
            time.sleep(0.02)
        else:
            self.fail("native process descendant survived bounded timeout cleanup")


if __name__ == "__main__":
    unittest.main()
