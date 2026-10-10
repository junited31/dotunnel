import ast
from pathlib import Path
import unittest


_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "verification-host-probe.yml"
_STEP = "      - name: Verify trusted source and capture read-only host evidence"
_PYTHON = "          python3 -I -S - <<'PY'"
_END = "          PY"


def _host_probe_script() -> str:
    lines = _WORKFLOW.read_text(encoding="utf-8").splitlines()
    step = lines.index(_STEP)
    start = next(index for index in range(step, len(lines)) if lines[index] == _PYTHON) + 1
    end = next(index for index in range(start, len(lines)) if lines[index] == _END)
    return "\n".join(line[10:] if line.startswith("          ") else line for line in lines[start:end])


def _identity_assignment(tree: ast.Module, field: str) -> ast.Assign:
    matches: list[ast.Assign] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "identity"
            and isinstance(target.slice, ast.Constant)
            and target.slice.value == field
            for target in node.targets
        ):
            matches.append(node)
    if not matches:
        raise AssertionError(f"workflow identity {field!r} assignment is missing")
    return min(matches, key=lambda node: node.lineno)


class HostProbeWorkflowTests(unittest.TestCase):
    def test_identity_reason_matches_prerequisite_status(self):
        tree = ast.parse(_host_probe_script(), filename=str(_WORKFLOW))
        assert isinstance(tree, ast.Module)
        helper: list[ast.stmt] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "_host_probe_identity_reason":
                helper.append(node)
        status_assignment = _identity_assignment(tree, "status")
        reason_assignment = _identity_assignment(tree, "reason")
        program = ast.Module(body=helper + [status_assignment, reason_assignment], type_ignores=[])
        compiled = compile(ast.fix_missing_locations(program), str(_WORKFLOW), "exec")

        expected = {
            "AVAILABLE": "host-prerequisites-available;kernel-pilot-remains-blocked",
            "BLOCKED": "host-prerequisites-or-start-headroom-unavailable;kernel-pilot-remains-blocked",
        }
        for status, reason in expected.items():
            with self.subTest(status=status):
                namespace = {"identity": {"status": "BLOCKED"}, "probe": {"status": status}}
                exec(compiled, namespace)
                self.assertEqual(namespace["identity"]["status"], status)
                self.assertEqual(namespace["identity"]["reason"], reason)


if __name__ == "__main__":
    _ = unittest.main()
