import json
from pathlib import Path

from dotunnel.files import WorkspaceFiles


_MAX_RESPONSE_BYTES = 512 * 1024
_GENERIC_ERROR = "Candidate file operation failed"


class CandidateFileTools:
    """Expose bounded read and hash-guarded replace tools for candidate files."""

    def __init__(
        self,
        snapshot: Path,
        files: tuple[str, ...],
        editable: tuple[str, ...],
        mode: str,
    ):
        if mode not in ("review", "edit"):
            raise ValueError("Invalid candidate file mode")
        if not isinstance(files, tuple) or not isinstance(editable, tuple):
            raise ValueError("Candidate paths must be tuples")
        if any(
            type(path) is not str or not self._is_relative_path(path)
            for path in files
        ):
            raise ValueError("Invalid candidate path")
        if len(set(files)) != len(files):
            raise ValueError("Duplicate candidate path")
        if any(
            type(path) is not str or path not in files for path in editable
        ):
            raise ValueError("Invalid editable candidate path")
        if len(set(editable)) != len(editable):
            raise ValueError("Duplicate editable candidate path")

        self._files = files
        self._file_set = frozenset(files)
        self._editable = editable
        self._editable_set = frozenset(editable)
        self._mode = mode
        self._workspace = WorkspaceFiles(snapshot)

    @staticmethod
    def _is_relative_path(path: str) -> bool:
        if not path or path.startswith("/") or "\x00" in path:
            return False
        try:
            if len(path) > 4096 or len(path.encode("utf-8", "strict")) > 4096:
                return False
        except UnicodeError:
            return False
        return all(component not in ("", ".", "..") for component in path.split("/"))

    def definitions(self) -> list[dict]:
        definitions = [
            {
                "type": "function",
                "name": "candidate_read_file",
                "description": "Read a UTF-8 file from the approved candidate workspace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "enum": list(self._files)},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            }
        ]
        if self._mode == "edit":
            definitions.append(
                {
                    "type": "function",
                    "name": "candidate_write_file",
                    "description": (
                        "Replace an existing editable candidate file only when its current "
                        "SHA-256 matches expected_sha256. File creation, deletion, and permission "
                        "changes are unavailable."
                    ),
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "enum": list(self._editable)},
                            "content": {"type": "string"},
                            "expected_sha256": {
                                "type": "string",
                                "pattern": "^[0-9a-fA-F]{64}$",
                            },
                        },
                        "required": ["path", "content", "expected_sha256"],
                        "additionalProperties": False,
                    },
                }
            )
        return definitions

    @staticmethod
    def _response(success: bool, result: dict | None = None) -> dict:
        if not success:
            text = _GENERIC_ERROR
        else:
            try:
                text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
                encoded = text.encode("utf-8", "strict")
                if len(encoded) > _MAX_RESPONSE_BYTES:
                    text = _GENERIC_ERROR
                    success = False
            except (TypeError, ValueError, UnicodeError):
                text = _GENERIC_ERROR
                success = False
        return {
            "success": success,
            "contentItems": [{"type": "inputText", "text": text}],
        }

    @staticmethod
    def _valid_sha256(value: object) -> bool:
        return (
            type(value) is str
            and len(value) == 64
            and all(character in "0123456789abcdefABCDEF" for character in value)
        )

    def call(self, tool: str, arguments: object) -> dict:
        if self._workspace is None:
            return self._response(False)
        if tool == "candidate_read_file":
            keys = {"path"}
        elif tool == "candidate_write_file" and self._mode == "edit":
            keys = {"path", "content", "expected_sha256"}
        else:
            return self._response(False)

        if type(arguments) is not dict or set(arguments) != keys:
            return self._response(False)
        path = arguments.get("path")
        if type(path) is not str:
            return self._response(False)

        if tool == "candidate_read_file":
            if path not in self._file_set:
                return self._response(False)
            try:
                return self._response(True, self._workspace.read_file(path))
            except Exception:
                return self._response(False)

        if path not in self._editable_set:
            return self._response(False)
        content = arguments.get("content")
        expected_sha256 = arguments.get("expected_sha256")
        if type(content) is not str or not self._valid_sha256(expected_sha256):
            return self._response(False)
        try:
            return self._response(
                True,
                self._workspace.write_file(
                    path, content, expected_sha256=expected_sha256
                ),
            )
        except Exception:
            return self._response(False)

    def close(self) -> None:
        workspace = self._workspace
        self._workspace = None
        if workspace is not None:
            workspace.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
