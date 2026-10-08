import hashlib
import os
import stat
import threading
from pathlib import Path

from .file_access import FileAccess


_FILE_LIMIT = 64 * 1024
_PATH_LIMIT = 4096
_LIST_LIMIT = 200
_LIST_VISIT_LIMIT = 1000
_SEARCH_MATCH_LIMIT = 100
_SEARCH_VISIT_LIMIT = 1000
_SEARCH_BYTE_LIMIT = 4 * 1024 * 1024
_SEARCH_LINE_LIMIT = 4096
_QUERY_LIMIT = 64 * 1024

_PATH_ERROR = "Invalid or inaccessible workspace path"
_ROOT_ERROR = "Invalid workspace root"
_FILE_ERROR = "File is not an accessible regular UTF-8 file"
_SIZE_ERROR = "File exceeds the 64 KiB limit"
_CONFLICT_ERROR = "File content does not match the expected SHA-256"
_IO_ERROR = "Filesystem operation failed"

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
_FILE_WRITE_FLAGS = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
_FILE_CREATE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | os.O_CLOEXEC
    | os.O_NOCTTY
)

_KEY_EXTENSIONS = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".p8",
    ".ppk",
    ".der",
    ".jks",
    ".keystore",
    ".gpg",
    ".pgp",
    ".asc",
)
_PROTECTED_NAMES = {
    "credential",
    "credentials",
    "secret",
    "secrets",
    "token",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_xmss",
    "identity",
    "private",
    "private_key",
    "private-key",
    "privatekey",
    "privkey",
    "authorized_keys",
    "known_hosts",
}


def _is_protected_component(component):
    if component.startswith("."):
        return True
    lowered = component.casefold()
    if lowered.split(".", 1)[0] in _PROTECTED_NAMES:
        return True
    return lowered.endswith(_KEY_EXTENSIONS)


def _validate_components(path, allow_root):
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        raise ValueError(_PATH_ERROR)
    if len(path) > _PATH_LIMIT:
        raise ValueError(_PATH_ERROR)
    try:
        if len(path.encode("utf-8", "strict")) > _PATH_LIMIT:
            raise ValueError(_PATH_ERROR)
    except UnicodeError:
        raise ValueError(_PATH_ERROR) from None
    if path == "." and allow_root:
        return ()
    components = tuple(path.split("/"))
    if any(component in ("", ".", "..") for component in components):
        raise ValueError(_PATH_ERROR)
    if any(_is_protected_component(component) for component in components):
        raise ValueError(_PATH_ERROR)
    return components


def _safe_entry_name(name):
    if not isinstance(name, str) or name in ("", ".", ".."):
        return False
    try:
        name.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return not _is_protected_component(name)


def _relative_path(components):
    path = "/".join(components)
    if len(path.encode("utf-8", "strict")) > _PATH_LIMIT:
        return None
    return path


def _read_up_to(fd, limit):
    chunks = []
    size = 0
    while size <= limit:
        chunk = os.read(fd, min(8192, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise ValueError(_SIZE_ERROR)
    return b"".join(chunks)


def _read_exactly_up_to(fd, amount):
    chunks = []
    remaining = amount
    while remaining:
        chunk = os.read(fd, min(8192, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(fd, content):
    view = memoryview(content)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


class WorkspaceFiles:
    """Bounded file operations rooted at a non-symlink directory.

    Writes are serialized per instance; external writers are not coordinated,
    and no cross-process atomicity is provided.
    """

    def __init__(self, root: Path, access):
        if not isinstance(access, FileAccess):
            raise ValueError("Invalid file access policy")
        self._access = access
        self._root_fd = -1
        self._write_lock = threading.Lock()
        self._closed = True
        try:
            raw_root = os.fspath(root)
            if not isinstance(raw_root, str) or not raw_root or "\x00" in raw_root:
                raise ValueError(_ROOT_ERROR)
            requested = Path(raw_root)
            if ".." in requested.parts:
                raise ValueError(_ROOT_ERROR)
            if not requested.is_absolute():
                requested = Path(os.getcwd()) / requested
            absolute = Path(os.path.normpath(os.fspath(requested)))
            home = Path(os.path.normpath(os.fspath(Path.home())))
            if absolute == Path("/") or absolute == home:
                raise ValueError(_ROOT_ERROR)

            current_fd = os.open("/", _DIRECTORY_FLAGS)
            try:
                for component in absolute.parts[1:]:
                    next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
                    os.close(current_fd)
                    current_fd = next_fd
                if not stat.S_ISDIR(os.fstat(current_fd).st_mode):
                    raise ValueError(_ROOT_ERROR)
                self._root_fd = current_fd
                self._closed = False
                current_fd = -1
            finally:
                if current_fd >= 0:
                    os.close(current_fd)
        except (OSError, TypeError, ValueError, UnicodeError):
            raise ValueError(_ROOT_ERROR) from None

    def close(self):
        if not self._closed:
            fd = self._root_fd
            self._root_fd = -1
            self._closed = True
            try:
                os.close(fd)
            except OSError:
                raise ValueError(_IO_ERROR) from None

    def _ensure_open(self):
        if self._closed:
            raise ValueError(_IO_ERROR)

    def _open_directory(self, components):
        self._ensure_open()
        current_fd = os.dup(self._root_fd)
        try:
            for component in components:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def _open_parent(self, components):
        if not components:
            raise ValueError(_PATH_ERROR)
        return self._open_directory(components[:-1]), components[-1]

    @staticmethod
    def _open_regular_at(parent_fd, name, flags):
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(_FILE_ERROR)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            after = os.fstat(fd)
            if not stat.S_ISREG(after.st_mode) or after.st_nlink != 1:
                raise ValueError(_FILE_ERROR)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @classmethod
    def _entry_kind(cls, parent_fd, name):
        if not _safe_entry_name(name):
            return None
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
                try:
                    return "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else None
                finally:
                    os.close(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                return None
            fd = cls._open_regular_at(parent_fd, name, _FILE_READ_FLAGS)
            os.close(fd)
            return "file"
        except (OSError, ValueError):
            return None

    def list_files(self, path="."):
        components = _validate_components(path, allow_root=True)
        self._access.require("browse", components)
        try:
            directory_fd = self._open_directory(components)
            try:
                entries = []
                visited = 0
                truncated = False
                with os.scandir(directory_fd) as iterator:
                    for item in iterator:
                        if visited >= _LIST_VISIT_LIMIT:
                            truncated = True
                            break
                        visited += 1
                        name = item.name
                        if not _safe_entry_name(name):
                            continue
                        entry_type = self._entry_kind(directory_fd, name)
                        if entry_type is None:
                            continue
                        child_components = (*components, name)
                        if entry_type == "directory":
                            if not self._access.browsable(child_components):
                                continue
                        elif not self._access.allows("read", child_components):
                            continue
                        entry_path = _relative_path(child_components)
                        if entry_path is None:
                            truncated = True
                            continue
                        candidate = {"path": entry_path, "type": entry_type}
                        if len(entries) < _LIST_LIMIT:
                            entries.append(candidate)
                        else:
                            truncated = True
                            largest_index = max(
                                range(len(entries)), key=lambda index: entries[index]["path"]
                            )
                            if entry_path < entries[largest_index]["path"]:
                                entries[largest_index] = candidate
                entries.sort(key=lambda entry: entry["path"])
                return {"entries": entries, "truncated": truncated}
            finally:
                os.close(directory_fd)
        except UnicodeError:
            raise ValueError(_PATH_ERROR) from None
        except ValueError:
            raise
        except OSError:
            raise ValueError(_IO_ERROR) from None

    def read_file(self, path):
        components = _validate_components(path, allow_root=False)
        self._access.require("read", components)
        try:
            parent_fd, name = self._open_parent(components)
            try:
                fd = self._open_regular_at(parent_fd, name, _FILE_READ_FLAGS)
                try:
                    if os.fstat(fd).st_size > _FILE_LIMIT:
                        raise ValueError(_SIZE_ERROR)
                    content_bytes = _read_up_to(fd, _FILE_LIMIT)
                    final_info = os.fstat(fd)
                    if not stat.S_ISREG(final_info.st_mode) or final_info.st_nlink != 1:
                        raise ValueError(_FILE_ERROR)
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)
            content = content_bytes.decode("utf-8", "strict")
            digest = hashlib.sha256(content_bytes).hexdigest()
            return {"path": "/".join(components), "content": content, "sha256": digest}
        except UnicodeError:
            raise ValueError(_FILE_ERROR) from None
        except ValueError:
            raise
        except OSError:
            raise ValueError(_IO_ERROR) from None

    def search_files(self, query, path="."):
        components = _validate_components(path, allow_root=True)
        self._access.require("browse", components)
        if not isinstance(query, str) or not query:
            raise ValueError("Search query must be non-empty text")
        if len(query) > _QUERY_LIMIT:
            raise ValueError("Search query exceeds the size limit")
        try:
            query_bytes = query.encode("utf-8", "strict")
        except UnicodeError:
            raise ValueError("Search query must be valid UTF-8 text") from None
        if len(query_bytes) > _QUERY_LIMIT:
            raise ValueError("Search query exceeds the size limit")

        try:
            start_fd = self._open_directory(components)
            os.close(start_fd)
            pending = [components]
            visited = 0
            scanned = 0
            matches = []
            truncated = False
            stop = False

            while pending and not stop:
                directory_components = pending.pop()
                try:
                    directory_fd = self._open_directory(directory_components)
                except OSError:
                    truncated = True
                    continue
                try:
                    names = []
                    with os.scandir(directory_fd) as iterator:
                        for item in iterator:
                            if visited >= _SEARCH_VISIT_LIMIT:
                                truncated = True
                                break
                            visited += 1
                            names.append(item.name)

                    child_directories = []
                    for name in sorted(names):
                        if not _safe_entry_name(name):
                            continue
                        entry_type = self._entry_kind(directory_fd, name)
                        if entry_type is None:
                            continue
                        relative_components = (*directory_components, name)
                        if entry_type == "directory":
                            if self._access.browsable(relative_components):
                                child_directories.append(relative_components)
                            continue
                        if entry_type != "file" or not self._access.allows("read", relative_components):
                            continue
                        entry_path = _relative_path(relative_components)
                        if entry_path is None:
                            truncated = True
                            continue

                        try:
                            fd = self._open_regular_at(directory_fd, name, _FILE_READ_FLAGS)
                        except (OSError, ValueError):
                            truncated = True
                            continue
                        try:
                            before = os.fstat(fd)
                            file_size = before.st_size
                            if file_size > _FILE_LIMIT:
                                truncated = True
                                continue
                            remaining = _SEARCH_BYTE_LIMIT - scanned
                            allowed = min(file_size, remaining)
                            data = _read_exactly_up_to(fd, allowed)
                            scanned += len(data)
                            after = os.fstat(fd)
                            partial = file_size > allowed or after.st_size > len(data)
                            if partial:
                                truncated = True
                            if not stat.S_ISREG(after.st_mode) or after.st_nlink != 1:
                                truncated = True
                                continue
                        finally:
                            os.close(fd)

                        try:
                            text = data.decode("utf-8", "strict")
                        except UnicodeDecodeError as error:
                            if partial and error.reason == "unexpected end of data" and error.end == len(data):
                                text = data[: error.start].decode("utf-8", "strict")
                            else:
                                continue

                        for line_number, line in enumerate(text.splitlines(), start=1):
                            if query not in line:
                                continue
                            if len(matches) >= _SEARCH_MATCH_LIMIT:
                                truncated = True
                                stop = True
                                break
                            if len(line) > _SEARCH_LINE_LIMIT:
                                position = line.find(query)
                                start = max(0, min(position, len(line) - _SEARCH_LINE_LIMIT))
                                line_text = line[start : start + _SEARCH_LINE_LIMIT]
                                truncated = True
                            else:
                                line_text = line
                            matches.append(
                                {
                                    "path": entry_path,
                                    "line": line_number,
                                    "text": line_text,
                                }
                            )
                        if stop or (partial and scanned >= _SEARCH_BYTE_LIMIT):
                            stop = True
                            break
                    pending.extend(reversed(child_directories))
                finally:
                    os.close(directory_fd)

            matches.sort(key=lambda match: (match["path"], match["line"]))
            return {"matches": matches, "truncated": truncated}
        except UnicodeError:
            raise ValueError(_FILE_ERROR) from None
        except ValueError:
            raise
        except OSError:
            raise ValueError(_IO_ERROR) from None

    def write_file(self, path, content, expected_sha256=None):
        with self._write_lock:
            return self._write_file_locked(path, content, expected_sha256)

    def _write_file_locked(self, path, content, expected_sha256):
        if not isinstance(content, str):
            raise ValueError("File content must be UTF-8 text")
        if len(content) > _FILE_LIMIT:
            raise ValueError(_SIZE_ERROR)
        try:
            content_bytes = content.encode("utf-8", "strict")
        except UnicodeError:
            raise ValueError("File content must be valid UTF-8 text") from None
        if len(content_bytes) > _FILE_LIMIT:
            raise ValueError(_SIZE_ERROR)

        if expected_sha256 is not None:
            if (
                not isinstance(expected_sha256, str)
                or len(expected_sha256) != 64
                or any(character not in "0123456789abcdefABCDEF" for character in expected_sha256)
            ):
                raise ValueError("Expected SHA-256 must be 64 hexadecimal characters")
            expected_sha256 = expected_sha256.lower()

        components = _validate_components(path, allow_root=False)
        self._access.require("write", components)
        digest = hashlib.sha256(content_bytes).hexdigest()
        try:
            parent_fd, name = self._open_parent(components)
            try:
                if expected_sha256 is None:
                    fd = os.open(name, _FILE_CREATE_FLAGS, 0o600, dir_fd=parent_fd)
                    try:
                        info = os.fstat(fd)
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise ValueError(_FILE_ERROR)
                        os.fchmod(fd, 0o600)
                        _write_all(fd, content_bytes)
                    finally:
                        os.close(fd)
                    return {"path": "/".join(components), "sha256": digest, "created": True}

                fd = self._open_regular_at(parent_fd, name, _FILE_WRITE_FLAGS)
                try:
                    if os.fstat(fd).st_size > _FILE_LIMIT:
                        raise ValueError(_SIZE_ERROR)
                    existing_bytes = _read_up_to(fd, _FILE_LIMIT)
                    existing_info = os.fstat(fd)
                    if not stat.S_ISREG(existing_info.st_mode) or existing_info.st_nlink != 1:
                        raise ValueError(_FILE_ERROR)
                    existing_digest = hashlib.sha256(existing_bytes).hexdigest()
                    if existing_digest != expected_sha256:
                        raise ValueError(_CONFLICT_ERROR)
                    if existing_bytes != content_bytes:
                        os.ftruncate(fd, 0)
                        os.lseek(fd, 0, os.SEEK_SET)
                        _write_all(fd, content_bytes)
                finally:
                    os.close(fd)
                return {"path": "/".join(components), "sha256": digest, "created": False}
            finally:
                os.close(parent_fd)
        except UnicodeError:
            raise ValueError(_FILE_ERROR) from None
        except ValueError:
            raise
        except OSError:
            raise ValueError(_IO_ERROR) from None
