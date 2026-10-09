from dataclasses import dataclass


_DENIED = "Workspace access denied"


@dataclass(frozen=True)
class Rule:
    parts: tuple[str, ...]
    kind: str

    def covers(self, parts):
        if self.kind == "file":
            return self.parts == parts
        return parts[: len(self.parts)] == self.parts


@dataclass(frozen=True)
class FileAccess:
    read: tuple[Rule, ...]
    write: tuple[Rule, ...]

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict) or set(value) != {"read", "write"}:
            raise ValueError("Invalid file access policy")

        def rules(items):
            if not isinstance(items, list) or len(items) > 128:
                raise ValueError("Invalid file access rules")
            result = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {"path", "kind"}:
                    raise ValueError("Invalid file access rule")
                path, kind = item["path"], item["kind"]
                if not isinstance(path, str) or kind not in ("file", "tree"):
                    raise ValueError("Invalid file access rule")
                try:
                    size = len(path.encode("utf-8", "strict"))
                except UnicodeError:
                    raise ValueError("Invalid permission path") from None
                if not 0 < size <= 4096 or "\0" in path:
                    raise ValueError("Invalid permission path")
                parts = () if path == "." and kind == "tree" else tuple(path.split("/"))
                if any(part in ("", ".", "..") for part in parts):
                    raise ValueError("Invalid permission path")
                rule = Rule(parts, kind)
                if rule in result:
                    raise ValueError("Duplicate permission rule")
                result.append(rule)
            return tuple(result)

        read, write = rules(value["read"]), rules(value["write"])
        for rule in write:
            if not any(
                read_rule.covers(rule.parts)
                and (rule.kind == "file" or read_rule.kind == "tree")
                for read_rule in read
            ):
                raise ValueError("Write permissions must be within read permissions")
        return cls(read, write)

    def allows(self, action, parts):
        if action not in ("read", "write"):
            return False
        rules = self.read if action == "read" else self.write
        return any(rule.covers(parts) for rule in rules)

    def browsable(self, parts):
        return any(
            (rule.kind == "tree" and rule.covers(parts))
            or (len(parts) < len(rule.parts) and rule.parts[: len(parts)] == parts)
            for rule in self.read
        )

    def require(self, action, parts):
        allowed = self.browsable(parts) if action == "browse" else self.allows(action, parts)
        if not allowed:
            raise ValueError(_DENIED)
