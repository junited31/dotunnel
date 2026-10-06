"""`dotunnel serve`: foreground stdio MCP server for one trusted configuration."""

import argparse
import json
import os
import sys
from pathlib import Path

from .config import load_config


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="dotunnel serve", description="Scoped stdio MCP for local workspace files and fixed tasks")
    parser.add_argument("--config", type=Path, required=True, help="Trusted local JSON outside writable workspace")
    parser.add_argument("--check-config", action="store_true", help="Validate only; do not open MCP or execute tasks")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.getuid() == 0:
        print("Run on Linux as a non-root user", file=sys.stderr)
        return 2
    # Delete inherited credentials without inspecting or logging their values.
    keep = {"HOME", "PATH", "LANG", "LC_ALL", "USER", "LOGNAME", "SHELL", "TERM"}
    for key in tuple(os.environ):
        if key not in keep:
            del os.environ[key]
    try:
        config = load_config(args.config)
    except (ValueError, OSError):
        print("Invalid or unsafe configuration; see README configuration requirements", file=sys.stderr)
        return 2
    if args.check_config:
        print(json.dumps({"valid": True, "tasks": [task.name for task in config.tasks]}))
        return 0
    from .server import build_server
    try:
        server, files = build_server(config)
        try:
            server.run(transport="stdio")
        finally:
            files.close()
    except (ValueError, OSError):
        print("Local MCP startup or operation failed", file=sys.stderr)
        return 2
    return 0
