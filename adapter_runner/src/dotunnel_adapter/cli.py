"""Operator consent commands and the one fixed-task execution entry."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from types import FrameType
from typing import Any, NoReturn

from .configuration import RunnerConfig, load_config, profile_fingerprint, registry_profile
from .filesystem import Workspace
from .protocol import RunnerError, decode_json, fingerprint, validate_request
from .runner import MUTATIONS, _policy, capabilities, check_registration, inspect_target, run
from .state import Store


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.exit(2, 'dotunnel-adapter-runner: invalid_request\n')


def _interrupt(signum: int, frame: FrameType | None) -> NoReturn:
    raise RunnerError('outcome_unknown')


def _load_pending(config: RunnerConfig, *, allow_unapproved: bool = False) -> tuple[dict[str, Any], str]:
    workspace = Workspace(config.workspace)
    try:
        raw, digest = workspace.read_request(config.request)
        request = validate_request(decode_json(raw), allow_unapproved=allow_unapproved)
        return request, digest
    finally:
        workspace.close()


def _approve(config: RunnerConfig, ttl_seconds: int) -> dict[str, Any]:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RunnerError('approval_required')
    if not 1 <= ttl_seconds <= 3600:
        raise RunnerError('invalid_request')
    store = Store(config.state_dir)
    try:
        request, digest = _load_pending(config, allow_unapproved=True)
        check_registration(request, config, store.owner)
        if request['action'] not in MUTATIONS:
            raise RunnerError('unsupported')
        _policy(request, config)
        deadline = time.monotonic() + config.backend['timeout_seconds']
        declaration = capabilities(config, request, deadline)
        if not declaration['operations'][request['action']]:
            raise RunnerError('unsupported')
        inspect_target(config, request, declaration, deadline, store)
        profile = profile_fingerprint(config)
        display = {
            'request': {key: value for key, value in request.items() if key != 'authorization'},
            'registry_profile': registry_profile(config), 'profile_fingerprint': profile,
        }
        print(json.dumps(display, ensure_ascii=True, indent=2))
        print('Authorize this exact operation once? [y/N] ', end='', flush=True)
        answer = sys.stdin.readline(16)
        if answer.strip().casefold() not in ('y', 'yes'):
            raise RunnerError('approval_required')
        fresh = load_config(config.config_path)
        if fresh != config:
            raise RunnerError('stale_target')
        _policy(request, fresh)
        current, current_digest = _load_pending(config, allow_unapproved=True)
        if current_digest != digest or current != request:
            raise RunnerError('request_conflict')
        # Consent references are not bearer tokens; state binds the exact payload.
        grant = store.issue_grant(
            request, time.time() + ttl_seconds, profile_fingerprint=profile,
        )
        return {'request_id': request['request_id'], 'grant_id': grant,
                'action': request['action'], 'fingerprint': request['operation']['fingerprint'],
                'profile_fingerprint': profile}
    finally:
        store.close()


def _fingerprint(config: RunnerConfig) -> dict[str, Any]:
    workspace = Workspace(config.workspace)
    try:
        raw, _ = workspace.read_request(config.request)
        request = decode_json(raw)
        if request.get('action') not in MUTATIONS or not isinstance(request.get('operation'), dict):
            raise RunnerError('invalid_request')
        computed = fingerprint(request)
        request['operation']['fingerprint'] = computed
        request = validate_request(request, allow_unapproved=True)
        return {'request_id': request['request_id'], 'fingerprint': computed}
    finally:
        workspace.close()


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog='dotunnel-adapter-runner', description='Explicit optional fixed JSON-stdio adapter runner.')
    commands = parser.add_subparsers(dest='command', required=True, parser_class=_Parser)
    for name in ('initialize', 'fingerprint', 'approve', 'revoke', 'run'):
        command = commands.add_parser(name)
        command.add_argument('--config', required=True)
        if name == 'approve':
            command.add_argument('--ttl-seconds', type=int, default=300)
        if name == 'revoke':
            command.add_argument('--grant-id', required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    previous = {}
    try:
        if sys.platform != 'linux' or os.getuid() == 0:
            raise RunnerError('invalid_config')
        config = load_config(args.config)
        if args.command == 'initialize':
            result = {'owner': Store.initialize(config.state_dir)}
        elif args.command == 'fingerprint':
            result = _fingerprint(config)
        elif args.command == 'approve':
            result = _approve(config, args.ttl_seconds)
        elif args.command == 'revoke':
            store = Store(config.state_dir)
            try:
                result = {'grant_id': args.grant_id, 'revoked': store.revoke_grant(args.grant_id)}
            finally:
                store.close()
        else:
            for signum in (signal.SIGTERM, signal.SIGHUP):
                previous[signum] = signal.signal(signum, _interrupt)
            result, status = run(config)
            print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
            return status
        print(json.dumps(result, ensure_ascii=True, separators=(',', ':')))
        return 0
    except RunnerError as error:
        print('dotunnel-adapter-runner: ' + error.code, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('dotunnel-adapter-runner: outcome_unknown', file=sys.stderr)
        return 130
    except OSError:
        print('dotunnel-adapter-runner: state_unavailable', file=sys.stderr)
        return 2
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
