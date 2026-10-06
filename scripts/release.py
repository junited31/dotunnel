#!/usr/bin/env python3
"""Prepare and verify immutable dotunnel release assets."""

from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import zipfile
from typing import TypedDict

PUBLIC_REPOSITORY = 'junited31/dotunnel'
CI_WORKFLOW_PATH = '.github/workflows/ci.yml'
# Stable Actions workflow ID from the public repository's workflow-runs API.
CI_WORKFLOW_ID = 376166735
MAX_WHEEL_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_TEMPLATE_BYTES = 1024 * 1024
MAX_CI_RESPONSE_BYTES = 8 * 1024 * 1024
VERSION_RE = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')
SHA_RE = re.compile(r'[0-9a-f]{40}\Z')


class ReleaseError(Exception):
    """An invalid release input or failed verification."""


class ReleaseAsset(TypedDict):
    name: str
    size: int
    sha256: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def canonical_version(value: str) -> str:
    require(bool(VERSION_RE.fullmatch(value)), 'version must be canonical MAJOR.MINOR.PATCH without a v prefix or prerelease')
    return value


def canonical_sha(value: str, label: str = 'source SHA') -> str:
    require(bool(SHA_RE.fullmatch(value)), f'{label} must be exactly 40 lowercase hexadecimal characters')
    return value


def _read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as error:
        raise ReleaseError(f'{label} is unavailable or is a symlink: {path}') from error
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), f'{label} must be a regular file: {path}')
        require(info.st_size <= limit, f'{label} exceeds the {limit}-byte limit')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, f'{label} exceeds the {limit}-byte limit')
        require(len(data) == info.st_size, f'{label} changed while it was being read')
        return data
    finally:
        os.close(fd)


def _parse_wheel_metadata(wheel_data: bytes, version: str) -> None:
    expected_dist_info = f'dotunnel-{version}.dist-info'
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_data)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), 'wheel contains duplicate ZIP paths')
            metadata_entries = [
                entry for entry in entries
                if re.fullmatch(r'[^/]+\.dist-info/METADATA', entry.filename)
            ]
            wheel_entries = [
                entry for entry in entries
                if re.fullmatch(r'[^/]+\.dist-info/WHEEL', entry.filename)
            ]
            require(
                len(metadata_entries) == 1
                and metadata_entries[0].filename == f'{expected_dist_info}/METADATA',
                'wheel must contain exactly one authoritative dist-info/METADATA',
            )
            require(
                len(wheel_entries) == 1
                and wheel_entries[0].filename == f'{expected_dist_info}/WHEEL',
                'wheel must contain exactly one authoritative dist-info/WHEEL',
            )
            metadata_info, wheel_info = metadata_entries[0], wheel_entries[0]
            require(
                metadata_info.file_size <= MAX_METADATA_BYTES and wheel_info.file_size <= MAX_METADATA_BYTES,
                f'wheel metadata exceeds the {MAX_METADATA_BYTES}-byte limit',
            )
            require(
                metadata_info.file_size + wheel_info.file_size <= MAX_METADATA_BYTES,
                f'combined wheel metadata exceeds the {MAX_METADATA_BYTES}-byte limit',
            )
            metadata_data = archive.read(metadata_info)
            wheel_data = archive.read(wheel_info)
    except ReleaseError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, ValueError) as error:
        raise ReleaseError(f'wheel is not a readable valid ZIP archive: {error}') from error

    try:
        metadata = BytesParser(policy=policy.default).parsebytes(metadata_data)
        wheel = BytesParser(policy=policy.default).parsebytes(wheel_data)
    except (ValueError, UnicodeError) as error:
        raise ReleaseError(f'wheel metadata is malformed: {error}') from error
    require(not metadata.defects, 'wheel METADATA contains malformed headers')
    require(not wheel.defects, 'wheel WHEEL contains malformed headers')
    names = metadata.get_all('Name', [])
    versions = metadata.get_all('Version', [])
    require(len(names) == 1 and names[0] == 'dotunnel', 'wheel METADATA must contain exactly one Name: dotunnel')
    require(len(versions) == 1 and versions[0] == version, 'wheel METADATA must contain exactly one matching Version')
    wheel_versions = wheel.get_all('Wheel-Version', [])
    purelib = wheel.get_all('Root-Is-Purelib', [])
    tags = wheel.get_all('Tag', [])
    require(wheel_versions == ['1.0'], 'wheel WHEEL must contain exactly one Wheel-Version: 1.0')
    require(purelib == ['true'], 'wheel WHEEL must contain exactly one Root-Is-Purelib: true')
    require(tags == ['py3-none-any'], 'wheel WHEEL must contain exactly one Tag: py3-none-any')


def _replace_assignment(text: str, name: str, value: str) -> str:
    lines = text.splitlines(keepends=True)
    indexes = [index for index, line in enumerate(lines) if line.rstrip('\r\n').startswith(f'{name}=')]
    require(len(indexes) == 1, f'installer template must define exactly one {name} assignment')
    index = indexes[0]
    line = lines[index]
    ending = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
    lines[index] = f'{name}={value}{ending}'
    return ''.join(lines)


def _render_installer(template_path: Path, version: str, wheel_sha256: str, wheel_bytes: int) -> bytes:
    template_data = _read_regular_file(template_path, MAX_TEMPLATE_BYTES, 'installer template')
    try:
        text = template_data.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ReleaseError('installer template must be UTF-8 text') from error
    wheel_url = (
        f'https://github.com/{PUBLIC_REPOSITORY}/releases/download/v{version}/'
        f'dotunnel-{version}-py3-none-any.whl'
    )
    for name, value in (
        ('WHEEL_VERSION', f"'{version}'"),
        ('WHEEL_URL', f"'{wheel_url}'"),
        ('WHEEL_SHA256', f"'{wheel_sha256}'"),
        ('WHEEL_BYTES', str(wheel_bytes)),
    ):
        text = _replace_assignment(text, name, value)
    return text.encode('utf-8')


def _describe_asset(path: Path, name: str) -> ReleaseAsset:
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(chunk)
            digest.update(chunk)
    return {'name': name, 'size': size, 'sha256': digest.hexdigest()}


def prepare_release(version: str, source_sha: str, wheel_path: Path,
                    installer_path: Path, output_path: Path) -> None:
    version = canonical_version(version)
    source_sha = canonical_sha(source_sha)
    expected_wheel_name = f'dotunnel-{version}-py3-none-any.whl'
    require(wheel_path.name == expected_wheel_name, f'wheel filename must be exactly {expected_wheel_name}')
    wheel_data = _read_regular_file(wheel_path, MAX_WHEEL_BYTES, 'wheel')
    require(bool(wheel_data), 'wheel must not be empty')
    _parse_wheel_metadata(wheel_data, version)

    installer = _render_installer(installer_path, version, hashlib.sha256(wheel_data).hexdigest(), len(wheel_data))
    require(not output_path.exists() and not output_path.is_symlink(), f'output path already exists: {output_path}')
    try:
        output_path.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ReleaseError(f'output path already exists: {output_path}') from error
    try:
        copied_wheel = output_path / expected_wheel_name
        rendered_installer = output_path / 'install.sh'
        with copied_wheel.open('xb') as stream:
            stream.write(wheel_data)
        os.chmod(copied_wheel, 0o644)
        with rendered_installer.open('xb') as stream:
            stream.write(installer)
        os.chmod(rendered_installer, 0o755)

        assets = [
            _describe_asset(copied_wheel, expected_wheel_name),
            _describe_asset(rendered_installer, 'install.sh'),
        ]
        checksums = ''.join(f"{asset['sha256']}  {asset['name']}\n" for asset in sorted(assets, key=lambda item: item['name']))
        with (output_path / 'SHA256SUMS').open('x', encoding='ascii', newline='\n') as stream:
            stream.write(checksums)
        manifest = {'version': version, 'source_sha': source_sha, 'assets': assets}
        with (output_path / 'release-manifest.json').open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(manifest, stream, ensure_ascii=True, indent=2, sort_keys=True)
            stream.write('\n')
    except BaseException:
        shutil.rmtree(output_path, ignore_errors=True)
        raise


def _git(cwd: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ['git', *args], cwd=cwd, check=False, capture_output=True, text=True,
        )
    except OSError as error:
        raise ReleaseError(f'git is unavailable while validating source: {error}') from error
    if result.returncode:
        detail = result.stderr.strip() or 'git command failed'
        raise ReleaseError(detail)
    return result.stdout.strip()


def _validate_main_ref(main_ref: str) -> None:
    require(main_ref in ('refs/heads/main', 'refs/remotes/origin/main'), 'main ref must be the protected main branch')


def _validate_ci_run(path: Path, source_sha: str) -> None:
    try:
        raw = _read_regular_file(path, MAX_CI_RESPONSE_BYTES, 'CI workflow-runs response')
        document = json.loads(raw)
    except (ReleaseError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ReleaseError(f'CI workflow-runs response is invalid: {error}') from error
    require(isinstance(document, dict), 'CI workflow-runs response must be a JSON object')
    runs = document.get('workflow_runs')
    require(isinstance(runs, list), 'CI workflow-runs response is missing workflow_runs')
    for run in runs:
        if not isinstance(run, dict):
            continue
        repository = run.get('repository')
        head_repository = run.get('head_repository')
        if (
            run.get('workflow_id') == CI_WORKFLOW_ID
            and run.get('path') == CI_WORKFLOW_PATH
            and run.get('event') == 'push'
            and run.get('status') == 'completed'
            and run.get('conclusion') == 'success'
            and run.get('head_branch') == 'main'
            and run.get('head_sha') == source_sha
            and isinstance(repository, dict)
            and repository.get('full_name') == PUBLIC_REPOSITORY
            and isinstance(head_repository, dict)
            and head_repository.get('full_name') == PUBLIC_REPOSITORY
        ):
            return
    raise ReleaseError(
        f'no successful completed push-to-main run of {CI_WORKFLOW_PATH} for {source_sha}'
    )


def validate_source(repository: str, event_name: str, ref: str, source_sha: str,
                    package_version: str, main_ref: str, dry_run: str,
                    ci_runs_path: Path, cwd: Path) -> str:
    require(repository == PUBLIC_REPOSITORY, f'release automation is restricted to {PUBLIC_REPOSITORY}')
    source_sha = canonical_sha(source_sha)
    package_version = canonical_version(package_version)
    _validate_main_ref(main_ref)
    checked_out_sha = _git(cwd, 'rev-parse', '--verify', 'HEAD^{commit}')
    require(checked_out_sha == source_sha, 'source SHA does not match the checked-out commit')
    main_sha = _git(cwd, 'rev-parse', '--verify', f'{main_ref}^{{commit}}')

    if event_name == 'workflow_dispatch':
        require(ref == 'refs/heads/main', 'manual dry-run is allowed only from refs/heads/main')
        require(dry_run == 'true', 'manual dispatch requires dry_run=true')
        require(source_sha == main_sha, 'manual dry-run source must be the exact current main SHA')
        version = package_version
    elif event_name == 'push':
        match = re.fullmatch(r'refs/tags/(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))', ref)
        if match is None:
            raise ReleaseError('push release ref must be a canonical stable vMAJOR.MINOR.PATCH tag')
        version = canonical_version(match.group(1)[1:])
        require(version == package_version, 'release tag version does not match package version')
        tagged_sha = _git(cwd, 'rev-parse', '--verify', f'{ref}^{{commit}}')
        require(tagged_sha == source_sha, 'release tag does not resolve to the checked-out source SHA')
        ancestor = subprocess.run(
            ['git', 'merge-base', '--is-ancestor', source_sha, main_ref],
            cwd=cwd, check=False, capture_output=True, text=True,
        )
        if ancestor.returncode == 1:
            raise ReleaseError('release source is not on protected main history')
        if ancestor.returncode != 0:
            raise ReleaseError(ancestor.stderr.strip() or 'unable to verify source ancestry on main')
    else:
        raise ReleaseError('only canonical tag pushes and manual dry-runs are supported')

    _validate_ci_run(ci_runs_path, source_sha)
    return version


def _prepare_command(args: argparse.Namespace) -> None:
    prepare_release(
        args.version, args.source_sha, args.wheel, args.installer, args.output,
    )
    print(f'Prepared v{args.version} from {args.source_sha} in {args.output}')


def _validate_source_command(args: argparse.Namespace) -> None:
    version = validate_source(
        args.repository, args.event_name, args.ref, args.source_sha,
        args.package_version, args.main_ref, args.dry_run,
        args.ci_runs, Path.cwd(),
    )
    print(f'Source gate passed for v{version} at {args.source_sha}')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='release.py')
    commands = parser.add_subparsers(dest='command', required=True)

    prepare = commands.add_parser('prepare', help='validate a wheel and prepare immutable release assets')
    prepare.add_argument('--version', required=True)
    prepare.add_argument('--source-sha', required=True)
    prepare.add_argument('--wheel', type=Path, required=True)
    prepare.add_argument('--installer', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    prepare.set_defaults(handler=_prepare_command)

    gate = commands.add_parser('validate-source', help='enforce public release source and CI policy')
    gate.add_argument('--repository', required=True)
    gate.add_argument('--event-name', required=True)
    gate.add_argument('--ref', required=True)
    gate.add_argument('--source-sha', required=True)
    gate.add_argument('--package-version', required=True)
    gate.add_argument('--main-ref', required=True)
    gate.add_argument('--dry-run', default='')
    gate.add_argument('--ci-runs', type=Path, required=True)
    gate.set_defaults(handler=_validate_source_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except ReleaseError as error:
        parser.error(str(error))
    except OSError as error:
        parser.error(f'file operation failed: {error}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
