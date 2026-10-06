"""Interactive upgrades from one authoritative GitHub release repository."""
from __future__ import annotations

from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

REPOSITORY = 'junited31/dotunnel'
_VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)')
_MAX_WHEEL = 16 * 1024 * 1024


class UpdateError(Exception):
    """An update cannot be safely checked or installed."""


@dataclass(frozen=True)
class Release:
    version: str
    asset_id: int
    filename: str
    size: int
    sha256: str


def version_key(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or len(value) > 64 or not _VERSION.fullmatch(value):
        raise UpdateError('Only canonical MAJOR.MINOR.PATCH stable versions are supported.')
    return tuple(int(part) for part in value.split('.'))


def release_version(data: object) -> str:
    if not isinstance(data, dict) or data.get('draft') is not False or data.get('prerelease') is not False:
        raise UpdateError('GitHub did not return a stable published release.')
    tag = data.get('tag_name')
    if not isinstance(tag, str) or not tag.startswith('v'):
        raise UpdateError('The release tag must be vMAJOR.MINOR.PATCH.')
    version = tag[1:]
    _ = version_key(version)
    return version


def parse_release(data: object) -> Release:
    version = release_version(data)
    assert isinstance(data, dict)
    filename = f'dotunnel-{version}-py3-none-any.whl'
    assets = data.get('assets')
    if not isinstance(assets, list):
        raise UpdateError('Release assets are missing.')
    matches = [a for a in assets if isinstance(a, dict) and a.get('name') == filename]
    if len(matches) != 1:
        raise UpdateError('The release must contain exactly one matching universal wheel.')
    asset = matches[0]
    identity, size, digest = asset.get('id'), asset.get('size'), asset.get('digest')
    if type(identity) is not int or identity <= 0 or type(size) is not int or not 0 < size <= _MAX_WHEEL:
        raise UpdateError('The release wheel has invalid identity or size.')
    if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise UpdateError('GitHub must provide the release asset SHA-256 digest.')
    return Release(version, identity, filename, size, digest[7:])


def _github_output(gh: str, endpoint: str, target: Path, *, binary: bool = False) -> None:
    command = [gh, 'api', '--hostname', 'github.com', f'repos/{REPOSITORY}/{endpoint}']
    if binary:
        command += ['--header', 'Accept: application/octet-stream']
    else:
        command += ['--jq', '{tag_name,draft,prerelease,assets:[.assets[]|{id,name,size,digest}]}']
    limit = _MAX_WHEEL if binary else 1024 * 1024
    try:
        with target.open('xb') as output, subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ) as process:
            assert process.stdout is not None
            deadline = time.monotonic() + 60
            size = 0
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise UpdateError('GitHub release access timed out.')
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > limit:
                            raise UpdateError('GitHub response exceeds the supported size limit.')
                        output.write(chunk)
                result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except (OSError, subprocess.TimeoutExpired) as error:
        raise UpdateError('GitHub access failed or timed out; check gh installation/authentication and connectivity.') from error
    if result:
        raise UpdateError('GitHub release access failed; check gh authentication, repository access and published releases.')


def latest_release(gh: str, directory: Path) -> object:
    target = directory / 'release.json'
    _github_output(gh, 'releases/latest', target)
    try:
        return json.loads(target.read_bytes())
    except (ValueError, UnicodeError) as error:
        raise UpdateError('GitHub returned invalid release metadata.') from error


def verify_wheel(path: Path, release: Release) -> None:
    if path.stat().st_size != release.size:
        raise UpdateError('Downloaded wheel size does not match the release.')
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if digest != release.sha256:
        raise UpdateError('Downloaded wheel SHA-256 does not match the release; nothing was installed.')
    try:
        with zipfile.ZipFile(path) as wheel:
            name = f'dotunnel-{release.version}.dist-info/METADATA'
            entries = [item for item in wheel.infolist() if item.filename == name]
            if len(entries) != 1 or entries[0].file_size > 256 * 1024:
                raise UpdateError('Wheel package metadata is missing, duplicated or oversized.')
            metadata = BytesParser().parsebytes(wheel.read(entries[0]))
            if metadata.get_all('Name') != ['dotunnel'] or metadata.get_all('Version') != [release.version]:
                raise UpdateError('Wheel package name/version does not match the release.')
    except (zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError) as error:
        raise UpdateError('The downloaded asset is not a supported wheel.') from error


def _installer(local_development: bool) -> list[str]:
    if sys.platform != 'linux' or os.getuid() == 0 or sys.prefix == sys.base_prefix or local_development:
        raise UpdateError('Automatic update requires a non-root Linux virtualenv package installation; use your normal installer otherwise.')
    distribution = importlib.metadata.distribution('dotunnel')
    prefix = Path(sys.prefix).resolve()
    if not Path(str(distribution.locate_file(''))).resolve().is_relative_to(prefix):
        raise UpdateError('The package is outside the current virtualenv; refusing to overwrite it.')
    direct_url = distribution.read_text('direct_url.json')
    if direct_url:
        try:
            data = json.loads(direct_url)
            if data.get('dir_info', {}).get('editable', False):
                raise UpdateError('Editable/source-checkout installations require manual updates.')
        except (ValueError, AttributeError) as error:
            raise UpdateError('Installed package provenance is invalid.') from error
    uv = shutil.which('uv')
    if uv:
        return [uv, '--no-config', 'pip', 'install', '--python', sys.executable,
                '--prefix', sys.prefix, '--only-binary', ':all:']
    if importlib.util.find_spec('pip') is not None:
        return [sys.executable, '-m', 'pip', '--isolated', 'install', '--upgrade',
                '--prefix', sys.prefix, '--only-binary', ':all:']
    raise UpdateError('Install uv or pip in the current environment before updating.')


def _confirm() -> bool:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise UpdateError('An interactive terminal is required for update approval; nothing was installed.')
    while True:
        print('Update now? [Y/n] ', end='', flush=True)
        answer = sys.stdin.readline()
        if not answer:
            raise UpdateError('Input ended before approval; nothing was installed.')
        answer = answer.strip().lower()
        if answer in ('', 'y', 'yes'):
            return True
        if answer in ('n', 'no'):
            return False
        print('Enter Y or n.')


def run_update(current_version: str, local_development: bool = False) -> int:
    print(f'Installed dotunnel version: {current_version}')
    print(f'Update source: GitHub Releases ({REPOSITORY})')
    try:
        current = version_key(current_version)
        gh = shutil.which('gh')
        if not gh:
            raise UpdateError('GitHub CLI (gh) is required; install it and authenticate for private repository access.')
        with tempfile.TemporaryDirectory(prefix='dotunnel-update-') as temporary:
            directory = Path(temporary)
            metadata = latest_release(gh, directory)
            latest = release_version(metadata)
            print(f'Latest stable version: {latest}')
            available = version_key(latest)
            if current >= available:
                print('Already up to date.' if current == available else 'Installed version is newer; no downgrade performed.')
                return 0
            print(f'Update available: {current_version} -> {latest}')
            release = parse_release(metadata)
            installer = _installer(local_development)
            if not _confirm():
                print('Update cancelled; installation unchanged.')
                return 0
            wheel = directory / release.filename
            _github_output(gh, f'releases/assets/{release.asset_id}', wheel, binary=True)
            verify_wheel(wheel, release)
            environment = os.environ.copy()
            for key in ('PIP_TARGET', 'PIP_PREFIX', 'PIP_USER', 'UV_TARGET', 'UV_PREFIX'):
                environment.pop(key, None)
            try:
                result = subprocess.run([*installer, str(wheel)], timeout=300,
                                        cwd=directory, env=environment)
            except (OSError, subprocess.TimeoutExpired) as error:
                raise UpdateError('Installer failed or timed out; inspect the environment before retrying.') from error
            if result.returncode:
                raise UpdateError('Installer failed; inspect the environment before retrying.')
            if importlib.metadata.version('dotunnel') != release.version:
                raise UpdateError('Installer exited successfully but the requested version was not installed.')
            print(f'Updated dotunnel to {release.version}.')
            print('Running clients/services were not restarted; restart them manually when idle to load the new version.')
            return 0
    except KeyboardInterrupt:
        print('\nUpdate cancelled.', file=sys.stderr)
        return 130
    except (UpdateError, OSError, importlib.metadata.PackageNotFoundError) as error:
        message = str(error) if isinstance(error, UpdateError) else 'Unable to inspect the installed package or update files.'
        print(f'Update failed: {message}', file=sys.stderr)
        return 2
