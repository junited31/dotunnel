import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from typing import TypedDict


ROOT = Path(__file__).resolve().parents[1]


class WheelOptions(TypedDict, total=False):
    filename_version: str
    metadata_name: str
    metadata_version: str
    tag: str
    omit_metadata: bool
    duplicate_metadata: bool
    extra_metadata: bool
    metadata_padding: int
    extra_bytes: int


class ReleaseBundleTests(unittest.TestCase):
    def test_prepare_emits_verifiable_bundle_and_detects_asset_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wheel = base / 'dotunnel-0.1.4-py3-none-any.whl'
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('dotunnel/__init__.py', '')
                archive.writestr('dotunnel-0.1.4.dist-info/METADATA',
                                 'Metadata-Version: 2.4\nName: dotunnel\nVersion: 0.1.4\n')
                archive.writestr('dotunnel-0.1.4.dist-info/WHEEL',
                                 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
            template = base / 'template.sh'
            template.write_text(
                "#!/bin/sh\nWHEEL_VERSION='0.1.4'\n"
                "WHEEL_URL='https://github.com/junited31/dotunnel/releases/download/"
                "v0.1.4/dotunnel-0.1.4-py3-none-any.whl'\n"
                "WHEEL_SHA256='" + '0' * 64 + "'\nWHEEL_BYTES=1\n"
            )
            output = base / 'bundle'
            source = '1' * 40
            result = subprocess.run([
                sys.executable, str(ROOT / 'scripts/release.py'), 'prepare',
                '--version', '0.1.4', '--source-sha', source,
                '--wheel', str(wheel), '--installer', str(template), '--output', str(output),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((output / 'release-manifest.json').read_text())
            self.assertEqual(manifest['version'], '0.1.4')
            self.assertEqual(manifest['source_sha'], source)
            names = {entry['name'] for entry in manifest['assets']}
            self.assertEqual(names, {wheel.name, 'install.sh'})
            check = subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=output,
                                   capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            copied = output / wheel.name
            self.assertEqual(copied.read_bytes(), wheel.read_bytes())
            self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(),
                             next(entry['sha256'] for entry in manifest['assets']
                                  if entry['name'] == wheel.name))
            copied.write_bytes(copied.read_bytes() + b'tampered')
            tampered = subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=output,
                                      capture_output=True, text=True)
            self.assertNotEqual(tampered.returncode, 0)

    @staticmethod
    def write_wheel(path, *, filename_version='0.1.4', metadata_name='dotunnel',
                    metadata_version='0.1.4', tag='py3-none-any', omit_metadata=False,
                    duplicate_metadata=False, extra_metadata=False,
                    metadata_padding=0, extra_bytes=0):
        dist_info = f'dotunnel-{filename_version}.dist-info'
        metadata = (
            f'Metadata-Version: 2.4\nName: {metadata_name}\n'
            f'Version: {metadata_version}\n'
        ).encode()
        if metadata_padding:
            metadata += b'Description: ' + b'x' * metadata_padding
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('dotunnel/__init__.py', '')
            if not omit_metadata:
                archive.writestr(f'{dist_info}/METADATA', metadata)
                if duplicate_metadata:
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore', UserWarning)
                        archive.writestr(f'{dist_info}/METADATA', metadata)
            if extra_metadata:
                archive.writestr(
                    'dotunnel-9.9.9.dist-info/METADATA',
                    'Metadata-Version: 2.4\nName: dotunnel\nVersion: 9.9.9\n',
                )
            archive.writestr(
                f'{dist_info}/WHEEL',
                f'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n',
            )
            if extra_bytes:
                archive.writestr('padding.bin', b'x' * extra_bytes)

    @staticmethod
    def template_text():
        return (
            "#!/bin/sh\n"
            "WHEEL_VERSION='0.1.4'\n"
            "WHEEL_URL='https://github.com/junited31/dotunnel/releases/download/"
            "v0.1.4/dotunnel-0.1.4-py3-none-any.whl'\n"
            "WHEEL_SHA256='" + '0' * 64 + "'\n"
            "WHEEL_BYTES=1\n"
        )

    def invoke_prepare(self, base, wheel, *, version='0.1.4', source_sha='1' * 40,
                       installer_text=None, output=None):
        template = base / 'template.sh'
        template.write_text(installer_text if installer_text is not None else self.template_text())
        output = output if output is not None else base / 'bundle'
        return subprocess.run([
            sys.executable, str(ROOT / 'scripts/release.py'), 'prepare',
            '--version', version, '--source-sha', source_sha,
            '--wheel', str(wheel), '--installer', str(template), '--output', str(output),
        ], capture_output=True, text=True)

    def test_prepare_rejects_noncanonical_version_and_source_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wheel = base / 'dotunnel-0.1.4-py3-none-any.whl'
            self.write_wheel(wheel)
            for index, version in enumerate(('v0.1.4', '0.1', '01.2.3', '0.1.4rc1')):
                with self.subTest(version=version):
                    output = base / f'bad-version-{index}'
                    result = self.invoke_prepare(base, wheel, version=version, output=output)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
            for index, source_sha in enumerate(('1' * 39, 'g' * 40, 'A' * 40)):
                with self.subTest(source_sha=source_sha):
                    output = base / f'bad-source-{index}'
                    result = self.invoke_prepare(base, wheel, source_sha=source_sha, output=output)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())

    def test_prepare_rejects_filename_metadata_and_wheel_tag_mismatches(self):
        cases: tuple[tuple[str, str, WheelOptions], ...] = (
            ('wrong-filename', 'dotunnel-0.1.5-py3-none-any.whl', {}),
            ('wrong-name', 'dotunnel-0.1.4-py3-none-any.whl', {'metadata_name': 'other'}),
            ('wrong-version', 'dotunnel-0.1.4-py3-none-any.whl', {'metadata_version': '0.1.5'}),
            ('wrong-tag', 'dotunnel-0.1.4-py3-none-any.whl', {'tag': 'py2-none-any'}),
            ('missing-metadata', 'dotunnel-0.1.4-py3-none-any.whl', {'omit_metadata': True}),
            ('duplicate-metadata', 'dotunnel-0.1.4-py3-none-any.whl', {'duplicate_metadata': True}),
            ('extra-metadata', 'dotunnel-0.1.4-py3-none-any.whl', {'extra_metadata': True}),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, filename, options in cases:
                with self.subTest(case=label):
                    base = root / label
                    base.mkdir()
                    wheel = base / filename
                    self.write_wheel(wheel, **options)
                    result = self.invoke_prepare(base, wheel)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertFalse((base / 'bundle').exists())

    def test_prepare_rejects_oversize_wheel_and_metadata(self):
        wheel_limit = 16 * 1024 * 1024
        metadata_limit = 1024 * 1024
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                ('wheel', wheel_limit + 1, 0),
                ('metadata', 0, metadata_limit + 1),
            )
            for label, extra_bytes, metadata_padding in cases:
                with self.subTest(asset=label):
                    base = root / label
                    base.mkdir()
                    wheel = base / 'dotunnel-0.1.4-py3-none-any.whl'
                    self.write_wheel(wheel, extra_bytes=extra_bytes,
                                     metadata_padding=metadata_padding)
                    result = self.invoke_prepare(base, wheel)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((base / 'bundle').exists())

    def test_prepare_refuses_occupied_output_without_touching_it(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wheel = base / 'dotunnel-0.1.4-py3-none-any.whl'
            self.write_wheel(wheel)
            output = base / 'bundle'
            output.mkdir()
            sentinel = output / 'keep'
            sentinel.write_text('existing output')
            result = self.invoke_prepare(base, wheel, output=output)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(sentinel.read_text(), 'existing output')
            self.assertEqual(sorted(item.name for item in output.iterdir()), ['keep'])

    def test_prepare_rejects_ambiguous_installer_assignment(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            wheel = base / 'dotunnel-0.1.4-py3-none-any.whl'
            self.write_wheel(wheel)
            template = self.template_text() + "WHEEL_VERSION='0.1.4'\n"
            result = self.invoke_prepare(base, wheel, installer_text=template)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((base / 'bundle').exists())

    @unittest.skipUnless(sys.platform == 'linux' and os.getuid() != 0,
                         'installer requires a non-root Linux user')
    def test_generated_installer_installs_the_prepared_wheel_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            version = '0.2.3'
            wheel = base / f'dotunnel-{version}-py3-none-any.whl'
            dist_info = f'dotunnel-{version}.dist-info'
            files = {
                'dotunnel_release_fixture/__init__.py': '',
                'dotunnel_release_fixture/cli.py':
                    "import importlib.metadata\n"
                    "def main():\n"
                    "    print(importlib.metadata.version('dotunnel'))\n",
                f'{dist_info}/METADATA':
                    f'Metadata-Version: 2.4\nName: dotunnel\nVersion: {version}\n',
                f'{dist_info}/WHEEL':
                    'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
                f'{dist_info}/entry_points.txt':
                    '[console_scripts]\ndotunnel = dotunnel_release_fixture.cli:main\n',
            }
            record = f'{dist_info}/RECORD'
            files[record] = ''.join(f'{name},,\n' for name in (*files, record))
            with zipfile.ZipFile(wheel, 'w') as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            output = base / 'bundle'
            prepared = self.invoke_prepare(
                base, wheel, version=version,
                installer_text=(ROOT / 'install.sh').read_text(), output=output,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            url = (
                f'https://github.com/junited31/dotunnel/releases/download/'
                f'v{version}/{wheel.name}'
            )
            binaries = base / 'bin'
            binaries.mkdir()
            curl = binaries / 'curl'
            curl.write_text(
                '#!/usr/bin/env python3\n'
                'import shutil, sys\n'
                'arguments = sys.argv[1:]\n'
                f'if arguments[-1] != {url!r}: raise SystemExit(2)\n'
                f"shutil.copyfile({str(wheel)!r}, arguments[arguments.index('--output') + 1])\n"
            )
            curl.chmod(0o755)
            home = base / 'home'
            home.mkdir(mode=0o700)
            environment = {
                'HOME': str(home), 'PATH': f"{binaries}:{os.environ['PATH']}",
                'LANG': 'C.UTF-8',
            }
            installed = subprocess.run(
                ['/bin/sh', str(output / 'install.sh')], env=environment,
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            result = subprocess.run(
                [str(home / '.local/bin/dotunnel')], env=environment,
                capture_output=True, text=True, check=True, timeout=15,
            )
            self.assertEqual(result.stdout.strip(), version)


    @staticmethod
    def git(repo, *args):
        return subprocess.run(
            ['git', '-C', str(repo), *args],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    def make_main_history(self, repo):
        subprocess.run(['git', 'init', '--quiet', '--initial-branch=main', str(repo)], check=True)
        self.git(repo, 'config', 'user.name', 'Release Test')
        self.git(repo, 'config', 'user.email', 'release-test@example.invalid')
        self.git(repo, 'commit', '--quiet', '--allow-empty', '-m', 'tagged source')
        source_sha = self.git(repo, 'rev-parse', 'HEAD')
        self.git(repo, 'tag', 'v0.1.4', source_sha)
        self.git(repo, 'commit', '--quiet', '--allow-empty', '-m', 'later main commit')
        main_sha = self.git(repo, 'rev-parse', 'HEAD')
        self.git(repo, 'checkout', '--quiet', source_sha)
        return source_sha, main_sha

    @staticmethod
    def ci_run(source_sha):
        repository = {'full_name': 'junited31/dotunnel'}
        return {
            'id': 1,
            'path': '.github/workflows/ci.yml',
            'event': 'push',
            'status': 'completed',
            'conclusion': 'success',
            'head_branch': 'main',
            'head_sha': source_sha,
            'workflow_id': 376166735,
            'repository': repository,
            'head_repository': repository,
        }

    def invoke_source_gate(self, repo, base, *, source_sha, ci_runs,
                           repository='junited31/dotunnel', event='push',
                           ref='refs/tags/v0.1.4', package_version='0.1.4',
                           dry_run='', main_ref='refs/heads/main'):
        runs_path = base / 'ci-runs.json'
        runs_path.write_text(json.dumps({'workflow_runs': ci_runs}))
        return subprocess.run([
            sys.executable, str(ROOT / 'scripts/release.py'), 'validate-source',
            '--repository', repository, '--event-name', event, '--ref', ref,
            '--source-sha', source_sha, '--package-version', package_version,
            '--main-ref', main_ref, '--dry-run', dry_run, '--ci-runs', str(runs_path),
        ], cwd=repo, capture_output=True, text=True)

    def test_source_gate_accepts_tag_with_ancestor_ci_for_exact_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / 'repo'
            repo.mkdir()
            source_sha, _ = self.make_main_history(repo)
            result = self.invoke_source_gate(
                repo, base, source_sha=source_sha, ci_runs=[self.ci_run(source_sha)],
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_gate_rejects_unrelated_or_unsuccessful_ci_run(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / 'repo'
            repo.mkdir()
            source_sha, _ = self.make_main_history(repo)
            invalid_runs = (
                {'path': 'ci.yml'},
                {'workflow_id': 1},
                {'event': 'pull_request'},
                {'status': 'in_progress'},
                {'conclusion': 'failure'},
                {'head_branch': 'release'},
                {'head_sha': '2' * 40},
                {'repository': {'full_name': 'attacker/dotunnel'}},
                {'head_repository': {'full_name': 'attacker/dotunnel'}},
            )
            for changes in invalid_runs:
                with self.subTest(changes=changes):
                    run = self.ci_run(source_sha)
                    run.update(changes)
                    result = self.invoke_source_gate(
                        repo, base, source_sha=source_sha, ci_runs=[run],
                    )
                    self.assertNotEqual(result.returncode, 0)
            result = self.invoke_source_gate(repo, base, source_sha=source_sha, ci_runs=[])
            self.assertNotEqual(result.returncode, 0)

    def test_source_gate_rejects_untrusted_tags_versions_and_repositories(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / 'repo'
            repo.mkdir()
            self.make_main_history(repo)
            self.git(repo, 'checkout', '--quiet', '--orphan', 'untrusted')
            self.git(repo, 'commit', '--quiet', '--allow-empty', '-m', 'untrusted source')
            untrusted_sha = self.git(repo, 'rev-parse', 'HEAD')
            self.git(repo, 'tag', 'v0.1.5', untrusted_sha)
            good_ci = [self.ci_run(untrusted_sha)]
            cases = (
                ('refs/tags/v0.1.4-untrusted', '0.1.4', 'junited31/dotunnel'),
                ('refs/tags/v0.1.5', '0.1.5', 'junited31/dotunnel'),
                ('refs/tags/v0.1.4', '0.1.5', 'junited31/dotunnel'),
                ('refs/tags/v0.1.4', '0.1.4', 'fork/dotunnel'),
            )
            for ref, package_version, repository in cases:
                with self.subTest(ref=ref, package_version=package_version, repository=repository):
                    result = self.invoke_source_gate(
                        repo, base, source_sha=untrusted_sha, ci_runs=good_ci,
                        repository=repository, ref=ref, package_version=package_version,
                    )
                    self.assertNotEqual(result.returncode, 0)

    def test_source_gate_allows_only_explicit_main_dry_run_even_when_tag_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / 'repo'
            repo.mkdir()
            _, main_sha = self.make_main_history(repo)
            self.git(repo, 'checkout', '--quiet', main_sha)
            valid_run = [self.ci_run(main_sha)]
            result = self.invoke_source_gate(
                repo, base, source_sha=main_sha, ci_runs=valid_run,
                event='workflow_dispatch', ref='refs/heads/main', dry_run='true',
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            invalid_inputs = (
                ('refs/heads/feature', 'true', main_sha),
                ('refs/heads/main', 'false', main_sha),
                ('refs/heads/main', 'true', self.git(repo, 'rev-parse', 'HEAD^')),
            )
            for ref, dry_run, source in invalid_inputs:
                with self.subTest(ref=ref, dry_run=dry_run, source=source):
                    self.git(repo, 'checkout', '--quiet', source)
                    result = self.invoke_source_gate(
                        repo, base, source_sha=source, ci_runs=[self.ci_run(source)],
                        event='workflow_dispatch', ref=ref, dry_run=dry_run,
                    )
                    self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
