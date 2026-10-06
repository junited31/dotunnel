"""Release update errors must not look like a successful version check."""
import contextlib
import io
import unittest
from unittest.mock import patch
import hashlib
import tempfile
from pathlib import Path
import zipfile

from dotunnel import updates

from dotunnel.operator import main


class UpdateCommandTests(unittest.TestCase):
    def test_missing_github_cli_fails_the_version_check(self):
        with patch('shutil.which', return_value=None), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['update']), 2)


class TerminalInput(io.StringIO):
    def isatty(self):
        return True


def release_data(version='0.1.1', payload=b'wheel'):
    return {
        'tag_name': 'v' + version, 'draft': False, 'prerelease': False,
        'assets': [{
            'id': 7, 'name': f'dotunnel-{version}-py3-none-any.whl',
            'size': len(payload), 'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(),
        }],
    }


class ReleaseValidationTests(unittest.TestCase):
    def test_numeric_version_order_avoids_lexical_downgrade(self):
        self.assertGreater(updates.version_key('0.10.0'), updates.version_key('0.9.99'))
        self.assertGreater(updates.version_key('1.0.0'), updates.version_key('0.99.99'))

    def test_noncanonical_and_prerelease_versions_fail_closed(self):
        for version in ('0.1', '01.2.3', '0.1.1rc1', '0.1.1+dev', 'x.y.z'):
            with self.subTest(version=version), self.assertRaises(updates.UpdateError):
                updates.version_key(version)

    def test_draft_prerelease_and_nonversion_tags_are_not_update_sources(self):
        for key, value in (('draft', True), ('prerelease', True), ('tag_name', 'main')):
            data = release_data()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(updates.UpdateError):
                updates.parse_release(data)

    def test_digest_identity_size_and_ambiguous_wheel_are_rejected(self):
        for key, value in (('digest', None), ('id', True), ('size', 17 * 1024 * 1024)):
            data = release_data()
            data['assets'][0][key] = value
            with self.subTest(key=key), self.assertRaises(updates.UpdateError):
                updates.parse_release(data)
        data = release_data()
        data['assets'].append(data['assets'][0].copy())
        with self.assertRaises(updates.UpdateError):
            updates.parse_release(data)

    def make_wheel(self, path, *, name='dotunnel', version='0.1.1'):
        with zipfile.ZipFile(path, 'w') as wheel:
            wheel.writestr('dotunnel-0.1.1.dist-info/METADATA',
                           f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n')
        return path.read_bytes()

    def test_tampered_content_is_rejected_even_at_same_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'wheel.whl'
            payload = self.make_wheel(path)
            release = updates.parse_release(release_data(payload=payload))
            path.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
            with self.assertRaises(updates.UpdateError):
                updates.verify_wheel(path, release)

    def test_digest_verified_wheel_must_match_package_and_version(self):
        for name, version in (('other-package', '0.1.1'), ('dotunnel', '0.1.2')):
            with self.subTest(name=name, version=version), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / 'wheel.whl'
                payload = self.make_wheel(path, name=name, version=version)
                with self.assertRaises(updates.UpdateError):
                    updates.verify_wheel(path, updates.parse_release(release_data(payload=payload)))


class UpdateConsentTests(unittest.TestCase):
    def invoke(self, current='0.1.0', data=None, answer='n\n', interactive=True):
        terminal = TerminalInput if interactive else io.StringIO
        with patch.object(updates, 'latest_release', return_value=data or release_data()), \
             patch.object(updates, '_installer', return_value=['unused-installer']), \
             patch('shutil.which', return_value='missing-gh-fixture'), \
             patch('sys.stdin', terminal(answer)), patch('sys.stdout', terminal()), \
             contextlib.redirect_stderr(io.StringIO()):
            return updates.run_update(current)

    def test_same_or_newer_local_version_needs_neither_wheel_nor_approval(self):
        for current in ('0.1.1', '0.2.0'):
            with self.subTest(current=current):
                self.assertEqual(self.invoke(current=current, data={
                    'tag_name': 'v0.1.1', 'draft': False, 'prerelease': False,
                    'assets': [],
                }, interactive=False), 0)

    def test_decline_does_not_attempt_download_or_install(self):
        self.assertEqual(self.invoke(answer='N\n'), 0)

    def test_noninteractive_yes_does_not_authorize_installation(self):
        self.assertEqual(self.invoke(answer='y\n', interactive=False), 2)

    def test_eof_does_not_authorize_default_yes(self):
        self.assertEqual(self.invoke(answer=''), 2)

    def test_invalid_reply_is_reprompted_and_can_decline(self):
        self.assertEqual(self.invoke(answer='maybe\nn\n'), 0)

    def test_blank_line_and_explicit_yes_are_approval(self):
        for answer in ('\n', 'y\n', 'YES\n'):
            with self.subTest(answer=answer), patch('sys.stdin', TerminalInput(answer)), \
                 patch('sys.stdout', TerminalInput()):
                self.assertTrue(updates._confirm())
if __name__ == '__main__':
    unittest.main()
