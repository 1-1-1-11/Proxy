"""Offline tests for the login-link entry; no browser, network or writes outside temporary folders."""
import json
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

import browser_entry as entry


class UrlTests(unittest.TestCase):
    def test_url_validation(self):
        self.assertEqual(entry.valid_url('https://claude.ai/login'), 'https://claude.ai/login')
        for bad in ('', 'file:///c:/x', 'https://user:pw@claude.ai', 'https://claude.ai/"x', 'javascript:alert(1)'):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                entry.valid_url(bad)


class ProgramTests(unittest.TestCase):
    def setUp(self):
        self.folder = pathlib.Path(tempfile.mkdtemp(prefix='claude-entry-'))
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.exe = self.folder / 'requirement-french.exe'
        self.exe.write_bytes(b'')
        mock.patch.object(entry, 'ENTRY', self.folder / 'browser-entry.json').start()
        self.addCleanup(mock.patch.stopall)

    def record(self, value):
        entry.ENTRY.write_text(json.dumps(value), encoding='utf-8')

    def test_only_the_recorded_existing_ccbaga_program_counts(self):
        self.assertIsNone(entry.program())
        self.record({'schema': 1, 'program': str(self.exe)})
        self.assertEqual(entry.program(), self.exe)
        other = self.folder / 'other.exe'
        other.write_bytes(b'')
        for bad in ({'schema': 2, 'program': str(self.exe)}, {'schema': 1, 'program': 'requirement-french.exe'},
                    {'schema': 1, 'program': str(other)}, {'schema': 1, 'program': str(self.folder / 'missing' / 'requirement-french.exe')},
                    {'schema': 1}, ['not', 'an', 'object']):
            with self.subTest(record=bad):
                self.record(bad)
                self.assertIsNone(entry.program())
        entry.ENTRY.write_text('{broken', encoding='utf-8')
        self.assertIsNone(entry.program())


class GateTests(unittest.TestCase):
    def setUp(self):
        self.popen = mock.patch.object(entry.subprocess, 'Popen').start()
        self.program = mock.patch.object(entry, 'program', return_value=pathlib.Path('C:/fixture/requirement-french.exe')).start()
        self.addCleanup(mock.patch.stopall)

    def gate(self, state):
        return mock.patch.object(entry, 'gate', return_value={'state': state, 'problems': [] if state == 'ready' else ['fixed_egress']})

    def test_blocked_gate_never_hands_off(self):
        with self.gate('blocked'):
            self.assertEqual(entry.launch('https://claude.ai/login')['state'], 'blocked')
        self.popen.assert_not_called()

    def test_ready_gate_hands_the_url_to_the_fingerprint_browser_entry(self):
        with self.gate('ready'):
            self.assertEqual(entry.launch('https://claude.ai/login')['state'], 'opened')
        launched=self.popen.call_args.args[0]
        self.assertEqual(launched[0].replace('/','\\'), 'C:\\fixture\\requirement-french.exe')
        self.assertEqual(launched[1:], ['--browser', 'https://claude.ai/login'])

    def test_missing_entry_is_blocked_not_a_fallback_browser(self):
        self.program.return_value = None
        with self.gate('ready'):
            self.assertEqual(entry.launch('https://claude.ai/login'), {'state': 'blocked', 'problems': ['entry']})
        self.popen.assert_not_called()

    def test_invalid_url_is_rejected_before_the_gate(self):
        with self.gate('ready') as gate, self.assertRaises(ValueError):
            entry.launch('file:///c:/secret')
        gate.assert_not_called()
        self.popen.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
