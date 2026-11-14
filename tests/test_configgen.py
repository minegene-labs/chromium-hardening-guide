import json
import os
import plistlib
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIGGEN = ROOT / 'configs' / 'ConfigGen.py'
CONFIG = ROOT / 'configs' / 'Configuration.config'
REG_LINE = re.compile(r'^"[^"]+"=(dword:[0-9A-F]{8}|"(?:[^"\\]|\\.)*")$')


def run_configgen(*args):
    outDir = os.environ.get('CONFIGGEN_TEST_OUT')
    if outDir:
        os.makedirs(outDir, exist_ok=True)
    workDir = tempfile.mkdtemp(prefix='configgen-', dir=outDir or None)
    result = subprocess.run(
        [sys.executable, str(CONFIGGEN), '-f', str(CONFIG), *args],
        cwd=workDir, capture_output=True, text=True
    )
    return result, Path(workDir)


class ConfigGenTest(unittest.TestCase):
    def generate(self, *args):
        result, workDir = run_configgen(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return workDir

    def test_configuration_is_valid_json(self):
        with open(CONFIG, encoding='utf-8') as f:
            self.assertTrue(json.load(f))

    def test_linux_policy_json(self):
        out = self.generate('-s', 'linux', '-t', 'policy', '-c', 'y')
        with open(out / 'policy' / '80-hardening-guide-policy.json', encoding='utf-8') as f:
            self.assertTrue(json.load(f))

    def test_linux_recommended_policy_json(self):
        out = self.generate('-s', 'linux', '-t', 'policy', '-c', 'y', '-r')
        for name in ('policy/80-hardening-guide-policy.json',
                     'recommended-policy/81-hardening-guide-policy-recommended.json'):
            with open(out / name, encoding='utf-8') as f:
                self.assertIsInstance(json.load(f), dict)

    def test_macos_profile_plist(self):
        out = self.generate('-s', 'macos', '-t', 'policy', '-c', 'y')
        with open(out / 'policy' / 'hardening-guide-policy.mobileconfig', 'rb') as f:
            profile = plistlib.load(f)
        self.assertEqual(profile['PayloadType'], 'Configuration')
        content = profile['PayloadContent'][0]['PayloadContent']['com.google.Chrome']
        self.assertTrue(content['Forced'][0]['mcx_preference_settings'])

    def test_macos_recommended_plist(self):
        out = self.generate('-s', 'macos', '-t', 'policy', '-c', 'y', '-r')
        with open(out / 'recommended-policy' / 'com.google.Chrome.plist', 'rb') as f:
            self.assertIsInstance(plistlib.load(f), dict)

    def test_windows_reg(self):
        out = self.generate('-s', 'windows', '-t', 'policy', '-c', 'y', '-r')
        with open(out / 'policy' / 'hardening-guide-policy.reg', encoding='utf-8') as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[0], 'Windows Registry Editor Version 5.00')
        sections = [l for l in lines if l.startswith('[')]
        self.assertEqual(len(sections), 2)
        for line in lines[1:]:
            if line and not line.startswith('['):
                self.assertRegex(line, REG_LINE)

    def test_flags_file(self):
        for system in ('linux', 'windows', 'macos'):
            with self.subTest(system=system):
                out = self.generate('-s', system, '-t', 'commandline', '-c', 'y')
                text = (out / 'flags' / '80-hardening-guide-flags.conf').read_text(encoding='utf-8')
                self.assertIn('--', text)

    def test_variable_flags_format(self):
        out = self.generate('-s', 'linux', '-t', 'commandline', '-c', 'y', '--format', 'variable')
        text = (out / 'flags' / '80-hardening-guide-flags.conf').read_text(encoding='utf-8')
        self.assertTrue(text.startswith('CHROMIUM_FLAGS="'))

    def test_choice_yes_matches_y(self):
        for system in ('linux', 'windows', 'macos'):
            with self.subTest(system=system):
                a = self.generate('-s', system, '-c', 'y')
                b = self.generate('-s', system, '-c', 'yes')
                for path in a.rglob('*'):
                    if path.is_file():
                        self.assertEqual(path.read_bytes(), (b / path.relative_to(a)).read_bytes())

    def test_default_system_is_host(self):
        host = {'linux': 'linux', 'windows': 'windows', 'darwin': 'macos'}[platform.system().lower()]
        a = self.generate('-t', 'policy', '-c', 'y')
        b = self.generate('-s', host, '-t', 'policy', '-c', 'y')
        files_a = sorted(p.relative_to(a).as_posix() for p in a.rglob('*') if p.is_file())
        files_b = sorted(p.relative_to(b).as_posix() for p in b.rglob('*') if p.is_file())
        self.assertEqual(files_a, files_b)
        self.assertTrue(files_a)


if __name__ == '__main__':
    unittest.main()
