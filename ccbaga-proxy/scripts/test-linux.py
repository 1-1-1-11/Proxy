#!/usr/bin/env python3
# [INPUT]: 可丢弃构建树、安装前缀、Linux 安装器和真实产物验收层。
# [OUTPUT]: 安装隔离、A/B 运行保护、失败回滚、载荷缺失与引擎篡改拒绝回归。
# [POS]: 离线临时目录测试，不安装到真实用户目录。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('install_linux', Path(__file__).with_name('install-linux.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
payload_spec = importlib.util.spec_from_file_location('payload', Path(__file__).with_name('verify-linux-package.py'))
payload = importlib.util.module_from_spec(payload_spec)
payload_spec.loader.exec_module(payload)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ccbaga-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / 'build'
        self.prefix = self.root / 'prefix with spaces'
        for name in ['requirement-french', 'browser-runtime/LinuxBrowser/chrome', 'browser-ui/browser.html']:
            path = self.build / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture')
            path.chmod(0o755)

    def test_install_upgrade_preserves_unrelated_user_data(self):
        data = self.prefix / 'share/ai.local.requirement-french/browser/profile/keep'
        data.parent.mkdir(parents=True)
        data.write_text('personal')
        installer.install(self.build, self.prefix)
        installer.install(self.build, self.prefix)
        self.assertEqual(data.read_text(), 'personal')
        self.assertEqual((self.prefix / 'bin/ccbaga-a').read_text(), 'fixture')
        self.assertIn('--browser %U', (self.prefix / 'share/applications/ccbaga-browser.desktop').read_text())
        self.assertTrue((self.prefix / 'share/ccbaga-install/lib/CCBaga-A/browser-runtime/LinuxBrowser/chrome').exists())

    def test_custom_launcher_and_linked_desktop_are_preserved(self):
        launcher = self.prefix / 'bin/ccbaga-a'
        launcher.parent.mkdir(parents=True)
        launcher.write_text('custom')
        with self.assertRaises(RuntimeError):
            installer.install(self.build, self.prefix)
        self.assertEqual(launcher.read_text(), 'custom')
        launcher.unlink()
        desktop = self.prefix / 'share/applications/ccbaga-a.desktop'
        desktop.parent.mkdir(parents=True)
        desktop.symlink_to(launcher)
        with self.assertRaises(RuntimeError):
            installer.install(self.build, self.prefix)
        self.assertTrue(desktop.is_symlink())

    def test_failed_desktop_write_rolls_back_application(self):
        installer.install(self.build, self.prefix)
        (self.build / 'requirement-french').write_text('new')
        original = Path.write_text
        def fail_once(path, *args, **kwargs):
            if path.name == 'ccbaga-browser.desktop':
                raise OSError('fixture failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'write_text', fail_once):
            with self.assertRaises(OSError):
                installer.install(self.build, self.prefix)
        self.assertEqual((self.prefix / 'bin/ccbaga-a').read_text(), 'fixture')

    def test_exec_escaping_rejects_newlines_and_escapes_field_codes(self):
        self.assertIn('%%', installer.desktop_exec(Path('/tmp/100%/app')))
        self.assertIn('\\\\$', installer.desktop_exec(Path('/tmp/$secret/app')))
        with self.assertRaises(ValueError):
            installer.desktop_exec(Path('/tmp/app\nmalformed'))

    def test_running_companion_blocks_replacement(self):
        installer.install(self.build, self.prefix)
        proc = self.root / 'proc-exe'
        proc.symlink_to(self.prefix / 'share/ccbaga-install/lib/CCBaga-A/browser-runtime/LinuxBrowser/chrome')
        original = Path.glob
        def processes(path, pattern):
            return iter([proc]) if path == Path('/proc') else original(path, pattern)
        (self.build / 'requirement-french').write_text('replacement')
        with patch.object(Path, 'glob', processes):
            with self.assertRaisesRegex(RuntimeError, 'CCBaga-B'):
                installer.install(self.build, self.prefix)
        self.assertEqual((self.prefix / 'bin/ccbaga-a').read_text(), 'fixture')


class PayloadTests(unittest.TestCase):
    def test_payload_rejects_missing_ui_and_modified_browser(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = b'\x7fELF\x02' + b'\0' * 13 + b'\x3e\x00'
            for name, content in {
                'usr/bin/requirement-french': elf,
                'usr/lib/CCBaga-A/browser-runtime/LinuxBrowser/chrome': elf,
                'usr/lib/CCBaga-A/browser-runtime/LICENSE.fingerprint-chromium': b'license',
                'usr/lib/CCBaga-A/browser-ui/browser.html': b'html',
                'usr/lib/CCBaga-A/browser-ui/assets/browser.js': b'js',
                'usr/share/applications/ccbaga-browser.desktop': b'Exec=requirement-french --browser %U',
                'usr/share/icons/hicolor/512x512/apps/ccbaga-browser.png': b'icon',
                'source-engine/chrome': elf,
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o755)
            payload.verify(root, root / 'source-engine/chrome')
            browser = root / 'usr/lib/CCBaga-A/browser-runtime/LinuxBrowser/chrome'
            isolated = root / 'usr/libexec/CCBaga-B/chrome'
            isolated.parent.mkdir(parents=True)
            browser.rename(isolated)
            payload.verify(root, root / 'source-engine/chrome')
            page = root / 'usr/lib/CCBaga-A/browser-ui/browser.html'
            page.unlink()
            with self.assertRaisesRegex(RuntimeError, 'UI'):
                payload.verify(root, root / 'source-engine/chrome')
            page.write_text('html')
            library = root / 'source-engine/libfixture.so'
            library.write_text('original optional library')
            (isolated.parent / library.name).write_text('modified library')
            with self.assertRaisesRegex(RuntimeError, 'engine file'):
                payload.verify(root, root / 'source-engine/chrome')
            library.unlink()
            isolated.write_text('modified')
            with self.assertRaisesRegex(RuntimeError, 'pinned browser'):
                payload.verify(root, root / 'source-engine/chrome')


if __name__ == '__main__':
    unittest.main()
