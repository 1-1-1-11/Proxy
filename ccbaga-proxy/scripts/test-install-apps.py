#!/usr/bin/env python3
# [INPUT]: macOS 安装模式边界、开发环境过滤与可丢弃命令替身。
# [OUTPUT]: 开发不能装外部 DMG、只接受临时签名、正式 Gatekeeper 不可绕过和凭据不传构建的回归。
# [POS]: 本机安装信任边界验收；不操作 /Applications、钥匙串或真实凭据。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

installer = load('install-apps'); dev = load('dev-install')

class InstallTests(unittest.TestCase):
    def test_development_cannot_accept_an_external_installer(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            installer.arguments(['--development', '/Volumes/Installer'])
        self.assertTrue(installer.arguments(['--development']).development)
        self.assertFalse(installer.arguments(['/Volumes/Installer']).development)

    def test_only_local_adhoc_skips_gatekeeper_and_release_still_requires_it(self):
        with patch.object(installer, 'run', return_value=SimpleNamespace(stderr='Signature=adhoc\n')) as run:
            installer.verify(Path('/fixture/app'), True)
            self.assertFalse(any(call.args[0]=='spctl' for call in run.call_args_list))
        with patch.object(installer, 'run', return_value=SimpleNamespace(stderr='Authority=Developer ID\n')):
            with self.assertRaises(RuntimeError): installer.verify(Path('/fixture/app'), True)
        def reject_gatekeeper(*args):
            if args[0]=='spctl': raise subprocess.CalledProcessError(1, args)
            return SimpleNamespace(stderr='Signature=adhoc\n')
        with patch.object(installer, 'run', side_effect=reject_gatekeeper):
            with self.assertRaises(subprocess.CalledProcessError): installer.verify(Path('/fixture/app'))

    def test_development_never_inherits_signing_secrets(self):
        with patch.dict(os.environ, {'APPLE_API_PRIVATE_KEY':'fixture', 'TAURI_SIGNING_PRIVATE_KEY':'fixture', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD':'fixture', 'CC_SIGN_IDENTITY':'fixture'}):
            env=dev.development_env()
            self.assertEqual(env['CC_SIGN_IDENTITY'], '-')
            self.assertFalse(any(key.startswith(('APPLE_', 'TAURI_SIGNING_PRIVATE_KEY')) for key in env))

if __name__ == '__main__':
    unittest.main()
