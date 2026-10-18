#!/usr/bin/env python3
# [INPUT]: 已解包 Linux 安装产物、固定来源引擎及宿主版本。
# [OUTPUT]: x86_64 宿主/引擎、内嵌 UI、B 桌面入口/图标和源引擎全文件/链接完整性验收。
# [POS]: Linux 四种安装产物共用的载荷边界；只读产物，不安装或访问用户资料。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
import hashlib
import os
from pathlib import Path
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(root, engine):
    host = root / 'usr/bin/requirement-french'
    with host.open('rb') as stream:
        elf = stream.read(20)
    if elf[:5] != b'\x7fELF\x02' or elf[18:20] != b'\x3e\x00' or not os.access(host, os.X_OK):
        raise RuntimeError('Package host is not an executable x86_64 ELF')
    browsers = list(root.glob('usr/lib/**/LinuxBrowser/chrome')) + list(root.glob('usr/libexec/CCBaga-B/chrome'))
    if len(browsers) != 1 or digest(browsers[0]) != digest(engine) or not os.access(browsers[0], os.X_OK):
        raise RuntimeError('Package must preserve the pinned browser executable')
    for source in engine.parent.rglob('*'):
        target = browsers[0].parent / source.relative_to(engine.parent)
        if source.is_symlink():
            if not target.is_symlink() or os.readlink(target) != os.readlink(source):
                raise RuntimeError('Package changed a browser engine link')
        elif source.is_file() and (not target.is_file() or digest(target) != digest(source)):
            raise RuntimeError('Package changed a browser engine file')
    resources = root / 'usr/lib/CCBaga-A'
    if not (resources / 'browser-ui/browser.html').is_file() or not list((resources / 'browser-ui/assets').glob('*.js')):
        raise RuntimeError('Embedded browser UI is missing')
    if not (resources / 'browser-runtime/LICENSE.fingerprint-chromium').is_file():
        raise RuntimeError('Browser license is missing')
    desktop = root / 'usr/share/applications/ccbaga-browser.desktop'
    if 'Exec=requirement-french --browser %U' not in desktop.read_text():
        raise RuntimeError('Companion desktop entry is invalid')
    if not (root / 'usr/share/icons/hicolor/512x512/apps/ccbaga-browser.png').is_file():
        raise RuntimeError('Companion icon is missing')
    print('Linux package payload verified:', root)


if __name__ == '__main__':
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
