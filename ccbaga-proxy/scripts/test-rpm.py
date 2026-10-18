#!/usr/bin/env python3
# [INPUT]: 标准 dpkg/rpmbuild/bsdtar、原生 RPM 构建层和可丢弃载荷。
# [OUTPUT]: 真实 RPM 元数据与原始载荷/引擎完整性回归，不执行样本程序。
# [POS]: 独立于应用编译的格式回归；只在临时目录生成、提取文件。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

scripts = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('release', scripts / 'release-linux.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
with tempfile.TemporaryDirectory(prefix='ccbaga-rpm-test-') as temporary:
    root = Path(temporary)
    release.ROOT = root
    (root / 'src-tauri/target/release/bundle').mkdir(parents=True)
    shutil.copy2(scripts.parent / 'src-tauri/tauri.linux.conf.json', root / 'src-tauri/tauri.linux.conf.json')
    tree = root / 'deb'
    elf = b'\x7fELF\x02' + b'\0' * 13 + b'\x3e\x00'
    for name, value in {
        'DEBIAN/control': b'Package: ccbaga-a\nVersion: 0.0.1\nArchitecture: amd64\nMaintainer: Fixture <fixture@example.invalid>\nDescription: disposable package fixture\n',
        'usr/bin/requirement-french': elf,
        'usr/libexec/CCBaga-B/chrome': elf,
        'usr/lib/CCBaga-A/browser-runtime/LICENSE.fingerprint-chromium': b'fixture',
        'usr/lib/CCBaga-A/browser-ui/browser.html': b'fixture',
        'usr/lib/CCBaga-A/browser-ui/assets/browser.js': b'fixture',
        'usr/share/applications/ccbaga-browser.desktop': b'Exec=requirement-french --browser %U',
        'usr/share/icons/hicolor/512x512/apps/ccbaga-browser.png': b'fixture',
    }.items():
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(0o755 if name.endswith(('chrome', 'requirement-french')) else 0o644)
    deb = root / 'fixture.deb'
    subprocess.run(['dpkg-deb', '--build', str(tree), str(deb)], check=True, stdout=subprocess.DEVNULL)
    release.build_rpm(deb, '0.0.1')
    rpm, = (root / 'src-tauri/target/release/bundle/rpm').glob('*.rpm')
    assert subprocess.check_output(['rpm', '-qp', '--queryformat', '%{VERSION} %{ARCH}', str(rpm)], text=True) == '0.0.1 x86_64'
    unpacked = root / 'unpacked'
    unpacked.mkdir()
    subprocess.run(['bsdtar', '-xf', str(rpm), '-C', str(unpacked)], check=True)
    release.payload.verify(unpacked, tree / 'usr/libexec/CCBaga-B/chrome')
print('Native RPM metadata and unmodified payload regression passed.')
