#!/usr/bin/env python3
# [INPUT]: 带内嵌 UI 和固定 Linux 引擎的本地构建，以及用户指定安装前缀。
# [OUTPUT]: 用户前缀 A/B 桌面入口和可回滚的应用目录替换，不修改用户资料。
# [POS]: Linux 源码安装边界；拒绝自定义启动器、链接父目录和仍运行的 A/B。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
import argparse
import os
from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def desktop_exec(path):
    text = str(path)
    if '\n' in text or '\r' in text:
        raise ValueError('Invalid application path')
    # Desktop Entry Exec has both string-value and argument quoting layers.
    for old, new in [('\\', '\\\\\\\\'), ('"', '\\\\\\"'), ('`', '\\\\`'), ('$', '\\\\$'), ('%', '%%')]:
        text = text.replace(old, new)
    return f'"{text}"'


def install(build, prefix):
    build, prefix = build.resolve(), prefix.absolute()
    source = build / 'requirement-french'
    engine = build / 'browser-runtime/LinuxBrowser/chrome'
    if not source.is_file() or not os.access(source, os.X_OK) or not engine.is_file():
        raise RuntimeError('Build first with bun run tauri build; native executable or browser resources missing')
    app = prefix / 'share/ccbaga-install'
    launcher = prefix / 'bin/ccbaga-a'
    executable = app / 'bin/requirement-french'
    for path in [app, launcher]:
        for parent in [path.parent, *path.parents]:
            if parent.is_symlink():
                raise RuntimeError(f'Refusing linked installation parent: {parent}')
    if app.is_symlink() or (app.exists() and not (app / '.ccbaga-install').is_file()):
        raise RuntimeError('Existing install directory is not owned by this installer')
    if (launcher.exists() or launcher.is_symlink()) and (not launcher.is_symlink() or launcher.readlink() != executable):
        raise RuntimeError('Refusing to replace a custom launcher')
    for proc in Path('/proc').glob('[0-9]*/exe'):
        try:
            if proc.readlink().is_relative_to(app):
                raise RuntimeError('Quit CCBaga-A and CCBaga-B before installing; installation left unchanged')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    applications = prefix / 'share/applications'
    for parent in [applications, *applications.parents]:
        if parent.is_symlink():
            raise RuntimeError(f'Refusing linked desktop directory: {parent}')
    desktop_files = [applications / f'{name}.desktop' for name in ['ccbaga-a', 'ccbaga-browser']]
    for path in desktop_files:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise RuntimeError('Refusing linked or non-file desktop entry')
    old_desktops = {path: path.read_bytes() if path.exists() else None for path in desktop_files}
    had_launcher = launcher.is_symlink()
    app.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.ccbaga-stage-', dir=app.parent) as temporary:
        stage = Path(temporary)
        pending = stage / 'new'
        (pending / 'bin').mkdir(parents=True)
        resources = pending / 'lib/CCBaga-A'
        resources.mkdir(parents=True)
        shutil.copy2(source, pending / 'bin/requirement-french')
        for name in ['browser-runtime', 'browser-ui']:
            shutil.copytree(build / name, resources / name, symlinks=True)
        (pending / '.ccbaga-install').write_text('CCBaga Linux source installation\n')
        previous = stage / 'previous'
        if app.exists():
            app.rename(previous)
        try:
            pending.rename(app)
            launcher.parent.mkdir(parents=True, exist_ok=True)
            if not launcher.is_symlink():
                launcher.symlink_to(executable)
            applications.mkdir(parents=True, exist_ok=True)
            for name, title, args in [('ccbaga-a', 'CCBaga-A', ''), ('ccbaga-browser', 'CCBaga-B', ' --browser %U')]:
                target = applications / f'{name}.desktop'
                if target.is_symlink():
                    raise RuntimeError('Refusing linked desktop entry')
                target.write_text(f'[Desktop Entry]\nType=Application\nName={title}\nExec={desktop_exec(executable)}{args}\nTerminal=false\nCategories=Utility;\n')
        except Exception:
            for path, content in old_desktops.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
            if not had_launcher:
                launcher.unlink(missing_ok=True)
            if app.exists():
                shutil.rmtree(app)
            if previous.exists():
                previous.rename(app)
            raise
    print(f'Installed CCBaga-A and CCBaga-B in {app}. Launch {launcher}.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', type=Path, default=ROOT / 'src-tauri/target/release')
    parser.add_argument('--prefix', type=Path, default=Path.home() / '.local')
    args = parser.parse_args()
    install(args.build_dir, args.prefix)


if __name__ == '__main__':
    main()
