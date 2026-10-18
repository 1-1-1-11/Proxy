#!/bin/sh
# [INPUT]: 固定 Chromium 引擎、CARGO_TARGET_DIR、品牌化脚本与平台复制工具。
# [OUTPUT]: macOS 签名 Browser.zip；Linux 源码/Arch 构建树中的完整引擎和版本元数据。
# [POS]: 构建资源入口；避免 Tauri 逐文件复制丢失 Framework 目录链接。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" = Linux ]; then
  test -x browser-runtime/LinuxBrowser/chrome || { echo 'Run python3 scripts/fetch-browser.py first' >&2; exit 1; }
  test "$(cat browser-runtime/LinuxBrowser/version.txt)" = "$(cat browser-runtime/version.txt)" || { echo 'Engine version mismatch' >&2; exit 1; }
  engine_output="${CARGO_TARGET_DIR:-src-tauri/target}/release/browser-runtime"
  mkdir -p "$engine_output"
  cp -a browser-runtime/LinuxBrowser "$engine_output/"
  exit 0
fi
sh scripts/brand-browser.sh
/usr/bin/codesign --verify --deep --strict browser-runtime/Browser.app
/usr/bin/plutil -extract CFBundleShortVersionString raw -o browser-runtime/version.txt browser-runtime/Browser.app/Contents/Info.plist
rm -f browser-runtime/Browser.zip
/usr/bin/ditto -c -k --keepParent browser-runtime/Browser.app browser-runtime/Browser.zip
