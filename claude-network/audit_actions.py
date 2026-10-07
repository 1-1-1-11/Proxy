"""Explicitly selected local actions. Listing plans never writes or launches apps.

The menu owns confirmation. Execution requires a recently prepared plan and
rechecks local prerequisites. No raw subprocess diagnostics or registry values
are printed. A successful action still requires the caller's fresh audit.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

REG_KEY = r'SOFTWARE\Policies\Google\Chrome'
REG_NAME = 'WebRtcIPHandling'
EXPECTED = 'disable_non_proxied_udp'
TOOL = 'claude_proxy_audit_actions'
_prepared = {}


def _read_value(hive, name=REG_NAME, view=None):
    import winreg
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view is None else view)
    try:
        with winreg.OpenKey(hive, REG_KEY, 0, access) as key:
            value, kind = winreg.QueryValueEx(key, name)
        return {'exists': True, 'value': value, 'type': kind}
    except FileNotFoundError:
        return {'exists': False, 'value': None, 'type': None}


def _url_policy_present(hive, view):
    import winreg
    if _read_value(hive, 'WebRtcIPHandlingUrl', view)['exists']:
        return True
    # Also reject legacy/list-style representations without enumerating values.
    try:
        with winreg.OpenKey(hive, REG_KEY + r'\WebRtcIPHandlingUrl', 0, winreg.KEY_READ | view) as key:
            children, values, _ = winreg.QueryInfoKey(key)
            return bool(children or values)
    except FileNotFoundError:
        return False


def _registry_state():
    try:
        import winreg
        views = (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)
        return {'readable': True, 'hkcu': _read_value(winreg.HKEY_CURRENT_USER),
                'hklm': [_read_value(winreg.HKEY_LOCAL_MACHINE, view=view) for view in views],
                'url_policy_present': any(_url_policy_present(hive, view)
                    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE) for view in views)}
    except (OSError, ImportError):
        return {'readable': False}


def _restore_dependencies(install_dir):
    root = Path(install_dir)
    profile = Path.home() / 'AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev'
    paths = [root / name for name in ('repair_proxy.py', 'repair_support.py', 'repair_jsonc.cjs',
             'routing-baseline.js', 'network_check.py', 'audit_policy.json', 'repair-baseline.dpapi',
             'ClaudeBrowser.cs', 'vendor/jsonc-parser/lib/main.js')]
    paths += [Path.home() / '.codex/CodexNetworkGuard/health_monitor.py',
              Path(r'C:\Program Files\nodejs\node.exe'), Path(r'C:\Tools\ClashVerge\clash-verge.exe'),
              Path(r'C:\Tools\ClashVerge\verge-mihomo.exe'),
              Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe']
    paths += [profile / name for name in ('profiles.yaml', 'clash-verge.yaml', 'config.yaml', 'verge.yaml')]
    missing = [path.name for path in paths if not path.is_file()]
    try:
        import yaml  # noqa: F401 - the existing repair backend requires this.
    except ImportError:
        missing.append('Python PyYAML')
    return missing


def _blockers(report):
    rows = {row['id']: row for row in report.get('checks', []) if isinstance(row, dict) and 'id' in row}
    ids = {row.get('id') if isinstance(row, dict) else row for row in report.get('blocking_checks', [])}
    ids |= {key for key, row in rows.items() if row.get('required') and row.get('status') != 'pass'}
    return {key: rows.get(key, {}) for key in ids if isinstance(key, str)}


def _build_options(report, install_dir):
    blockers = _blockers(report)
    allchecks = {row['id']: row for row in report.get('checks', []) if isinstance(row, dict) and 'id' in row}
    target_exit = '本机策略定义的固定出口'
    reported_ip = allchecks.get('fixed_egress', {}).get('evidence', {}).get('expected_ip')
    if isinstance(reported_ip, str):
        try:
            target_exit = '预期固定出口 ' + str(ipaddress.ip_address(reported_ip))
        except ValueError:
            pass
    repairable = {'mihomo_core', 'listener_owner', 'controller', 'fixed_policy', 'browser-build-baseline'}
    applies = any(key in repairable or re.fullmatch(r'settings-\d+', key) for key in blockers)
    missing = _restore_dependencies(install_dir) if applies else []
    restore = {'id': 'restore_proxy', 'title': '恢复本机已有的受管理代理配置',
               'available': bool(applies and not missing),
               'changes': ['调用已有 repair_proxy.py，使用本机私有基线及现有凭据恢复受管理配置。',
                           '可能启动或重载 Clash，校正 Claude / VS Code 设置及 Google、X、OpenAI 分流。'],
               'impact': '涉及受管理应用与代理组；可能短暂影响正在使用这些通道的连接。不会承诺修复供应商、物理网络或账号问题。',
               'expected': '恢复目标：' + target_exit + '。后端完成后重新检查；依赖文件存在不代表凭据有效或外部链路一定恢复。',
               'rollback': '变更前文件由原后端保存到 repair-backups 的 manifest 和本用户 DPAPI 副本；按该记录逐文件恢复，菜单不自动恢复旧运行状态。',
               'reason': ('缺少本机恢复依赖：' + '、'.join(missing)) if missing else
                         '当前阻断项属于本机代理或受管理配置。' if applies else
                         '当前未发现需要恢复的受管理配置。' if not blockers else
                         '没有可由此后端处理的本地配置阻断；供应商故障、出口检测未知或实际请求不足不能据此承诺修复。'}
    row = blockers.get('browser_webrtc', {})
    evidence = row.get('evidence', {})
    policy = evidence.get('effective_policy', {})
    reason = evidence.get('reason')
    state = _registry_state() if reason in ('effective_policy_not_protective', 'profile_scope_unverified') else {'readable': False}
    current = state.get('hkcu', {})
    correct = current.get('exists') and current.get('type') == 1 and current.get('value') == EXPECTED
    machine_conflict = any(value.get('exists') and
                           (value.get('type') != 1 or value.get('value') != EXPECTED)
                           for value in state.get('hklm', []))
    if 'browser_webrtc' not in allchecks:
        explanation = '本轮未检查浏览器，请先运行 -Full。'
    elif allchecks['browser_webrtc'].get('status') == 'pass':
        explanation = '本次保护已通过，无需设置。'
    elif reason not in ('effective_policy_not_protective', 'profile_scope_unverified'):
        explanation = '当前 WebRTC 阻断不是已确认的策略值或来源问题；此方案不能修复 STUN、ICE、网络或其他未知原因。'
    elif not state.get('readable'):
        explanation = '无法完整读取当前用户和本机 Chrome 策略，不能安全生成写入方案。'
    elif correct:
        explanation = 'HKCU 已是期望值；请重新检查 Chrome 实际加载的策略和来源差异，重复写入不能承诺修复。'
    elif machine_conflict:
        explanation = '存在 HKLM 策略冲突；本工具不会改动机器级策略。'
    elif state.get('url_policy_present') or policy.get('url_overrides_empty') is not True:
        explanation = '存在或未确认按 URL 的 WebRTC 策略；本工具不会删除 URL 特例。'
    else:
        explanation = ''
    chrome = {'id': 'chrome_webrtc', 'title': '设置当前 Windows 用户的 Chrome WebRTC 保护策略',
              'available': not explanation,
              'changes': ['先原子保存 HKCU 单个 WebRtcIPHandling 值的存在性、值和类型。',
                          '仅将该值设为 REG_SZ disable_non_proxied_udp；不修改 HKLM 或 URL 特例。'],
              'impact': '影响此 Windows 用户的全部 Chrome 资料和 WebRTC 通话，可能改变视频会议、语音和点对点连接。不会自动启动或关闭 Chrome。',
              'expected': '设置当前用户策略后重新检查；仍需确认 Chrome 实际加载结果，不能以注册表写入成功代替 WebRTC 验收。',
              'rollback': '使用执行结果给出的 --rollback-backup 命令，只恢复此单个值；检测到后续不同修改时拒绝覆盖。',
              'reason': explanation or '观测原因是策略值或来源问题，当前用户尚未设置期望值，且未发现 HKLM 冲突或 URL 特例。'}
    return [restore, chrome]


def repair_options(report, install_dir):
    key = str(Path(install_dir).resolve())
    _prepared[key] = (time.monotonic(), copy.deepcopy(report))
    return _build_options(report, Path(install_dir))


def _serialized_value(value):
    return {'base64': base64.b64encode(value).decode('ascii')} if isinstance(value, bytes) else value


def _backup_directory(install_dir):
    root = Path(install_dir).resolve()
    folder = root / 'backups'
    if folder.resolve().parent != root or folder.resolve().name != 'backups':
        raise ValueError('Backup directory outside installation')
    return folder


def _write_backup(install_dir, previous):
    folder = _backup_directory(install_dir)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / ('chrome-webrtc-' + uuid.uuid4().hex + '.json')
    payload = {'schema': 1, 'tool': TOOL, 'action': 'chrome_webrtc',
               'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'target': {'hive': 'HKCU', 'key': REG_KEY, 'name': REG_NAME},
               'previous': {**previous, 'value': _serialized_value(previous.get('value'))},
               'applied': {'exists': True, 'value': EXPECTED, 'type': 1}}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf8', dir=folder,
                                         prefix='.chrome-webrtc-', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return target


def _write_current(value):
    import winreg
    if value['exists']:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, REG_KEY, 0,
                               winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, REG_NAME, 0, value['type'], value['value'])
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY, 0,
                                winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                winreg.DeleteValue(key, REG_NAME)
        except FileNotFoundError:
            pass


def _current():
    import winreg
    return _read_value(winreg.HKEY_CURRENT_USER)


def _rollback_command(install_dir, backup):
    # The menu prints this command; PowerShell literal quoting preserves spaces.
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    return '& ' + quote(sys.executable) + ' -X utf8 -B ' + quote(Path(install_dir) / 'audit_actions.py') + \
           ' --install-dir ' + quote(Path(install_dir).resolve()) + ' --rollback-backup ' + quote(backup)


def execute_option(option_id, install_dir, workspace):
    root = Path(install_dir).resolve()
    prepared = _prepared.get(str(root))
    if not prepared or time.monotonic() - prepared[0] > 300:
        return {'exit_code': 3, 'message': '方案未准备或已过期，请重新检查并查看修复方案；未作修改。'}
    option = next((row for row in _build_options(prepared[1], root) if row['id'] == option_id), None)
    if not option or not option['available']:
        return {'exit_code': 3, 'message': '方案当前不可执行；未作修改。' + (option['reason'] if option else '')}
    _prepared.pop(str(root), None)
    if option_id == 'restore_proxy':
        try:
            result = subprocess.run([sys.executable, '-X', 'utf8', '-B', str(root / 'repair_proxy.py'),
                                     '--workspace', str(Path(workspace).resolve())],
                                    capture_output=True, timeout=180,
                                    creationflags=0x08000000 if os.name == 'nt' else 0)
            code = result.returncode
        except (OSError, subprocess.TimeoutExpired):
            return {'exit_code': 3, 'message': '原恢复后端未在限定时间内正常完成；不输出原始诊断，请重新检查当前状态。'}
        return {'exit_code': code,
                'message': '原恢复后端执行完成，接下来须独立重检。' if code == 0 else '原恢复后端返回失败，不能视为修复成功；接下来重新检查。',
                'backup': str(root / 'repair-backups') if (root / 'repair-backups').is_dir() else None}
    backup = None
    try:
        # Re-read immediately before taking a durable snapshot and changing one value.
        previous = _current()
        if previous.get('exists') and previous.get('value') == EXPECTED and previous.get('type') == 1:
            return {'exit_code': 3, 'message': '策略已由其他操作设为期望值；未重复写入，请重新检查。'}
        backup = _write_backup(root, previous)
        _write_current({'exists': True, 'value': EXPECTED, 'type': 1})
        if _current() != {'exists': True, 'value': EXPECTED, 'type': 1}:
            raise OSError('Registry readback mismatch')
        return {'exit_code': 0, 'message': '当前用户的 Chrome 单值策略已写入并读回；尚需重新验收 Chrome 实际生效结果。',
                'backup': str(backup), 'rollback_command': _rollback_command(root, backup)}
    except (OSError, ValueError, TypeError):
        result = {'exit_code': 3, 'message': '备份或单值策略写入未完成，未宣称修复成功。'}
        if backup is not None:
            result.update(backup=str(backup), rollback_command=_rollback_command(root, backup))
        return result


def _load_backup(install_dir, filename):
    path = Path(filename).resolve(strict=True)
    if path.parent != _backup_directory(install_dir).resolve() or not re.fullmatch(r'chrome-webrtc-[a-f0-9]{32}\.json', path.name):
        raise ValueError('Backup path not owned')
    if path.stat().st_size > 65536:
        raise ValueError('Backup too large')
    data = json.loads(path.read_text(encoding='utf8'))
    if (not isinstance(data, dict) or data.get('schema') != 1 or data.get('tool') != TOOL or data.get('action') != 'chrome_webrtc'
            or data.get('target') != {'hive': 'HKCU', 'key': REG_KEY, 'name': REG_NAME}
            or data.get('applied') != {'exists': True, 'value': EXPECTED, 'type': 1}):
        raise ValueError('Backup identity invalid')
    previous = data.get('previous', {})
    if not isinstance(previous, dict) or set(previous) != {'exists', 'type', 'value'} or type(previous['exists']) is not bool:
        raise ValueError('Backup state invalid')
    kind, value = previous['type'], previous['value']
    if not previous['exists']:
        if kind is not None or value is not None:
            raise ValueError('Absent value invalid')
    elif type(kind) is not int:
        raise ValueError('Registry type invalid')
    elif kind in (1, 2):
        if not isinstance(value, str):
            raise ValueError('Registry text invalid')
    elif kind in (4, 5, 11):
        if type(value) is not int or not 0 <= value < 2 ** (64 if kind == 11 else 32):
            raise ValueError('Registry integer invalid')
    elif kind == 7:
        if not isinstance(value, list) or not all(isinstance(part, str) for part in value):
            raise ValueError('Registry list invalid')
    elif kind in (0, 3, 6, 8, 9, 10) and isinstance(value, dict) and set(value) == {'base64'}:
        previous['value'] = base64.b64decode(value['base64'], validate=True)
    else:
        raise ValueError('Unsupported registry backup')
    return previous


def rollback_backup(install_dir, filename):
    try:
        previous = _load_backup(install_dir, filename)
        current = _current()
        if current == previous:
            return {'exit_code': 0, 'message': '此值已处于备份状态，无需修改。'}
        if current != {'exists': True, 'value': EXPECTED, 'type': 1}:
            return {'exit_code': 3, 'message': '该值已有其他修改，拒绝覆盖；请先核对当前策略。'}
        _write_current(previous)
        if _current() != previous:
            raise OSError('Rollback readback mismatch')
        return {'exit_code': 0, 'message': '已恢复备份中的 HKCU 单个策略值；没有修改其他策略或启动、关闭 Chrome。'}
    except (OSError, ValueError, TypeError, KeyError):
        return {'exit_code': 3, 'message': '备份不属于本安装目录、格式无效或回滚未完成；未宣称恢复成功。'}


def main():
    parser = argparse.ArgumentParser(description='只对显式指定的本工具备份回滚 Chrome 单个 HKCU 值。')
    parser.add_argument('--install-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--rollback-backup', type=Path, required=True)
    args = parser.parse_args()
    result = rollback_backup(args.install_dir, args.rollback_backup)
    print(json.dumps(result, ensure_ascii=False))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
