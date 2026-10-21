#!/usr/bin/env python3
"""Reject workstation identifiers and unexpected public IPs in the current tree.

The patterns are structural. This file does not store the values removed from history.
"""
from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'dist', 'target'}
SKIP_NAMES = {'bun.lock', 'Cargo.lock'}
SKIP_SUFFIXES = {
    '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.icns', '.zip',
    '.woff', '.woff2', '.ttf', '.otf', '.pdf', '.lock',
}
ALLOWED_NETS = [
    ipaddress.ip_network('0.0.0.0/32'),
    ipaddress.ip_network('0.0.1.0/32'),  # Windows OpenSSH capability version in an upstream workflow
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('126.255.255.255/32'),  # firewall range bound in the guard script
    ipaddress.ip_network('128.0.0.0/32'),
    ipaddress.ip_network('255.255.255.255/32'),
    ipaddress.ip_network('1.1.1.1/32'),
    ipaddress.ip_network('1.0.0.1/32'),
    ipaddress.ip_network('8.8.8.8/32'),
    ipaddress.ip_network('8.8.4.4/32'),
    ipaddress.ip_network('223.5.5.5/32'),
    ipaddress.ip_network('223.6.6.6/32'),
]
GITHUB_OWNERS = {
    '1-1-1-11', 'liseami', 'lobehub', 'unicode-org', 'adryfish', 'suyuan2022',
    'vercel-labs', 'actions', 'oven-sh', 'swatinem', 'microsoft', 'tauri-apps',
    'xtls',
}
WINDOWS_USERS = {'example', 'u', 'test', 'default', 'you', 'fixture', 'a', 'ab'}
EMAIL_DOMAINS = {'example.invalid', 'example.com', 'example.org', 'example.net'}
IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
USER_PATH = re.compile(r'Users[/\\]+([A-Za-z0-9_.-]+)')
GITHUB = re.compile(r'(?<![\w.])github\.com/([A-Za-z0-9][A-Za-z0-9_.-]*)')
DRIVE_D = re.compile(r'(?<![A-Za-z0-9])D:[/\\]')
EMAIL = re.compile(r'(?<![:/\w])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
NUMERIC_MUTEX = re.compile(r'Local\\+[A-Za-z]+-(\d{4,})')
DOCUMENTS_TREE = re.compile(r'Documents[/\\]+ChatGPT')
OLD_NODE = re.compile(
    r'(?<!Example-)(?:' + '|'.join(('JP-' + 'HY2', 'KR-' + 'HY2', 'USLA' + '2')) + ')'
)


def allowed_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True
    return any(address in network for network in ALLOWED_NETS)


def scan(path: Path, text: str) -> list[str]:
    findings = []
    rel = path.relative_to(ROOT).as_posix()

    def add(line: int, message: str) -> None:
        findings.append(f'{rel}:{line}: {message}')

    for match in IPV4.finditer(text):
        line_start = text.rfind('\n', 0, match.start()) + 1
        line_end = text.find('\n', match.start())
        line = text[line_start:len(text) if line_end < 0 else line_end]
        if any(token in line for token in ('<path', 'stroke=', 'd="')):
            continue
        if not allowed_ip(match.group(0)):
            add(text.count('\n', 0, match.start()) + 1, f'unexpected public IP {match.group(0)}')
    for pattern, message in (
        (DRIVE_D, 'workstation D: path'),
        (DOCUMENTS_TREE, 'personal Documents tree'),
        (NUMERIC_MUTEX, 'numeric mutex suffix'),
        (OLD_NODE, 'subscription node name without the Example- prefix'),
    ):
        for match in pattern.finditer(text):
            add(text.count('\n', 0, match.start()) + 1, message)
    for match in USER_PATH.finditer(text):
        if match.group(1).lower() not in WINDOWS_USERS:
            add(text.count('\n', 0, match.start()) + 1, f'Windows user {match.group(1)}')
    for match in GITHUB.finditer(text):
        owner = match.group(1)
        if owner.lower() not in GITHUB_OWNERS:
            add(text.count('\n', 0, match.start()) + 1, f'unexpected GitHub owner {owner}')
    for match in EMAIL.finditer(text):
        if match.group(1).lower() not in EMAIL_DOMAINS:
            add(text.count('\n', 0, match.start()) + 1, f'email at {match.group(1)}')
    return findings


def main() -> int:
    findings = []
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_NAMES or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        data = path.read_bytes()
        if b'\0' in data[:8192]:
            continue
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            continue
        findings.extend(scan(path, text))
    if findings:
        print('\n'.join(findings))
        return 1
    print('public tree check passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
