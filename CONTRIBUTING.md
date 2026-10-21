# 参与贡献

后续功能在 [CC-Guard](https://github.com/1-1-1-11/CC-Guard)。这个仓库只保留前身快照。

这里接受的改动：文档、许可和归属、已提交敏感信息的清理、以及让现有离线测试继续能跑的小修复。请不要往这里加新功能。

## 提交说明

- 写清问题、改动和你跑过的检查。
- 不要附带订阅链接、节点密码、令牌、私钥、`audit_policy.json`、`repair-baseline.dpapi`，或带真实用户名的本机路径。
- 预期出口只用文档地址（`203.0.113.0/24`、`192.0.2.0/24`、`198.51.100.0/24`）或 `audit_policy.example.json`。
- 改到 `ccbaga-proxy/` 时保留它自己的 [LICENSE](ccbaga-proxy/LICENSE) 和 [NOTICE.md](ccbaga-proxy/NOTICE.md)。

## 合并前在本地跑

需要 Python 3.11 或更新版本、PATH 上的 `node`，以及 `psutil`、`PyYAML`（版本见 `proxy-v2/requirements.txt`）。

```bash
python -m pip install -r proxy-v2/requirements.txt
python scripts/check_public_tree.py
python -m compileall -q proxy-v2 v1 ccbaga-proxy/proxy-bridge ccbaga-proxy/scripts ccbaga-proxy/skills scripts
cp proxy-v2/claude-network/audit_policy.example.json proxy-v2/claude-network/audit_policy.json
cp v1/claude-network/audit_policy.example.json v1/claude-network/audit_policy.json
python -m unittest discover -s proxy-v2/claude-network -p 'test_*.py'
python -m unittest discover -s v1/claude-network -p 'test_*.py'
python -m unittest discover -s ccbaga-proxy/proxy-bridge -p 'test_*.py'
python ccbaga-proxy/skills/ccbaga-network/scripts/test_network.py
```

`audit_policy.json` 已被忽略，不要提交。桌面程序的 Bun 和 Cargo 检查写在 `ccbaga-proxy/README.md`，本仓库的 CI 不跑它们。

报告问题时请写操作系统、你执行的命令、期望和实际结果。敏感细节不要开公开 Issue，按 [SECURITY.md](SECURITY.md) 私下联系。
