# 第三方声明

根目录 [LICENSE](LICENSE) 覆盖本仓库里 Proxy v1、Proxy v2、整合说明和这些维护文件。它不取代下面各组件自己的版权声明和许可。

## CCBaga

`ccbaga-proxy/` 是 [liseami/CCBaga](https://github.com/liseami/CCBaga) 的修改快照（整合分支 `codex/proxy-integration`，树 `8d2d4bd`），不包含上游提交历史。

```text
Copyright (c) 2026 CCBaga contributors
```

许可是 MIT。全文在 [ccbaga-proxy/LICENSE](ccbaga-proxy/LICENSE)。独立 Skill 的同一份 MIT 在 [ccbaga-proxy/skills/ccbaga-network/LICENSE](ccbaga-proxy/skills/ccbaga-network/LICENSE)。

本仓库作者对这份快照的修改也按根目录 MIT 提供，但修改不取消 CCBaga 的版权声明。再分发 `ccbaga-proxy/` 时请同时保留那份 LICENSE。

引擎、图标、字体数据和界面库的进一步边界写在 [ccbaga-proxy/NOTICE.md](ccbaga-proxy/NOTICE.md)。下面是本仓库需要单独点名的部分。

## 已随树保留的许可

| 组件 | 许可 | 位置 |
| --- | --- | --- |
| Fingerprint Chromium / ungoogled-chromium 声明 | BSD-3-Clause，Copyright (c) 2015-2023, The ungoogled-chromium Authors | [ccbaga-proxy/browser-runtime/LICENSE.fingerprint-chromium](ccbaga-proxy/browser-runtime/LICENSE.fingerprint-chromium) |
| LobeHub lobe-icons，提交 `c385b2b8d1f9e19aa86e628d4e23c91ee1111a47` 的五枚 SVG | MIT，Copyright (c) 2023 LobeHub | [ccbaga-proxy/assets/ai-icons/LICENSE.lobehub.txt](ccbaga-proxy/assets/ai-icons/LICENSE.lobehub.txt) |
| Unicode CLDR 48 的 Windows 时区映射 | Unicode License | [ccbaga-proxy/src-tauri/windows/LICENSE.unicode.txt](ccbaga-proxy/src-tauri/windows/LICENSE.unicode.txt) |
| `jsonc-parser`（Microsoft） | MIT，Copyright (c) Microsoft | [proxy-v2/claude-network/vendor/jsonc-parser/LICENSE.md](proxy-v2/claude-network/vendor/jsonc-parser/LICENSE.md) 与 [v1/claude-network/vendor/jsonc-parser/LICENSE.md](v1/claude-network/vendor/jsonc-parser/LICENSE.md) |

Tauri、React、Radix UI、Motion、Tailwind CSS、Vite 和 Rust 依赖各自保留上游许可。版本见 `ccbaga-proxy/bun.lock` 和 `ccbaga-proxy/src-tauri/Cargo.lock`。

## 许可没有在本仓库里确认

这些内容不能因为根目录或 CCBaga 的 MIT 声明就被当成 MIT。再分发二进制或摘出这些文件之前，需要补上上游许可，或者删掉。

- **`ccbaga-proxy/vendor/cromma-ui`**：本地复制的界面库，树里没有独立的上游 LICENSE。NOTICE 已写明不能用本项目的 MIT 代替它的许可。
- **清理员和浏览器插画**（`ccbaga-proxy/assets/cleaner-logo.jpg`、`browser-logo.jpg`）：NOTICE 只说作品是供这个项目使用的，没有单独的许可文本。
- **claude-cleanup skill**：只在文档里引用了 [suyuan2022/suyuan-skill](https://github.com/suyuan2022/suyuan-skill/tree/main/claude-cleanup)，代码没有放进本仓库，许可也没有一起带来。
- **Chromium 浏览器本体**：源码树里没有引擎二进制。Fingerprint Chromium 的一份 BSD 声明不能代替 Chromium 及其依赖的完整归属。NOTICE 要求打二进制包时保留引擎自己的归属材料。
- **`ccbaga-proxy/skills/ccbaga-network/providers.json` 里的供应商推广参数**：随 CCBaga 副本而来，离线测试锁了完整地址。这不是本仓库的订阅链接。请确认它们属于上游公开项目，而不是本仓库所有者自己的推广号。

Anthropic、Claude、Apple、Chromium 以及其他商标仍归各自所有者。提到它们不表示获得了背书。
