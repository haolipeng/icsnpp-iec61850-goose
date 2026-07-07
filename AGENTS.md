# AGENTS.md

## 开发验证

在日常开发、TDD 和调试阶段，优先使用直接的 CMake 构建/安装流程：

```bash
cmake --build build
cmake --install build
cd testing
make test
```

修改 `.spicy`、`.evt` 或 Zeek 脚本后，优先使用这条路径。它会重新构建本地 analyzer 产物，并安装到测试实际加载的 Zeek 路径中。这样反馈更快，也能避免 zkg 的 clone/cache 层造成“到底加载了哪个版本”的排查成本。

当 CMake 测试流程已经通过后，再使用 `zkg install .` 做打包或交付前验证：

```bash
zkg remove icsnpp-iec61850-goose
zkg install .
zeek -Cr testing/Traces/GOOSE.pcap icsnpp-iec61850-goose
```

注意：`zkg install .` 会拒绝 dirty git worktree。工作区存在未提交改动时，不要为了验证 zkg 路径而强行清理或回滚用户改动；除非用户明确要求，否则先继续使用 CMake build/install 路径验证。

简要规则：日常 TDD 和调试使用 CMake build/install；交付、发布或验证可安装包路径时再使用 zkg。

## GOOSE / ASN.1 原始字节处理

处理协议原始字节时，不要通过字符串编码/解码路径构造或传递二进制内容。Spicy 中需要生成单个协议字节时，优先使用：

```spicy
pack(cast<uint8>(value), spicy::ByteOrder::Big)
```

ASN.1 / BER tag 不要因为测试 pcap 中出现了某个字节就直接硬编码为魔法值。应按 BER identifier octet 规则由 class、constructed bit 和 tag number 组合生成，或在代码注释中明确该字节来自协议规则。
