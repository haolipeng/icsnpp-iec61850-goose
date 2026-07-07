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

简要规则：日常 TDD 和调试使用 CMake build/install；交付、发布或验证可安装包路径时再使用 zkg。
