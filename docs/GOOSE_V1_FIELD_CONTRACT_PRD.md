# GOOSE V1 字段契约说明

## 文档状态

本文档描述本仓库 `icsnpp-iec61850-goose`  fork 所实现的 **GOOSE V1 行为分析输入契约**。相关改造已在 Spicy 解析器、`goose.evt` 事件边界和 Zeek 日志脚本中落地，并以 btest 回归测试覆盖。

**主要代码位置：**

| 组件 | 文件 |
|------|------|
| Spicy 解析 | `analyzer/goose.spicy` |
| 事件桥接 | `analyzer/goose.evt` |
| 日志与事件处理 | `scripts/main.zeek` |
| 解析质量分类 | `scripts/parse-quality.zeek` |

## AI 阅读与修改约定

本文档的权威规则位置如下：

- `goose.log` 字段契约以第 2 节为准
- `parse_status` / `parse_error` 取值与分类规则以第 3 节为准
- 事件边界以第 4 节为准
- 第 7 节只描述测试覆盖，不重新定义字段或解析质量规则
- 第 8 节定义 V1 不做的事情；实现时不得把这些内容补进 V1

修改字段或解析质量规则时，优先按以下入口检查和更新：

1. `scripts/main.zeek`：`Info` 日志 record、事件 handler、字段格式化与日志写入
2. `scripts/parse-quality.zeek`：`parse_status` / `parse_error` 分类规则
3. `analyzer/goose.evt`：Spicy 到 Zeek 的事件参数
4. `analyzer/goose.spicy`：协议字段解析、`seen*` 标志、原始字节导出
5. `testing/tests/` 与 `testing/Baseline/`：btest 用例和期望日志

日常验证使用 CMake 构建/安装路径：`cmake --build build`、`cmake --install build`、`cd testing && make test`。

---

## 1. 背景与目标

### 1.1 背景

上游 DINA 版插件可解析并输出基础 `goose.log`，但字段命名（camelCase）、字段范围与日志语义不能直接满足项目 GOOSE V1 行为分析输入要求。

DINA 原版典型字段包括 `src`、`dst`、`gocbRef`、`timeAllowedtoLive`、`dataSet`、`t`、`stNum`、`sqNum` 等，缺少项目所需的 `eth_type`、`go_id`、`timestamp_quality`、`all_data_hash`、`all_data_raw_hex`、`parse_status`、`parse_error` 等稳定字段。

### 1.2 目标

在不依赖 SCD/CID/ICD、设备资产清单、信号点表或人工语义映射的前提下，基于镜像流量中实际解析到的 GOOSE 内容，输出稳定、可用于以下场景的 `goose.log`：

- 通信关系基线
- 窗口统计
- 发布源基线
- 后续序列 / 重放类行为分析

### 1.3 V1 原则

- **不采集** GOOSE `test` 字段
- **不要求** `reserved1` / `reserved2` 进入 V1 契约（可作为未来调试/取证增强）
- **AllData 不展开**：只做完整原始 TLV 摘要（hash），不做条目展开与业务语义映射

---

## 2. `goose.log` 字段契约

V1 固定输出以下列（顺序以 Zeek 日志头为准）：

```text
ts
src_mac
dst_mac
eth_type
appid
length
gocb_ref
time_allowed_to_live
dataset
go_id
timestamp
timestamp_quality
st_num
sq_num
simulation
conf_rev
nds_com
num_dat_set_entries
all_data_hash
all_data_raw_hex
parse_status
parse_error
```

### 2.1 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `ts` | time | 是 | Zeek 观测到报文的时间（`network_time()`） |
| `src_mac` | string | 否 | 以太网源 MAC；无 L2 信息时为 `-` |
| `dst_mac` | string | 否 | 以太网目的 MAC；无 L2 信息时为 `-` |
| `eth_type` | string | 是 | 固定为 `0x88b8` |
| `appid` | string | 是 | 应用 ID，格式为 `0x` 前缀十六进制小写 |
| `length` | int | 是 | GOOSE PDU 长度字段 |
| `gocb_ref` | string | 是 | GOOSE 控制块引用（原 `gocbRef`） |
| `time_allowed_to_live` | int | 是 | 报文存活时间（原 `timeAllowedtoLive`） |
| `dataset` | string | 是 | 数据集引用（原 `dataSet`） |
| `go_id` | string | 否 | 可选 GOOSE 标识；PDU 无 tag 3 时为 `-` |
| `timestamp` | time | 否 | GOOSE 内部 `T` 解析时间；无 tag 4 时为 `-` |
| `timestamp_quality` | string | 否 | `T` 最后一字节 timeQuality，格式 `0x` 前缀十六进制；无 tag 4 时为 `-` |
| `st_num` | int | 是 | 状态序号（原 `stNum`） |
| `sq_num` | int | 是 | 采样序号（原 `sqNum`） |
| `simulation` | bool | 是 | 仿真标志 |
| `conf_rev` | int | 是 | 配置版本（原 `confRev`） |
| `nds_com` | bool | 是 | 需 commissioning 标志（原 `ndsCom`） |
| `num_dat_set_entries` | int | 是 | 数据集条目数（原 `numDatSetEntries`） |
| `all_data_hash` | string | 是 | AllData 完整 TLV 的 SHA-256；无 AllData 时为空 |
| `all_data_raw_hex` | string | 是 | AllData 完整 TLV 十六进制；**默认空**，调试开启后填充 |
| `parse_status` | string | 是 | 解析质量：`ok` / `partial` / `failed` |
| `parse_error` | string | 是 | 稳定错误码，见 §3 |

### 2.2 时间字段区分

| 字段 | 来源 | 含义 |
|------|------|------|
| `ts` | Zeek | 分析器看到报文的时间 |
| `timestamp` | GOOSE PDU tag 4（UtcTime） | 设备侧数据集时间 |
| `timestamp_quality` | UtcTime 第 8 字节 | 时间品质字节 |

`timestamp` 由秒与 `fractionOfSecond` 共同派生：

```zeek
secondSinceEpoch + fractionOfSecond / 16777216.0
```

### 2.3 AllData 摘要规则

- **hash 范围**：AllData 的完整 BER TLV，包含 **tag、length、value**
- **实现**：Spicy 侧捕获 `element.raw_tlv_prefix + element.application_data`，转十六进制后经 Zeek 计算 SHA-256
- **`all_data_raw_hex`**：固定列，默认空字符串；设置 `redef goose::log_all_data_raw_hex=T` 后填充

```bash
zeek -r GOOSE.pcap icsnpp-iec61850-goose -e 'redef goose::log_all_data_raw_hex=T;'
```

### 2.4 发布者标识键

下游模块可使用 **`src_mac + appid + gocb_ref`** 作为 GOOSE 发布者键，仅依赖被动流量字段。

---

## 3. 解析质量（`parse_status` / `parse_error`）

### 3.1 三态定义

| `parse_status` | 含义 |
|----------------|------|
| `ok` | 必需字段齐全，且 AllData TLV 可用于 hash |
| `partial` | 已识别为 GOOSE，但缺少非致命重要字段或存在可恢复告警 |
| `failed` | 缺少关键字段，或 Spicy 层解析失败 |

### 3.2 错误码

| `parse_error` | 含义 | 典型场景 |
|---------------|------|----------|
| `none` | 无错误 | `parse_status=ok` |
| `missing_required_field` | 缺少必需字段 | 无 `gocb_ref`、无 MAC、缺 `dataset` 等 |
| `missing_all_data` | 缺少 AllData | 无 tag 11 |
| `truncated_packet` | 报文截断 | payload 字节不足 |
| `malformed_asn1` | ASN.1 结构无法解析 | 损坏的 BER 编码 |
| `unsupported_tlv` | 不支持的 context tag | Spicy 遇到未实现 tag |

### 3.3 分类规则（`scripts/parse-quality.zeek`）

解析质量分两条路径产生：

| 路径 | 触发事件 | 分类函数 | 说明 |
|------|----------|----------|------|
| A. 解析完成 | `goose::goose_packet` | `classify_parse_quality()` | Spicy 跑完 `Message` unit，按 `seen*` 标志判定 |
| B. 解析失败 | `goose::goose_packet_error` | `normalize_parse_error()` | Spicy 触发 `%error`，直接记为 `failed` |

路径 A 的输入在 `main.zeek` 的 `goose::goose_packet` handler 中组装：

| 输入字段 | 含义 | 来源 |
|----------|------|------|
| `has_src_mac` | 是否有源 MAC | `pkt?$l2 && pkt$l2?$src` |
| `has_dst_mac` | 是否有目的 MAC | `pkt?$l2 && pkt$l2?$dst` |
| `has_appid` | 是否有 appid | 固定为 `T`（固定头已解析） |
| `seen_gocb_ref` | PDU 是否出现 tag 0 | Spicy `seenGocbRef` |
| `seen_st_num` | PDU 是否出现 tag 5 | Spicy `seenStNum` |
| `seen_sq_num` | PDU 是否出现 tag 6 | Spicy `seenSqNum` |
| `seen_dataset` | PDU 是否出现 tag 2 | Spicy `seenDataSet` |
| `seen_conf_rev` | PDU 是否出现 tag 8 | Spicy `seenConfRev` |
| `seen_num_dat_set_entries` | PDU 是否出现 tag 10 | Spicy `seenNumDatSetEntries` |
| `seen_all_data` | PDU 是否出现 tag 11 | Spicy `seenAllData` |
| `parser_warning` | Spicy 解析完成后的可恢复告警 | Spicy `parserWarning`，初始 `"none"`；遇未知 tag 时为 `"unsupported_tlv"` |

`seen*` 表示 ASN.1 SEQUENCE 里是否实际出现过对应 context tag，不按字段值是否为空判断。

`classify_parse_quality()` 按下表顺序检查，命中即返回：

| 顺序 | 条件 | 结果 |
|------|------|------|
| **L1 硬必需** | `src_mac`、`dst_mac`、`appid`、`gocb_ref`、`st_num`、`sq_num` | `failed` + `missing_required_field` |
| **L2 AllData** | 缺少 tag 11（`seen_all_data=F`） | `partial` + `missing_all_data` |
| **L3 解析告警** | `parser_warning != "none"` | `partial` + 对应告警码，并写入日志 `parse_error` |
| **L4 软必需** | `dataset`、`conf_rev`、`num_dat_set_entries` | `partial` + `missing_required_field` |
| **全部通过** | 以上条件均不命中 | `ok` + `none` |
| **不参与降级** | `go_id`、`timestamp`、`timestamp_quality`、`simulation`、`nds_com`、`time_allowed_to_live` | 单独缺失不改变 `parse_status` |

路径 B 不调用 `classify_parse_quality()`，固定输出：

```text
parse_status = failed
parse_error  = normalize_parse_error(Spicy 原始 msg)
```

`normalize_parse_error()` 规则：

| Spicy `msg` 匹配模式 | 归一化结果 |
|---------------------|------------|
| 含 `truncat`、`unexpected end`、`end of data`、`not enough data`、`short read`、`eof`、`EOD`、`expected … bytes … available` | `truncated_packet` |
| 其他 | `malformed_asn1` |

此时日志中 GOOSE 语义字段多为空/零值，仅保留 `appid`、`length`、MAC（若有）与时间戳。

---

## 4. 事件边界

`.evt` 定义两条 Zeek 事件，对应 Spicy 解析的两种结局：

```text
Message unit 解析完成
    → goose::goose_packet        → 写完整 goose.log（含 parse 质量分类）

Message unit 解析失败（%error）
    → goose::goose_packet_error  → 写失败记录（parse_status=failed）
```

| 事件 | 触发条件 | 主要参数 |
|------|----------|----------|
| `goose::goose_packet` | Spicy 成功跑完 `Message` unit | 全部解析字段 + `seen*` 标志 + `parserWarning` |
| `goose::goose_packet_error` | Spicy 触发 `%error`（截断、ASN.1 失败等） | `appid`、`length`、原始错误 `msg` |

错误路径中 `parse_error` 经 `normalize_parse_error()` 归一化为 `truncated_packet` 或 `malformed_asn1`。

---

## 5. 与 DINA 原版的命名对照

| DINA / Spicy | V1 `goose.log` |
|--------------|----------------|
| `src` | `src_mac` |
| `dst` | `dst_mac` |
| `gocbRef` | `gocb_ref` |
| `timeAllowedtoLive` | `time_allowed_to_live` |
| `dataSet` | `dataset` |
| `t` | `timestamp` |
| `stNum` | `st_num` |
| `sqNum` | `sq_num` |
| `confRev` | `conf_rev` |
| `ndsCom` | `nds_com` |
| `numDatSetEntries` | `num_dat_set_entries` |
| `appid`（int） | `appid`（`0x` 十六进制 string） |
| — | `eth_type`、`timestamp_quality`、`all_data_hash`、`all_data_raw_hex`、`parse_status`、`parse_error` |

---

## 6. 实现要点

- 在现有 Spicy 解析器、`goose.evt`、`main.zeek` 上最小增量改造
- 字段命名统一 **snake_case**
- 能在 Zeek 层完成的改名/格式化（如 `appid`、`eth_type`）不改动 Spicy
- Spicy 层新增/扩展：
  - `SecondSinceEpoch`、`FractionOfSecond`、`TimeQuality` 传递
  - AllData 完整 TLV 捕获与十六进制导出
  - `seen*` 标志与 `parserWarning`
- 解析错误从 `print` 改为结构化 `parse_status` / `parse_error`
- Suricata 仍负责规则签名与部分 malformed 检测；本解析器记录解析质量与行为事实，**不消费** Suricata 告警

---

## 7. 测试覆盖

本节只列出第 2、3、4 节契约的验证方式，不作为字段或解析质量规则的权威定义。

在 btest 层通过 PCAP 回放断言 `goose.log` 契约：

| 测试 | 文件 | 验证点 |
|------|------|--------|
| 正常 GOOSE | `test-GOOSE.zeek` | 日志字段与 Baseline 一致 |
| 解析质量 ok | `test-GOOSE-parse-quality.zeek` | `parse_status=ok`，`parse_error=none` |
| 缺 gocbRef | `test-GOOSE-missing-gocb-ref.zeek` | `failed` + `missing_required_field` |
| 缺 AllData | `test-GOOSE-missing-all-data.zeek` | `partial` + `missing_all_data` |
| 截断报文 | `test-GOOSE-truncated.zeek` | 不崩溃；`failed` + `truncated_packet` |
| AllData 原始 hex | `test-GOOSE-raw-hex.zeek` | `log_all_data_raw_hex=T` 时填充 hex |
| AllData 原语回退 | `test-GOOSE-all-data-primitives-fallbacks.zeek` | hash 稳定性 |
| 分析器注册 | `test-show-plugin.zeek` | `ANALYZER_SPICY_GOOSE` 存在 |

测试原则：

- 在日志边界断言，不断言 Spicy 内部实现细节（除非影响外部可见行为）
- 正常样本断言 `all_data_hash` 稳定
- 默认配置断言 `all_data_raw_hex` 为空
- 断言 `ts` 与 `timestamp` 为不同时间源

---

## 8. 不在 V1 范围内

- SCD/CID/ICD 导入与一致性校验
- 从配置文件推导 GOOSE 发布/订阅关系
- 设备资产清单或信号点表依赖
- AllData 条目展开、递归解码、业务语义映射（Trip、Lockout、断路器位置等）
- GOOSE VLAN ID / 802.1Q priority 日志与异常检测
- RCB/BRCB/URCB 报告控制块检测
- GOOSE `test` 字段
- V1 必需字段中的 `reserved1` / `reserved2`
- 解析器直接产生行为告警（告警由通信关系/窗口/基线模块产生）
- Zeek 行为分析引擎消费 Suricata 告警
- 本解析器不输出 `src_mac_seen`、`goose_publisher_seen`；二者由下游通信关系/基线模块补充

---

## 9. 后续可选增强

- `reserved1` / `reserved2` 作为调试/取证字段
- AllData 条目级解析与业务语义映射（V2+）
- VLAN ID / priority 日志
