# GOOSE V1 字段契约与 DINA Fork 改造 PRD

## Problem Statement

当前 `icsnpp-iec61850-goose` 可以解析并输出基础 `goose.log`，但其字段命名、字段范围和日志语义不能直接满足项目 GOOSE V1 行为分析输入契约。

项目需要在不依赖 SCD/CID/ICD、设备资产清单、信号点表或人工语义映射的前提下，基于镜像流量中实际解析到的 GOOSE 内容，输出稳定、可用于通信关系基线、窗口统计、发布源基线和后续序列/重放类行为分析的 `goose.log`。

现有 DINA 输出的字段包括 `src`、`dst`、`gocbRef`、`timeAllowedtoLive`、`dataSet`、`t`、`stNum`、`sqNum`、`simulation`、`confRev`、`ndsCom`、`numDatSetEntries` 等。它们多数能映射到项目字段，但仍缺少 `eth_type`、`go_id`、`timestamp_quality`、`all_data_hash`、`all_data_raw_hex`、`parse_status`、`parse_error` 等项目需要的稳定字段。

同时，项目已明确 GOOSE V1 不采集 `test`，不把 `reserved1` / `reserved2` 作为必需字段，AllData 只做完整原始 TLV 摘要，不展开条目、不做业务语义映射。

## Solution

Fork `icsnpp-iec61850-goose` 并在现有 Spicy analyzer、evt 事件边界和 Zeek 日志脚本基础上做最小二次开发，输出满足项目 GOOSE V1 契约的 `goose.log`。

V1 `goose.log` 字段契约为：

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
src_mac_seen
goose_publisher_seen
```

其中 `src_mac_seen` 和 `goose_publisher_seen` 不是协议解析字段，而是通信关系/基线比对模块补充的事实字段；如果本 fork 只负责协议解析事件，可不在解析事件中直接生成这两个字段。

`timestamp` 表示 GOOSE 报文内部 `T` 字段解析后的时间，类型为 Zeek `time`，由 `T` 的 seconds 和 fractionOfSecond 派生。`ts` 表示 Zeek 观测到报文的时间。`timestamp_quality` 表示 GOOSE `T` 字段最后 1 字节 timeQuality，使用 `0x` 前缀十六进制字符串。

`all_data_hash` 为 `SHA-256(AllData 完整原始 TLV 字节)`，hash 范围包含 AllData 的 tag、length 和 value。`all_data_raw_hex` 是固定日志字段，默认填空，仅在调试或取证配置开启时填充 AllData 完整原始 TLV 十六进制。

`parse_status` 使用三态：`ok`、`partial`、`failed`。`parse_error` 使用少量稳定错误码：`none`、`missing_required_field`、`missing_all_data`、`truncated_packet`、`malformed_asn1`、`unsupported_tlv`。

## User Stories

1. As a behavior-analysis engineer, I want GOOSE logs to use project field names, so that downstream baselines and detections do not depend on DINA-specific camelCase names.
2. As a behavior-analysis engineer, I want `src` and `dst` normalized to `src_mac` and `dst_mac`, so that GOOSE MAC fields are not confused with MMS IP fields.
3. As a behavior-analysis engineer, I want `gocbRef` normalized to `gocb_ref`, so that publisher keys use project naming consistently.
4. As a behavior-analysis engineer, I want `timeAllowedtoLive` normalized to `time_allowed_to_live`, so that TTL-related behavior analysis can use stable field names.
5. As a behavior-analysis engineer, I want `dataSet` normalized to `dataset`, so that dataset baselines can be queried consistently.
6. As a behavior-analysis engineer, I want `stNum` and `sqNum` normalized to `st_num` and `sq_num`, so that sequence analysis can consume stable fields.
7. As a behavior-analysis engineer, I want `confRev` normalized to `conf_rev`, so that configuration-version behavior can be analyzed later.
8. As a behavior-analysis engineer, I want `ndsCom` normalized to `nds_com`, so that commissioning state can be logged consistently.
9. As a behavior-analysis engineer, I want `numDatSetEntries` normalized to `num_dat_set_entries`, so that AllData size baselines can use a stable field.
10. As a behavior-analysis engineer, I want `appid` formatted as a `0x`-prefixed hex string, so that publisher keys match the project contract.
11. As a behavior-analysis engineer, I want `eth_type` recorded as `0x88b8`, so that the GOOSE EtherType is explicit in project logs.
12. As a behavior-analysis engineer, I want `go_id` logged when present, so that optional GOOSE identifier information is available without being required.
13. As a behavior-analysis engineer, I want `timestamp` to represent the GOOSE internal `T` time, so that later analysis can compare device time against Zeek observation time.
14. As a behavior-analysis engineer, I want `timestamp_quality` logged, so that behavior analysis can judge whether GOOSE internal time is trustworthy.
15. As a behavior-analysis engineer, I want `timestamp` to include fractionOfSecond when available, so that sub-second GOOSE timing behavior is not silently lost.
16. As a behavior-analysis engineer, I want `ts` and `timestamp` documented as different time sources, so that alert explanations do not confuse analyzer time and device time.
17. As a behavior-analysis engineer, I want `simulation` retained, so that future simulation-state behavior can be analyzed.
18. As a behavior-analysis engineer, I want `nds_com` retained, so that future commissioning-state behavior can be analyzed.
19. As a behavior-analysis engineer, I do not want GOOSE V1 to require `test`, so that implementation stays aligned with fields actually present in the current GOOSE parser.
20. As a behavior-analysis engineer, I do not want `reserved1` and `reserved2` in the V1 required contract, so that behavior-analysis logs stay focused on useful first-phase facts.
21. As a protocol engineer, I want `reserved1` and `reserved2` documented as optional debug/forensic enhancement fields, so that future protocol-forensics work can add them without redefining V1.
22. As a behavior-analysis engineer, I want `all_data_hash` computed from the complete AllData TLV, so that content stability checks are not affected by partial decoding choices.
23. As a behavior-analysis engineer, I want AllData hash scope to include tag, length, and value, so that structural changes are reflected in the hash.
24. As a behavior-analysis engineer, I want `all_data_raw_hex` available behind a debug/forensic switch, so that investigations can inspect raw AllData without bloating default logs.
25. As a behavior-analysis engineer, I want AllData entries not to be expanded in V1, so that the first release avoids premature business semantics.
26. As a behavior-analysis engineer, I want `parse_status=ok` when required fields and AllData hash are available, so that downstream modules can safely use the event.
27. As a behavior-analysis engineer, I want `parse_status=partial` when GOOSE is recognized but non-critical important fields are missing, so that quality issues are visible without dropping all facts.
28. As a behavior-analysis engineer, I want `parse_status=failed` when required fields are unavailable, so that publisher baselines do not consume invalid events.
29. As a behavior-analysis engineer, I want `parse_error=none` on successful parsing, so that query logic can filter parse errors simply.
30. As a behavior-analysis engineer, I want stable parse error codes for truncation, ASN.1 malformation, missing AllData, missing required fields, and unsupported TLVs, so that window statistics and alert explanations are consistent.
31. As a communications-baseline engineer, I want `src_mac + appid + gocb_ref` to remain the GOOSE publisher key, so that publisher identity is based only on passive traffic fields.
32. As a communications-baseline engineer, I want `src_mac_seen` and `goose_publisher_seen` generated outside the parser, so that protocol parsing remains separate from baseline comparison.
33. As a Zeek maintainer, I want the fork to reuse the existing Spicy analyzer where possible, so that implementation risk stays low.
34. As a Zeek maintainer, I want fields already present in the DINA event to be renamed in Zeek script where possible, so that Spicy changes are limited to fields that truly need parser support.
35. As a Zeek maintainer, I want `timestamp_quality` passed through the Spicy-to-Zeek event boundary, so that the Zeek log can include it.
36. As a Zeek maintainer, I want AllData complete TLV bytes exposed to hashing logic, so that Zeek can produce the required hash deterministically.
37. As a Zeek maintainer, I want parser errors converted from prints into structured status/error fields, so that malformed traffic does not only appear in stdout.
38. As a test author, I want normal GOOSE PCAP replay to produce the project `goose.log`, so that field contracts are tested at the log boundary.
39. As a test author, I want truncated GOOSE samples to avoid Zeek crashes, so that parser robustness is covered.
40. As a test author, I want btests to assert key log fields exist, so that regressions in event/log wiring are caught.
41. As a SOC analyst, I want GOOSE log fields to be stable and explicit, so that alert triage can explain current observations against historical baselines.
42. As a SOC analyst, I want AllData represented as a digest by default, so that logs remain compact while still supporting state-fingerprint analysis.
43. As a SOC analyst, I want optional raw AllData output for investigations, so that deep packet-level review remains possible when needed.
44. As a product owner, I want GOOSE V1 to avoid SCD/CID dependencies, so that deployment works when customers do not provide configuration files.
45. As a product owner, I want business semantic mapping of Trip/Lockout/breaker position left out of V1, so that V1 can ship with passive traffic facts only.

## Implementation Decisions

- Fork the existing GOOSE analyzer and implement the project contract with minimal changes to the existing Spicy parser, evt bridge, and Zeek logging script.
- Keep project log field names in snake_case.
- Normalize DINA `src` / `dst` to `src_mac` / `dst_mac`.
- Normalize DINA GOOSE ASN.1 field names to project names: `gocb_ref`, `time_allowed_to_live`, `dataset`, `st_num`, `sq_num`, `conf_rev`, `nds_com`, `num_dat_set_entries`.
- Convert `appid` from integer to `0x`-prefixed hexadecimal string at the Zeek script layer.
- Populate `eth_type` as `0x88b8` for events emitted by this analyzer.
- Add `go_id` as an optional field; missing `go_id` does not degrade `parse_status`.
- Replace the earlier raw-hex timestamp idea with `timestamp` as parsed Zeek `time` from GOOSE `T`, plus `timestamp_quality` as the `T` field quality byte.
- Ensure `timestamp` is derived from both seconds and fractionOfSecond, not only seconds, when the parser has the data.
- Add `timestamp_quality` by passing the final byte of GOOSE `T` through the parser event boundary and formatting it as `0x` hex.
- Keep `ts` as Zeek observation time and document it separately from `timestamp`.
- Do not include `test` in GOOSE V1.
- Do not include `reserved1` or `reserved2` in the required V1 `goose.log` contract; document them as optional debug/forensic enhancements.
- Keep `simulation` and `nds_com` as boolean fields.
- Compute `all_data_hash` from the complete AllData TLV bytes, including tag, length, and value.
- Keep `all_data_raw_hex` as a fixed field that defaults empty and is populated only when debug/forensic output is enabled.
- Do not expand AllData entries, recursively decode arrays/structures, or map AllData to business semantics in V1.
- Use `parse_status` values `ok`, `partial`, and `failed`.
- Use `parse_error` values `none`, `missing_required_field`, `missing_all_data`, `truncated_packet`, `malformed_asn1`, and `unsupported_tlv`.
- Keep baseline fields `src_mac_seen` and `goose_publisher_seen` outside protocol parsing; they are added by the communication relationship/baseline module.
- Keep Suricata responsible for rule signatures and protocol malformed/encoding detections; Zeek GOOSE parser records parse quality and behavior facts without consuming Suricata alerts.

## Testing Decisions

- Test at the highest useful seam: replay representative PCAPs through Zeek and assert the generated `goose.log` contract.
- Existing btest-style replay tests should be extended rather than adding a separate bespoke test runner.
- Normal GOOSE samples should assert that `goose.log` is generated and includes at least `src_mac`, `dst_mac`, `appid`, `gocb_ref`, `st_num`, `sq_num`, `parse_status`, `timestamp`, and `timestamp_quality`.
- AllData-capable samples should assert that `all_data_hash` is present and stable for unchanged complete AllData TLV bytes.
- Debug/forensic configuration tests should assert that `all_data_raw_hex` is empty by default and populated when enabled.
- Truncated or malformed samples should assert that Zeek does not crash and that `parse_status` is `partial` or `failed` with a stable `parse_error`.
- Field formatting tests should assert `appid` and `eth_type` use `0x`-prefixed lowercase hexadecimal strings.
- Time-field tests should assert `ts` and `timestamp` are distinct concepts: `ts` comes from observation time, while `timestamp` comes from GOOSE `T`.
- Time-quality tests should assert `timestamp_quality` is emitted as `0x` hex from the final byte of GOOSE `T`.
- Publisher-key tests should assert `src_mac + appid + gocb_ref` can be constructed when `parse_status` is not `failed`.
- Tests should assert missing `go_id`, `timestamp`, `timestamp_quality`, `simulation`, `nds_com`, or `time_allowed_to_live` does not degrade parse status by itself.
- Tests should assert missing `dataset`, `conf_rev`, `num_dat_set_entries`, or `all_data_hash` degrades to `partial`.
- Tests should assert missing `src_mac`, `dst_mac`, `appid`, `gocb_ref`, `st_num`, or `sq_num` degrades to `failed`.
- Tests should avoid asserting internal Spicy implementation details except where necessary to validate externally visible log behavior.

## Out of Scope

- No SCD/CID/ICD import.
- No SCD/CID consistency validation.
- No derivation of GOOSE publish/subscribe relationships from configuration files.
- No device asset inventory or signal-point table dependency.
- No Trip, Lockout, breaker-position, protection-start, or other business semantic mapping from AllData.
- No expansion of AllData entries into per-item fields in V1.
- No recursive parsing of AllData arrays or structures in V1.
- No GOOSE VLAN ID or 802.1Q priority logging in the project V1 contract.
- No VLAN ID or priority anomaly detection.
- No RCB/BRCB/URCB report-control-block detection.
- No GOOSE `test` field in V1.
- No required `reserved1` / `reserved2` fields in V1.
- No GOOSE behavior alerts directly from the parser; behavior alerts are produced by the communication relationship/window/baseline modules.
- No consumption of Suricata alerts by the Zeek behavior analysis engine.

## Further Notes

- This PRD is ready for agent implementation and should be treated as `ready-for-agent`.
- The current DINA parser already parses many required protocol facts; most naming differences can be handled in Zeek script.
- `timestamp_quality`, complete AllData TLV capture, and structured parse errors are the main parser-layer changes.
- The fork should keep the implementation as close as possible to the upstream analyzer to minimize maintenance risk.
