---
name: burp-http-history
description: 读取、同步、分析 Burp Suite Proxy HTTP History 的完整请求响应记录(经 burp-history-file-bridge 的 HTTP API,零截断)。不用于 Repeater 操作。
---

# Burp HTTP History(经 history-file-bridge)

数据链:Burp(已装 burp-history-file-bridge 扩展)→ HTTP API **http://192.168.144.1:8765**(WSL 可直连)→ `http-history.jsonl`(Windows 侧 `C:\Users\13272\.burp-history-file-bridge\<项目名>\`,WSL 视角 `/mnt/c/Users/13272/.burp-history-file-bridge/`)。

## 数据纪律(不可谈判)

- **完整请求与响应,零脱敏零截断**:Cookie、Authorization、Token、响应 body 全量在。
- **`request.raw_base64` / `response.raw_base64` 是权威字节**(`base64 -d` 还原);`raw_text_utf8` 只是视图(非 UTF-8 字节会有替换符)。
- 保留 `byte_length` 与 `sha256` 供完整性核对。
- `has_response: false` 的行 = 响应未到;后续到达会原子重建补全。
- 每行一条 JSONL;**大文件分块读**,块可能切断 JSONL 行——拼接相邻块再解析单条。

## HTTP API(WSL 直连)

```bash
# 增量同步:新增追加;检测到删除/Clear/响应补全时原子重建
curl -X POST 'http://192.168.144.1:8765/v1/export?mode=incremental'
# 同步响应里含 record_count / completed_record_count / last_seen_id / pending_ids

# 时间最新的一条完整记录
curl 'http://192.168.144.1:8765/v1/latest'

# 分块读文件字节范围(大文件首选,服务端切片不占内存)
curl 'http://192.168.144.1:8765/v1/file?offset=0&length=1048576'

# 全量重建(仅在明确要求时;普通读取一律增量)
curl -X POST 'http://192.168.144.1:8765/v1/export?mode=full'
```

活动项目的 jsonl = `/mnt/c/Users/13272/.burp-history-file-bridge/*/http-history.jsonl` 中 **mtime 最新**者;字段抽取用 `jq`(例:`jq -r '.time.request_sent_at.iso'`)。

## 工具选择

- 最新完整交换:`/v1/latest`(附 raw_text_utf8 视图,base64 原样保留)。
- 状态/计数/未决响应:看增量同步的响应体。
- 大历史或要落盘导出:分块 `/v1/file` 拉到任务目录,**不要把整个文件灌进上下文**。
- 明确要求"干净重建"时才 `/v1/export?mode=full`。

## 时间语义

排序与识别最新用 `time.request_sent_at`;四个时间字段(`proxy_received_request_at` / `request_sent_at` / `response_started_at` / `response_completed_at`,各含 ISO-8601 与 epoch ns)全保留;缺失的时间不要编造。

## 运营行为

- 普通读取一律增量同步;不要动辄 full 重建。
- 引用历史时注明 history_id 与时间;只写增量到任务记录。
