---
name: burp-http-repeater
description: 将 Burp History 中的完整请求或修改后的 Raw HTTP 放入命名 Repeater 标签,供人工在 Burp 里继续深挖。只投放,不自动发送。
---

# Burp Repeater 投放(经 history-file-bridge)

把值得**人工深挖**的请求摆进 Burp 的 Repeater 标签(带语义命名),交还操作员控制。**两个端点都只创建并填充标签,不会点击 Send——不会因此产生任何网络请求。**

## API(WSL 直连 192.168.144.1:8765)

```bash
# 按 History ID 原样复制完整最终请求到命名 Repeater 标签
curl -X POST 'http://192.168.144.1:8765/v1/repeater/history?history_id=<ID>&session_name=<语义名>'

# 把修改后的完整 Raw HTTP 投放到命名 Repeater 标签
curl -X POST --data-binary @request.raw \
  'http://192.168.144.1:8765/v1/repeater/raw?host=<host>&port=<port>&secure=<true|false>&session_name=<语义名>'
```

- `session_name` 用**语义命名**(如 `login-baseline`、`upload-bypass-modified`),让操作员一眼知道每个标签是什么。
- Raw HTTP = 完整请求报文(起始行 + 头部 + 空行 + body),base64 解码后的原文。
- `secure=true` 表示 https 目标。

## 使用时机

- 自动化探测已确认有价值、但需要**人工调参续攻**的请求(变 payload、变会话、试边界)。
- 交付阶段:把关键请求摆成一组命名标签,作为报告的"人工复核入口"。

## 边界

- 只投放工单授权目标的请求。
- 投放后在交付说明里列出标签名清单,方便操作员定位。
