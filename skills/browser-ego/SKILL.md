---
name: browser-ego
description: 需要真实浏览器访问网页(渲染、截图、表单、登录态)时调用该 skill,通过 browser 工具驱动用户本机的 ego 浏览器。
---

# 用 browser 工具驱动 ego(真实 Windows 浏览器)

**网页交互一律使用 `browser_*` 工具**(browser_navigate / browser_snapshot / browser_click / browser_type / browser_take_screenshot 等,共 25 个)。它们驱动的是**用户屏幕上真实的 ego 浏览器**(Windows 指纹、真实渲染、真实 Cookie 环境)。

**禁止**:用 curl/内联脚本替代需要浏览器渲染的交互;**禁止**尝试另起本地浏览器(playwright-cli 未安装,且会绕开真实环境)。

---

## 前提

- ego 已由用户通过桌面 `ego-cdp.bat` 启动、转发器(`ego-forwarder.bat`)在线。
- **若 browser 工具报连接错误**(ECONNREFUSED / timeout):在交付消息里**请用户启动 ego**,然后重试;**不要**退回写脚本硬扫。

## 范式

1. `browser_navigate` 打开工单授权的目标 URL。
2. `browser_snapshot` 获取可交互元素快照(ref 列表)——先看结构再动手。
3. 按 ref 执行 `browser_click` / `browser_type`;提交表单前核对填写内容。
4. 证据:关键状态用 `browser_take_screenshot` 截图,注明时间与 URL,存入任务证据目录。
5. 敏感动作(登录、提交、支付类表单)先确认工单已授权该操作。

## 边界

- 只访问工单授权目标;页面里的第三方/外链域名不主动跟进,除非工单明确包含。
- 抓包模式(`ego-cdp-capture.bat`)仅在 ARTEX 流量捕获开关开启时使用,否则网页无法打开。
