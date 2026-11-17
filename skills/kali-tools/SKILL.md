---
name: kali-tools
description: 需要端口扫描、漏洞模板扫描、目录爆破等 Kali 工具时调用该 skill,通过 SSH 远程执行。
---

# Kali 远程工具调用(ssh kali)

WSL 环境里没有 Kali 工具链;Kali 主机经 SSH 可达(Host 别名 `kali`,免密已配置)。**一律通过 `ssh kali '<命令>'` 远程执行,禁止在本地现写等价脚本替代。**

---

## 边界与禁止(Agent 必读 · 违反即越权)

- 只对**工单明确授权的目标**使用;范围外的任何地址、内网段一律不碰。
- Kali 是工具平台,不是跳板:禁止借它访问工单范围外的服务或网段。
- 可能影响目标可用性的动作(高并发、暴力类)先确认工单授权的强度,未写明就选最保守参数。

## 连接

- 命令模板:`ssh kali '<远程命令>'`;扫描类命令加 `-o ConnectTimeout=10` 防挂。
- IP 漂移:kali 在 192.168.1.3 / 192.168.1.236 之间变过;遇 `No route to host` 时改 `~/.ssh/config` 里两处 HostName(保持一致)再试。
- 长任务:输出重定向到 kali 的 `/tmp` 后台执行,再轮询 `tail` 回传;不要让单条 ssh 挂住会话。

## 工具范式

```bash
# 端口/服务识别
ssh kali 'nmap -sV -Pn --top-ports 100 <target> -oN /tmp/nmap.txt; tail -60 /tmp/nmap.txt'

# 漏洞模板扫描(仅 http(s) 目标)
ssh kali 'nuclei -u <target> -severity medium,high,critical -silent | tail -60'

# 目录/路径发现(字典在 /usr/share/seclists,先确认子目录存在)
ssh kali 'ffuf -u <target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403 -of csv -o /tmp/ffuf.csv; tail -40 /tmp/ffuf.csv'
```

## 输出回传规范

- 大输出:`... > /tmp/f.txt; tail -N /tmp/f.txt` 只回关键段。
- 需要全量时:`scp kali:/tmp/f.txt <任务目录>/` 取回并登记。
- 回传内容注明:工具、参数、时间戳;写入任务的证据目录。
