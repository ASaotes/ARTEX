package server

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// stdio 类型 MCP 会以 artex 进程权限执行任意 command+args（披露链的最后一步）。
// 这里提供部署方可选的三道闸门，默认全部保持原有行为（允许所有 stdio、不降权）：
//
//	ARTEX_MCP_STDIO_DISABLED=1
//	    完全禁止新建 stdio MCP 连接（http/sse 不受影响）。
//	ARTEX_MCP_STDIO_ALLOWLIST=npx,/usr/bin/node
//	    命令白名单；条目可附带参数前缀，如 "npx @playwright/mcp"，只有命令与
//	    前 N 个参数都匹配才放行。空值 = 不限制（兼容既有部署）。
//	ARTEX_MCP_STDIO_RUN_AS=artex
//	    以指定非 root 用户运行 stdio MCP 子进程（需要 setpriv，仅 root 生效；
//	    进程已是该用户时无需包装，若是其他非 root 用户则直接拒绝）。
//
// 白名单匹配使用解析后的绝对路径或 basename；带参数的条目按 token 精确比对，
// 不是字符串前缀（"npx @playwright/mcp" 不会放行 "npx @playwright/mcp-evil"）。
const (
	envMCPStdioDisabled  = "ARTEX_MCP_STDIO_DISABLED"
	envMCPStdioAllowlist = "ARTEX_MCP_STDIO_ALLOWLIST"
	envMCPStdioRunAs     = "ARTEX_MCP_STDIO_RUN_AS"
)

type stdioPolicy struct {
	disabled bool
	allow    []stdioAllowEntry
	runAs    string
}

type stdioAllowEntry struct {
	command string
	args    []string
}

// loadStdioPolicy reads the policy from the environment. Invalid values are not
// silently ignored: they would give the operator a false sense of protection.
func loadStdioPolicy() (stdioPolicy, error) {
	var p stdioPolicy
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envMCPStdioDisabled))) {
	case "", "0", "false", "no", "off":
	case "1", "true", "yes", "on":
		p.disabled = true
	default:
		return p, fmt.Errorf("%s 取值无效: %q（应为 1/true/0/false）", envMCPStdioDisabled, os.Getenv(envMCPStdioDisabled))
	}
	for _, entry := range strings.FieldsFunc(os.Getenv(envMCPStdioAllowlist), func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	}) {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		for _, f := range fields {
			if strings.ContainsRune(f, 0) {
				return p, fmt.Errorf("%s 含非法空字符", envMCPStdioAllowlist)
			}
		}
		p.allow = append(p.allow, stdioAllowEntry{command: fields[0], args: fields[1:]})
	}
	p.runAs = strings.TrimSpace(os.Getenv(envMCPStdioRunAs))
	if strings.ContainsRune(p.runAs, 0) {
		return p, fmt.Errorf("%s 含非法空字符", envMCPStdioRunAs)
	}
	return p, nil
}

// prepare resolves and validates one stdio MCP launch, and applies the optional
// privilege drop. It returns the exact command/args/env passed to the MCP
// library; no other code path spawns stdio servers.
func (p stdioPolicy) prepare(command string, args []string, env map[string]string) (string, []string, map[string]string, error) {
	if p.disabled {
		return "", nil, nil, fmt.Errorf("stdio 类型 MCP 已被 %s 禁用", envMCPStdioDisabled)
	}
	if strings.TrimSpace(command) == "" {
		return "", nil, nil, fmt.Errorf("stdio 传输缺少命令")
	}
	if strings.ContainsRune(command, 0) {
		return "", nil, nil, fmt.Errorf("stdio MCP 命令含非法空字符")
	}
	outArgs := make([]string, 0, len(args))
	for _, a := range args {
		if strings.ContainsRune(a, 0) {
			return "", nil, nil, fmt.Errorf("stdio MCP 参数含非法空字符")
		}
		outArgs = append(outArgs, a)
	}
	resolved, err := resolveStdioCommand(command)
	if err != nil {
		return "", nil, nil, err
	}
	if len(p.allow) > 0 && !p.allowed(resolved, outArgs) {
		return "", nil, nil, fmt.Errorf("stdio MCP 命令 %q 不在允许列表内（%s）", command, envMCPStdioAllowlist)
	}
	outEnv := make(map[string]string, len(env)+3)
	for k, v := range env {
		outEnv[k] = v
	}
	if p.runAs != "" {
		resolved, outArgs, outEnv, err = applyStdioRunAs(resolved, outArgs, outEnv, p.runAs, os.Geteuid(), user.Lookup, exec.LookPath)
		if err != nil {
			return "", nil, nil, err
		}
	}
	return resolved, outArgs, outEnv, nil
}

func resolveStdioCommand(command string) (string, error) {
	if strings.ContainsAny(command, `/\`) {
		abs, err := filepath.Abs(command)
		if err != nil {
			return "", fmt.Errorf("解析 stdio MCP 命令 %q: %w", command, err)
		}
		abs = filepath.Clean(abs)
		st, err := os.Stat(abs)
		if err != nil {
			return "", fmt.Errorf("stdio MCP 命令 %q 不可用: %w", command, err)
		}
		if st.IsDir() {
			return "", fmt.Errorf("stdio MCP 命令 %q 是目录", command)
		}
		return abs, nil
	}
	path, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Errorf("stdio MCP 命令 %q 不在 PATH 中: %w", command, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("解析 stdio MCP 命令 %q: %w", command, err)
	}
	return filepath.Clean(abs), nil
}

func (p stdioPolicy) allowed(resolved string, args []string) bool {
	base := filepath.Base(resolved)
	for _, e := range p.allow {
		matchCmd := e.command == base || filepath.Clean(e.command) == resolved
		if !matchCmd {
			if abs, err := filepath.Abs(e.command); err == nil && filepath.Clean(abs) == resolved {
				matchCmd = true
			}
		}
		if !matchCmd || len(e.args) > len(args) {
			continue
		}
		matchArgs := true
		for i := range e.args {
			if e.args[i] != args[i] {
				matchArgs = false
				break
			}
		}
		if matchArgs {
			return true
		}
	}
	return false
}

// applyStdioRunAs wraps the command with setpriv so the MCP subprocess (and any
// grandchildren) run as an unprivileged user. euid/lookup/lookPath are parameters
// so the decision logic is testable without actually being root.
func applyStdioRunAs(command string, args []string, env map[string]string, username string, euid int, lookup func(string) (*user.User, error), lookPath func(string) (string, error)) (string, []string, map[string]string, error) {
	if euid != 0 {
		cur, err := user.Current()
		if err != nil {
			return "", nil, nil, fmt.Errorf("读取当前用户失败，无法执行 %s: %w", envMCPStdioRunAs, err)
		}
		if cur.Username != username && cur.Uid != username {
			return "", nil, nil, fmt.Errorf("进程不是 root，无法把 stdio MCP 降权到 %q", username)
		}
		return command, args, env, nil
	}
	target, err := lookup(username)
	if err != nil {
		return "", nil, nil, fmt.Errorf("查找 %s 用户 %q 失败: %w", envMCPStdioRunAs, username, err)
	}
	if target.Uid == "0" {
		return "", nil, nil, fmt.Errorf("%s 不能指向 root（%q），降权无意义", envMCPStdioRunAs, username)
	}
	setpriv, err := lookPath("setpriv")
	if err != nil {
		return "", nil, nil, fmt.Errorf("已配置 %s=%s，但找不到 setpriv，拒绝以 root 运行 stdio MCP: %w", envMCPStdioRunAs, username, err)
	}
	wrapped := []string{
		"--reuid=" + target.Uid,
		"--regid=" + target.Gid,
		"--clear-groups",
		"--no-new-privs",
		"--",
		command,
	}
	wrapped = append(wrapped, args...)
	outEnv := make(map[string]string, len(env)+3)
	for k, v := range env {
		outEnv[k] = v
	}
	outEnv["HOME"] = target.HomeDir
	outEnv["USER"] = target.Username
	outEnv["LOGNAME"] = target.Username
	return setpriv, wrapped, outEnv, nil
}
