package server

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestStdioPolicyDisabled(t *testing.T) {
	t.Setenv(envMCPStdioDisabled, "1")
	p, err := loadStdioPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.prepare("/bin/echo", nil, nil); err == nil || !strings.Contains(err.Error(), "禁用") {
		t.Fatalf("want disabled error, got %v", err)
	}
}

func TestStdioPolicyRejectsInvalidDisabledValue(t *testing.T) {
	t.Setenv(envMCPStdioDisabled, "maybe")
	if _, err := loadStdioPolicy(); err == nil {
		t.Fatal("invalid boolean must be rejected, not silently treated as enabled")
	}
}

func TestStdioPolicyAllowlistCommandAndArgs(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "mcp-server.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv(envMCPStdioAllowlist, script+" --safe")
	p, err := loadStdioPolicy()
	if err != nil {
		t.Fatal(err)
	}
	resolved, args, _, err := p.prepare(script, []string{"--safe", "extra"}, nil)
	if err != nil {
		t.Fatalf("allowed command rejected: %v", err)
	}
	if resolved != script || len(args) != 2 || args[0] != "--safe" {
		t.Fatalf("resolved=%q args=%v", resolved, args)
	}
	if _, _, _, err := p.prepare(script, []string{"--unsafe"}, nil); err == nil || !strings.Contains(err.Error(), "允许列表") {
		t.Fatalf("argument prefix mismatch must be rejected, got %v", err)
	}
	if _, _, _, err := p.prepare("/bin/echo", []string{"--safe"}, nil); err == nil {
		t.Fatal("command not in allowlist must be rejected")
	}
	// 参数按 token 精确匹配，不是字符串前缀。
	if _, _, _, err := p.prepare(script, []string{"--safeevil"}, nil); err == nil {
		t.Fatal("token prefix must not match")
	}
}

func TestStdioPolicyAllowsEmptyAllowlist(t *testing.T) {
	t.Setenv(envMCPStdioAllowlist, "")
	p, err := loadStdioPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.prepare("/bin/echo", []string{"hello"}, nil); err != nil {
		t.Fatalf("empty allowlist must preserve existing behaviour: %v", err)
	}
}

func TestStdioPolicyRejectsNulArgument(t *testing.T) {
	t.Setenv(envMCPStdioAllowlist, "")
	p, _ := loadStdioPolicy()
	if _, _, _, err := p.prepare("/bin/echo", []string{"a\x00b"}, nil); err == nil {
		t.Fatal("NUL in args must be rejected")
	}
}

func TestStdioRunAsWrapsWithSetpriv(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "1001", Gid: "1002", HomeDir: "/home/mcp"}, nil
	}
	lookPath := func(name string) (string, error) {
		if name != "setpriv" {
			return "", errors.New("unexpected lookup")
		}
		return "/usr/bin/setpriv", nil
	}
	cmd, args, env, err := applyStdioRunAs("/usr/bin/npx", []string{"@playwright/mcp"}, map[string]string{"X": "1"}, "mcp", 0, lookup, lookPath)
	if err != nil {
		t.Fatalf("run-as failed: %v", err)
	}
	if cmd != "/usr/bin/setpriv" {
		t.Fatalf("cmd=%q want setpriv", cmd)
	}
	joined := strings.Join(args, "\n")
	for _, want := range []string{"--reuid=1001", "--regid=1002", "--no-new-privs", "--", "/usr/bin/npx", "@playwright/mcp"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("wrapped args missing %q: %v", want, args)
		}
	}
	if env["HOME"] != "/home/mcp" || env["USER"] != "mcp" || env["X"] != "1" {
		t.Fatalf("env=%v", env)
	}
}

func TestStdioRunAsRejectsRootTarget(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "0", Gid: "0", HomeDir: "/root"}, nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/setpriv", nil }
	if _, _, _, err := applyStdioRunAs("/bin/echo", nil, nil, "root", 0, lookup, lookPath); err == nil {
		t.Fatal("run-as root must be rejected")
	}
}

func TestStdioRunAsRequiresSetpriv(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "1001", Gid: "1002", HomeDir: "/home/mcp"}, nil
	}
	lookPath := func(string) (string, error) { return "", errors.New("not found") }
	if _, _, _, err := applyStdioRunAs("/bin/echo", nil, nil, "mcp", 0, lookup, lookPath); err == nil || !strings.Contains(err.Error(), "setpriv") {
		t.Fatalf("missing setpriv must fail closed, got %v", err)
	}
}

func TestStdioRunAsDifferentNonRootUserFails(t *testing.T) {
	cur, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	lookup := func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "9999", Gid: "9999", HomeDir: "/home/other"}, nil
	}
	lookPath := func(string) (string, error) { return "/usr/bin/setpriv", nil }
	if _, _, _, err := applyStdioRunAs("/bin/echo", nil, nil, "someone-else", 1000, lookup, lookPath); err == nil {
		t.Fatalf("non-root process cannot switch to another user (current %s)", cur.Username)
	}
	// 当前用户就是目标用户时无需包装。
	cmd, args, _, err := applyStdioRunAs("/bin/echo", []string{"hi"}, nil, cur.Username, 1000, lookup, lookPath)
	if err != nil {
		t.Fatalf("already-target user: %v", err)
	}
	if cmd != "/bin/echo" || len(args) != 1 {
		t.Fatalf("already-target user should not wrap: cmd=%q args=%v", cmd, args)
	}
}

// connectMCP 是代码库里唯一的 stdio exec 入口；策略必须在 spawn 之前生效。
func TestConnectMCPStdioHonoursPolicy(t *testing.T) {
	t.Setenv(envMCPStdioDisabled, "1")
	if _, err := connectMCP(context.Background(), &db.MCPServer{Transport: "stdio", Command: "/bin/echo"}); err == nil || !strings.Contains(err.Error(), "禁用") {
		t.Fatalf("disabled stdio: got %v", err)
	}

	t.Setenv(envMCPStdioDisabled, "")
	t.Setenv(envMCPStdioAllowlist, "/bin/true")
	if _, err := connectMCP(context.Background(), &db.MCPServer{Transport: "stdio", Command: "/bin/echo"}); err == nil || !strings.Contains(err.Error(), "允许列表") {
		t.Fatalf("allowlist deny: got %v", err)
	}
}
