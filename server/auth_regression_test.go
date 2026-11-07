package server

// 这些测试用进程内的假 SQL 驱动模拟 settings 表，因此不依赖 PostgreSQL：
// 上一轮测试环境无 PG 时，auth 的故障注入/并发回归会整体 skip，等于没验证。
// 假驱动只实现 db.GetSetting / InsertSettingIfAbsent / SetSetting 用到的三条 SQL，
// 语义与真实 SQL 保持一致（缺行返回 sql.ErrNoRows；ON CONFLICT DO NOTHING 不覆盖）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
)

var fakeDriverSeq atomic.Int64

type fakeSettingsStore struct {
	mu       sync.Mutex
	values   map[string]string
	getErr   error
	writeErr error

	getCalls    int
	insertCalls int
	setCalls    int
}

func (s *fakeSettingsStore) get(key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getCalls++
	if s.getErr != nil {
		return "", false, s.getErr
	}
	v, ok := s.values[key]
	return v, ok, nil
}

func (s *fakeSettingsStore) insertIfAbsent(key, value string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.insertCalls++
	if s.writeErr != nil {
		return false, s.writeErr
	}
	if _, ok := s.values[key]; ok {
		return false, nil
	}
	s.values[key] = value
	return true, nil
}

func (s *fakeSettingsStore) set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setCalls++
	if s.writeErr != nil {
		return s.writeErr
	}
	s.values[key] = value
	return nil
}

type fakeSettingsDriver struct{ store *fakeSettingsStore }

func (d *fakeSettingsDriver) Open(string) (driver.Conn, error) {
	return &fakeSettingsConn{store: d.store}, nil
}

type fakeSettingsConn struct{ store *fakeSettingsStore }

func (c *fakeSettingsConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not supported")
}
func (c *fakeSettingsConn) Close() error { return nil }
func (c *fakeSettingsConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions not supported")
}

func (c *fakeSettingsConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q := collapseSQL(query)
	if !strings.HasPrefix(q, "SELECT value FROM settings WHERE key=$1") {
		return nil, fmt.Errorf("fake db: unexpected query %q", q)
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("fake db: want 1 arg, got %d", len(args))
	}
	value, ok, err := c.store.get(fmt.Sprint(args[0].Value))
	if err != nil {
		return nil, err
	}
	return &fakeSettingsRows{value: value, ok: ok}, nil
}

func (c *fakeSettingsConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	q := collapseSQL(query)
	if len(args) != 2 {
		return nil, fmt.Errorf("fake db: want 2 args, got %d", len(args))
	}
	key, value := fmt.Sprint(args[0].Value), fmt.Sprint(args[1].Value)
	switch {
	case strings.HasPrefix(q, "INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING"):
		inserted, err := c.store.insertIfAbsent(key, value)
		if err != nil {
			return nil, err
		}
		if inserted {
			return fakeResult(1), nil
		}
		return fakeResult(0), nil
	case strings.HasPrefix(q, "INSERT INTO settings(key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET"):
		if err := c.store.set(key, value); err != nil {
			return nil, err
		}
		return fakeResult(1), nil
	default:
		return nil, fmt.Errorf("fake db: unexpected exec %q", q)
	}
}

func collapseSQL(q string) string { return strings.Join(strings.Fields(q), " ") }

type fakeSettingsRows struct {
	value string
	ok    bool
	done  bool
}

func (r *fakeSettingsRows) Columns() []string { return []string{"value"} }
func (r *fakeSettingsRows) Close() error      { return nil }
func (r *fakeSettingsRows) Next(dest []driver.Value) error {
	if !r.ok || r.done {
		return io.EOF
	}
	dest[0] = r.value
	r.done = true
	return nil
}

type fakeResult int64

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return int64(r), nil }

// newFakeAuthServer returns a Server wired to an isolated in-memory settings store.
func newFakeAuthServer(t *testing.T) (*Server, *fakeSettingsStore) {
	t.Helper()
	store := &fakeSettingsStore{values: map[string]string{}}
	name := fmt.Sprintf("authfake-%d", fakeDriverSeq.Add(1))
	sql.Register(name, &fakeSettingsDriver{store: store})
	sqlDB, err := sql.Open(name, "fake")
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	pg := &db.DB{DB: sqlDB}
	return &Server{m: &Manager{pg: pg}, jwtKey: []byte("fake-auth-test-signing-key-0123456789")}, store
}

func fakeRequest(method, path, remoteIP string, body any) *http.Request {
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, strings.NewReader(string(b)))
	}
	if remoteIP != "" {
		r.RemoteAddr = remoteIP + ":54321"
	}
	return r
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func tokenFromResponse(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if out.Token == "" {
		t.Fatalf("response has no token: %s", rec.Body.String())
	}
	return out.Token
}

// 读失败一律 5xx，且绝不能写数据库。这条路径就是披露里的 fail-open。
func TestAuthReadFailureIsFailClosedAndNeverWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(s *Server, ip string) *httptest.ResponseRecorder
	}{
		{"status", func(s *Server, ip string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			s.authStatus(rec, fakeRequest("GET", "/api/auth/status", ip, nil))
			return rec
		}},
		{"init", func(s *Server, ip string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			s.authInit(rec, fakeRequest("POST", "/api/auth/init", ip, map[string]string{"password": "attacker-password"}))
			return rec
		}},
		{"login", func(s *Server, ip string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			s.authLogin(rec, fakeRequest("POST", "/api/auth/login", ip, map[string]string{"username": "ARTEX", "password": "x"}))
			return rec
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, store := newFakeAuthServer(t)
			store.values[authPassKey] = mustHash(t, "existing-admin-password")
			store.getErr = errors.New("connection pool exhausted")
			rec := tc.call(s, "203.0.113.7")
			if rec.Code < 500 || rec.Code > 599 {
				t.Fatalf("status=%d want 5xx; body=%s", rec.Code, rec.Body.String())
			}
			if store.insertCalls != 0 || store.setCalls != 0 {
				t.Fatalf("读失败时不应写库: insert=%d set=%d", store.insertCalls, store.setCalls)
			}
			if got := store.values[authPassKey]; got == "" || !strings.HasPrefix(got, "$2") {
				t.Fatalf("已有密码哈希被改动: %q", got)
			}
		})
	}
}

// 写失败也必须 5xx，并且旧哈希保持不变。
func TestAuthWriteFailureKeepsExistingHash(t *testing.T) {
	s, store := newFakeAuthServer(t)
	store.writeErr = errors.New("write failed")
	rec := httptest.NewRecorder()
	s.authInit(rec, fakeRequest("POST", "/api/auth/init", "203.0.113.8", map[string]string{"password": "new-password"}))
	if rec.Code < 500 || rec.Code > 599 {
		t.Fatalf("status=%d want 5xx; body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := store.values[authPassKey]; ok {
		t.Fatalf("写失败后不应留下密码哈希")
	}
	if store.insertCalls != 1 {
		t.Fatalf("insert calls=%d want 1", store.insertCalls)
	}
}

// 并发 init：两个请求都通过读检查后，只有主键约束允许的那个能写入；
// 结果必须恰好一个 200、一个 403，且库里的哈希属于拿到 200 的密码。
func TestAuthInitConcurrentOnlyOneWins(t *testing.T) {
	for attempt := 0; attempt < 3; attempt++ {
		s, store := newFakeAuthServer(t)
		passwords := []string{"concurrent-password-a", "concurrent-password-b"}
		codes := make([]int, 2)
		var wg sync.WaitGroup
		for i := range passwords {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rec := httptest.NewRecorder()
				req := fakeRequest("POST", "/api/auth/init", fmt.Sprintf("198.51.100.%d", i+1),
					map[string]string{"password": passwords[i]})
				s.authInit(rec, req)
				codes[i] = rec.Code
			}(i)
		}
		wg.Wait()

		okCount := 0
		for _, c := range codes {
			if c == http.StatusOK {
				okCount++
			} else if c != http.StatusForbidden {
				t.Fatalf("attempt %d: unexpected status %d (want 200/403)", attempt, c)
			}
		}
		if okCount != 1 {
			t.Fatalf("attempt %d: %d successes, want exactly 1 (codes=%v)", attempt, okCount, codes)
		}
		stored := store.values[authPassKey]
		matches := 0
		for _, pw := range passwords {
			if bcrypt.CompareHashAndPassword([]byte(stored), []byte(pw)) == nil {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("attempt %d: stored hash matches %d passwords, want 1", attempt, matches)
		}
	}
}

// init 的每 IP 限流：已有密码时前 5 次快速 403，第 6 次 429。
func TestAuthInitRateLimited(t *testing.T) {
	s, store := newFakeAuthServer(t)
	store.values[authPassKey] = mustHash(t, "existing-admin-password")
	const ip = "198.51.100.50"
	for i := 1; i <= 5; i++ {
		rec := httptest.NewRecorder()
		s.authInit(rec, fakeRequest("POST", "/api/auth/init", ip, map[string]string{"password": "whatever123"}))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: status=%d want 403; body=%s", i, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	s.authInit(rec, fakeRequest("POST", "/api/auth/init", ip, map[string]string{"password": "whatever123"}))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 6: status=%d want 429; body=%s", rec.Code, rec.Body.String())
	}
	// 另一个来源 IP 不受影响。
	rec = httptest.NewRecorder()
	s.authInit(rec, fakeRequest("POST", "/api/auth/init", "198.51.100.51", map[string]string{"password": "whatever123"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("different ip: status=%d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthLoginLockoutAfterRepeatedFailures(t *testing.T) {
	s, store := newFakeAuthServer(t)
	store.values[authPassKey] = mustHash(t, "correct-horse-battery")
	const ip = "203.0.113.30"
	for i := 1; i <= authLoginMaxFailures; i++ {
		rec := httptest.NewRecorder()
		s.authLogin(rec, fakeRequest("POST", "/api/auth/login", ip, map[string]string{"username": "ARTEX", "password": "wrong"}))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status=%d want 401; body=%s", i, rec.Code, rec.Body.String())
		}
	}
	// 锁定后即使密码正确也拒绝，避免在线爆破继续消耗 bcrypt。
	rec := httptest.NewRecorder()
	s.authLogin(rec, fakeRequest("POST", "/api/auth/login", ip, map[string]string{"username": "ARTEX", "password": "correct-horse-battery"}))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login: status=%d want 429; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("锁定响应缺少 Retry-After")
	}
	// 其他 IP 仍可正常登录。
	rec = httptest.NewRecorder()
	s.authLogin(rec, fakeRequest("POST", "/api/auth/login", "203.0.113.31", map[string]string{"username": "ARTEX", "password": "correct-horse-battery"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("other ip login: status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// 数据库故障不是「密码错」，不能把管理员锁在门外。
func TestAuthLoginDatabaseErrorDoesNotLockOut(t *testing.T) {
	s, store := newFakeAuthServer(t)
	store.values[authPassKey] = mustHash(t, "correct-horse-battery")
	store.getErr = errors.New("connection pool exhausted")
	for i := 0; i < authLoginMaxFailures+2; i++ {
		rec := httptest.NewRecorder()
		s.authLogin(rec, fakeRequest("POST", "/api/auth/login", "203.0.113.40", map[string]string{"username": "ARTEX", "password": "correct-horse-battery"}))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("db error: status=%d want 503; body=%s", rec.Code, rec.Body.String())
		}
	}
	store.getErr = nil
	rec := httptest.NewRecorder()
	s.authLogin(rec, fakeRequest("POST", "/api/auth/login", "203.0.113.40", map[string]string{"username": "ARTEX", "password": "correct-horse-battery"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("after recovery: status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// JWT 密码版本：改密（含 reset-password.sh 这类带外改哈希）后旧 token 立即失效。
func TestJWTRevokedWhenPasswordHashChanges(t *testing.T) {
	s, store := newFakeAuthServer(t)
	oldHash := mustHash(t, "old-admin-password")
	store.values[authPassKey] = oldHash
	oldToken, err := signJWTForHash(s.jwtKey, oldHash)
	if err != nil {
		t.Fatal(err)
	}

	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(tok string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/tasks", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		protected.ServeHTTP(rec, req)
		return rec
	}
	if rec := call(oldToken); rec.Code != http.StatusOK {
		t.Fatalf("current token: status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}

	// 模拟 reset-password.sh 直接改写 settings 表。
	newHash := mustHash(t, "new-admin-password")
	store.values[authPassKey] = newHash
	if rec := call(oldToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale token after hash change: status=%d want 401; body=%s", rec.Code, rec.Body.String())
	}
	newToken, err := signJWTForHash(s.jwtKey, newHash)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(newToken); rec.Code != http.StatusOK {
		t.Fatalf("new token: status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}
	emptyToken, err := signJWTForHash(s.jwtKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(emptyToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token for empty hash: status=%d want 401; body=%s", rec.Code, rec.Body.String())
	}
}

func TestChangePasswordRotatesToken(t *testing.T) {
	s, store := newFakeAuthServer(t)
	oldHash := mustHash(t, "old-admin-password")
	store.values[authPassKey] = oldHash
	oldToken, err := signJWTForHash(s.jwtKey, oldHash)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := fakeRequest("POST", "/api/auth/change-password", "203.0.113.60",
		map[string]string{"old_password": "old-admin-password", "new_password": "new-admin-password"})
	req.Header.Set("Authorization", "Bearer "+oldToken)
	s.authChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change password: status=%d want 200; body=%s", rec.Code, rec.Body.String())
	}
	if err := bcrypt.CompareHashAndPassword([]byte(store.values[authPassKey]), []byte("new-admin-password")); err != nil {
		t.Fatalf("stored hash does not match new password: %v", err)
	}
	newToken := tokenFromResponse(t, rec)

	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	call := func(tok string) int {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/tasks", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		protected.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := call(oldToken); code != http.StatusUnauthorized {
		t.Fatalf("old token after change: status=%d want 401", code)
	}
	if code := call(newToken); code != http.StatusOK {
		t.Fatalf("returned token: status=%d want 200", code)
	}
}

func TestRequireAuthFailsClosedWhenPasswordReadFails(t *testing.T) {
	s, store := newFakeAuthServer(t)
	hash := mustHash(t, "admin-password")
	store.values[authPassKey] = hash
	tok, err := signJWTForHash(s.jwtKey, hash)
	if err != nil {
		t.Fatal(err)
	}
	store.getErr = errors.New("connection pool exhausted")

	protected := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	protected.ServeHTTP(rec, req)
	if rec.Code < 500 || rec.Code > 599 {
		t.Fatalf("status=%d want 5xx; body=%s", rec.Code, rec.Body.String())
	}
}

func TestClientIPHonoursProxyHeadersOnlyWhenEnabled(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/auth/init", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")

	t.Setenv("ARTEX_TRUST_PROXY_HEADERS", "")
	if got := clientIP(req); got != "127.0.0.1" {
		t.Fatalf("untrusted headers: got %q want 127.0.0.1", got)
	}
	t.Setenv("ARTEX_TRUST_PROXY_HEADERS", "1")
	if got := clientIP(req); got != "203.0.113.9" {
		t.Fatalf("trusted headers: got %q want 203.0.113.9", got)
	}
	// 伪造的非法 IP 不能成为限流键。
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(req); got != "127.0.0.1" {
		t.Fatalf("invalid header: got %q want 127.0.0.1", got)
	}
}

func TestAuthGuardRefillAndLockExpiry(t *testing.T) {
	g := newAuthGuard()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }

	for i := 0; i < authInitMaxPerWindow; i++ {
		if !g.allowInit("203.0.113.1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if g.allowInit("203.0.113.1") {
		t.Fatal("6th request within the window should be limited")
	}
	now = now.Add(authInitWindow)
	if !g.allowInit("203.0.113.1") {
		t.Fatal("bucket should refill after one window")
	}

	for i := 0; i < authLoginMaxFailures; i++ {
		if g.recordLoginFailure("203.0.113.2") && i != authLoginMaxFailures-1 {
			t.Fatalf("locked too early at failure %d", i+1)
		}
	}
	if _, locked := g.loginLocked("203.0.113.2"); !locked {
		t.Fatal("expected lockout after threshold failures")
	}
	now = now.Add(authLoginLockout)
	if _, locked := g.loginLocked("203.0.113.2"); locked {
		t.Fatal("lockout should expire")
	}
}
