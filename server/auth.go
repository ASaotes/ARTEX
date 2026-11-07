package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// authClaims 在标准 JWT 声明之外绑定「签发时的管理员密码版本」。
//
// 版本不是密码、也不是 bcrypt 哈希本身（JWT 载荷对客户端可读，放哈希等于把
// 哈希送给任何拿到 token 的人），而是 bcrypt 哈希的截断 SHA-256。改密后哈希
// 变化 → 版本变化 → 所有旧 token 在服务端校验时立即失效，无需维护黑名单。
type authClaims struct {
	PasswordVersion string `json:"pv"`
	jwt.RegisteredClaims
}

func authPasswordVersion(hash string) string {
	sum := sha256.Sum256([]byte("artex-auth-password-version-v1\x00" + hash))
	return hex.EncodeToString(sum[:16])
}

// signJWTForHash issues a 7-day HS256 token for user ARTEX bound to hash, the
// current auth.password_hash value. Empty hash is the legitimate "not
// initialised" state and gets its own deterministic version.
func signJWTForHash(key []byte, hash string) (string, error) {
	now := time.Now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{
		PasswordVersion: authPasswordVersion(hash),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "ARTEX",
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}).SignedString(key)
}

// parseJWT validates the signature/expiry and returns the claims. Only HS256 is
// accepted; the previous implementation accepted any HMAC algorithm.
func parseJWT(tokenStr string, key []byte) (*authClaims, error) {
	var claims authClaims
	if _, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})); err != nil {
		return nil, err
	}
	return &claims, nil
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// currentPasswordHash reads the stored admin password hash. A nil data source
// only happens in tests that exercise the mux without a Manager; production
// servers always have PostgreSQL, so treating it as the empty (uninitialised)
// state keeps those tests usable without weakening a real deployment.
func (s *Server) currentPasswordHash() (string, error) {
	if s.m == nil || s.m.pg == nil {
		return "", nil
	}
	hash, _, err := s.m.pg.GetSetting(authPassKey)
	return hash, err
}

// tokenMatchesCurrentPassword reports whether tok is authentic AND was issued
// for the password currently stored. This is the revocation point: after
// /init, /change-password or an out-of-band reset-password.sh run, the stored
// hash changes and every older token stops matching.
//
// The hash is read from PostgreSQL on each request instead of cached so that a
// password change by another process/instance takes effect immediately, which
// is the whole point of binding the version. If the read fails we return the
// error and the caller fails closed (503): accepting a token we cannot check
// would silently restore the old "cannot tell" behaviour.
func (s *Server) tokenMatchesCurrentPassword(tok string) (hash string, ok bool, err error) {
	claims, perr := parseJWT(tok, s.jwtKey)
	if perr != nil {
		return "", false, nil
	}
	hash, err = s.currentPasswordHash()
	if err != nil {
		return "", false, err
	}
	want := authPasswordVersion(hash)
	return hash, subtle.ConstantTimeCompare([]byte(claims.PasswordVersion), []byte(want)) == 1, nil
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		_, ok, err := s.tokenMatchesCurrentPassword(tok)
		if err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		if !ok {
			writeErr(w, 401, "token 无效、已过期或已因密码变更失效")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
//
// 除了 fail-closed 读检查，这里还加了两道防滥用闸门：按来源 IP 的令牌桶限流，
// 以及同时执行的 init 上限（bcrypt 很吃 CPU）。两者都在碰数据库之前生效。
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	g := s.authGuard()
	if !g.allowInit(ip) {
		auditAuth("init", "rate_limited", ip, "", "per-ip window")
		writeErr(w, 429, "请求过于频繁，请稍后再试")
		return
	}
	if !g.acquireInit() {
		auditAuth("init", "rate_limited", ip, "", "concurrency limit")
		writeErr(w, 429, "请求过于频繁，请稍后再试")
		return
	}
	defer g.releaseInit()

	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		auditAuth("init", "unavailable", ip, "", "settings read failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		auditAuth("init", "rejected_initialized", ip, "", "")
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		auditAuth("init", "invalid_request", ip, "", "empty password")
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		auditAuth("init", "invalid_request", ip, "", "password policy")
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		auditAuth("init", "error", ip, "", "bcrypt failed")
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		log.Printf("[auth] init 保存密码失败: %v", err)
		auditAuth("init", "unavailable", ip, "", "settings write failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !inserted {
		auditAuth("init", "rejected_initialized", ip, "", "lost insert race")
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWTForHash(s.jwtKey, string(hash))
	if err != nil {
		auditAuth("init", "error", ip, "", "sign token failed")
		writeErr(w, 500, "token 生成失败")
		return
	}
	auditAuth("init", "success", ip, "", "")
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password. The response carries a fresh
// token so the session performing the change is not logged out; every other
// token is invalidated because its password version no longer matches.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	hash, tokOK, err := s.tokenMatchesCurrentPassword(extractToken(r))
	if err != nil {
		auditAuth("change_password", "unavailable", ip, "", "settings read failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !tokOK {
		auditAuth("change_password", "unauthorized", ip, "", "invalid or stale token")
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		auditAuth("change_password", "invalid_request", ip, "", "bad json")
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		auditAuth("change_password", "invalid_request", ip, "", "empty new password")
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		auditAuth("change_password", "invalid_request", ip, "", "password policy")
		writeErr(w, 400, msg)
		return
	}
	if hash == "" {
		auditAuth("change_password", "rejected_uninitialized", ip, "", "")
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		auditAuth("change_password", "wrong_current_password", ip, "", "")
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		auditAuth("change_password", "error", ip, "", "bcrypt failed")
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		log.Printf("[auth] change-password 保存失败: %v", err)
		auditAuth("change_password", "unavailable", ip, "", "settings write failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	tok, err := signJWTForHash(s.jwtKey, string(newHash))
	if err != nil {
		auditAuth("change_password", "error", ip, "", "sign token failed")
		writeErr(w, 500, "token 生成失败")
		return
	}
	auditAuth("change_password", "success", ip, "", "")
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, locked := s.authGuard().loginLocked(ip); locked {
		retry := int(wait.Seconds())
		if retry < 1 {
			retry = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		auditAuth("login", "locked", ip, "ARTEX", "")
		writeErr(w, 429, "登录失败次数过多，请稍后再试")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		auditAuth("login", "invalid_request", ip, "", "bad json")
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.Username != "ARTEX" {
		auditAuth("login", "invalid_credentials", ip, req.Username, "unknown user")
		s.loginFailure(w, ip, req.Username)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		auditAuth("login", "unavailable", ip, req.Username, "settings read failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		auditAuth("login", "rejected_uninitialized", ip, req.Username, "")
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		auditAuth("login", "invalid_credentials", ip, req.Username, "wrong password")
		s.loginFailure(w, ip, req.Username)
		return
	}
	s.authGuard().recordLoginSuccess(ip)
	tok, err := signJWTForHash(s.jwtKey, hash)
	if err != nil {
		auditAuth("login", "error", ip, req.Username, "sign token failed")
		writeErr(w, 500, "token 生成失败")
		return
	}
	auditAuth("login", "success", ip, req.Username, "")
	writeJSON(w, 200, map[string]any{"token": tok})
}

// loginFailure counts one failed credential attempt and converts the attempt
// that crosses the threshold into the start of a lockout. The current response
// stays 401 (the attempt did fail); the next attempt sees 429.
func (s *Server) loginFailure(w http.ResponseWriter, ip, user string) {
	if s.authGuard().recordLoginFailure(ip) {
		auditAuth("login", "lockout_started", ip, user, "too many failures")
		w.Header().Set("Retry-After", strconv.Itoa(int(authLoginLockout.Seconds())))
	}
	writeErr(w, 401, "用户名或密码错误")
}
