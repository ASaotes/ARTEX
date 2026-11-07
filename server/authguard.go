package server

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 认证入口的防滥用参数。都是进程内状态：重启后计数清零，这是可接受的——
// 这里的目的是挡住在线暴力破解和初始化接口的 CPU 消耗，而不是做持久化的
// 账号风控；真正的密码学保证仍在 bcrypt 与 SQL 主键约束上。
const (
	// /api/auth/init 每个来源 IP 每分钟最多尝试次数。init 只在首次部署时有意义，
	// 正常用户一两次就完成，5 次足够覆盖输错/确认失败。
	authInitMaxPerWindow = 5
	authInitWindow       = time.Minute
	// 同时执行的 authInit 上限。每个请求要跑一次 bcrypt(~60ms 且吃 CPU)，
	// 不封顶时未认证请求可以轻易把管理端口打满。
	defaultAuthInitConcurrency = 2
	// 登录失败锁定：同一来源 IP 在 15 分钟内失败 5 次，锁定 15 分钟。
	authLoginMaxFailures    = 5
	authLoginFailureWindow  = 15 * time.Minute
	authLoginLockout        = 15 * time.Minute
	authGuardSweepInterval  = 10 * time.Minute
	authGuardSweepThreshold = 4096
)

// authGuard 保存认证入口的短时状态。所有方法都带锁，可被 HTTP handler 并发调用。
type authGuard struct {
	mu     sync.Mutex
	init   map[string]*authRateEntry
	logins map[string]*authLoginState
	slots  chan struct{}
	sweep  time.Time

	// now 仅用于测试注入时钟；生产路径保持 nil，方法内回落到 time.Now。
	now func() time.Time
}

type authRateEntry struct {
	tokens float64
	last   time.Time
}

type authLoginState struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

func newAuthGuard() *authGuard {
	return newAuthGuardWithConcurrency(defaultAuthInitConcurrency)
}

func newAuthGuardWithConcurrency(n int) *authGuard {
	if n < 1 {
		n = 1
	}
	return &authGuard{
		init:   map[string]*authRateEntry{},
		logins: map[string]*authLoginState{},
		slots:  make(chan struct{}, n),
	}
}

func (g *authGuard) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// allowInit 按 IP 做令牌桶限流：桶容量 authInitMaxPerWindow，匀速回填。
func (g *authGuard) allowInit(ip string) bool {
	now := g.clock()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)

	e := g.init[ip]
	if e == nil {
		e = &authRateEntry{tokens: authInitMaxPerWindow, last: now}
		g.init[ip] = e
	}
	if elapsed := now.Sub(e.last).Seconds(); elapsed > 0 {
		e.tokens += elapsed * (authInitMaxPerWindow / authInitWindow.Seconds())
		if e.tokens > authInitMaxPerWindow {
			e.tokens = authInitMaxPerWindow
		}
		e.last = now
	}
	if e.tokens < 1 {
		return false
	}
	e.tokens--
	return true
}

// acquireInit 非阻塞地占用一个并发执行槽；槽满时立即返回 false。
func (g *authGuard) acquireInit() bool {
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *authGuard) releaseInit() {
	<-g.slots
}

// loginLocked 返回该 IP 剩余的锁定时间；未锁定返回 0,false。
func (g *authGuard) loginLocked(ip string) (time.Duration, bool) {
	now := g.clock()
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.logins[ip]
	if st == nil || st.lockedUntil.IsZero() || !now.Before(st.lockedUntil) {
		return 0, false
	}
	return st.lockedUntil.Sub(now), true
}

// recordLoginFailure 记一次失败；达到阈值时开始锁定并返回 true。
func (g *authGuard) recordLoginFailure(ip string) bool {
	now := g.clock()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked(now)

	st := g.logins[ip]
	if st == nil {
		st = &authLoginState{}
		g.logins[ip] = st
	}
	if st.windowStart.IsZero() || now.Sub(st.windowStart) > authLoginFailureWindow {
		st.failures = 0
		st.windowStart = now
	}
	st.failures++
	if st.failures >= authLoginMaxFailures {
		st.failures = 0
		st.windowStart = time.Time{}
		st.lockedUntil = now.Add(authLoginLockout)
		return true
	}
	return false
}

func (g *authGuard) recordLoginSuccess(ip string) {
	g.mu.Lock()
	delete(g.logins, ip)
	g.mu.Unlock()
}

// sweepLocked 丢掉过期的限流/锁定条目，避免被随机 IP 撑爆内存。
func (g *authGuard) sweepLocked(now time.Time) {
	if !g.sweep.IsZero() && now.Sub(g.sweep) < authGuardSweepInterval &&
		len(g.init) < authGuardSweepThreshold && len(g.logins) < authGuardSweepThreshold {
		return
	}
	g.sweep = now
	for ip, e := range g.init {
		// 窗口过后令牌本就回填满了，直接丢掉条目等价于重置，也避免被大量
		// 一次性来源 IP 撑爆内存。
		if now.Sub(e.last) > authInitWindow {
			delete(g.init, ip)
		}
	}
	for ip, st := range g.logins {
		expiredLock := st.lockedUntil.IsZero() || !now.Before(st.lockedUntil)
		if expiredLock && (st.windowStart.IsZero() || now.Sub(st.windowStart) > authLoginFailureWindow) {
			delete(g.logins, ip)
		}
	}
}

// trustProxyHeaders 决定是否采信 X-Forwarded-For / X-Real-IP。默认不信任：
// 直接暴露端口时这些头可被客户端伪造，按伪造 IP 限流等于没有限流。把管理端口
// 放在同机/可信反代之后时，设置 ARTEX_TRUST_PROXY_HEADERS=1 才能按真实客户端
// 分别计数（否则所有请求都会算到反代这一个 IP 上）。
func trustProxyHeaders() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_TRUST_PROXY_HEADERS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// clientIP 返回用于限流/锁定的来源地址。
func clientIP(r *http.Request) string {
	if trustProxyHeaders() {
		for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
			if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil {
				return ip.String()
			}
		}
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		return ip.String()
	}
	if host = strings.TrimSpace(host); host != "" {
		return host
	}
	return "unknown"
}

// auditAuth 输出一行结构化审计日志。绝不记录凭据正文：detail 只允许放结果原因、
// 计数等元信息；user 可能来自请求，用 %q 转义防止换行注入伪造日志行。
func auditAuth(event, result, ip, user, detail string) {
	if user == "" {
		user = "-"
	}
	line := "[auth-audit] event=" + event + " result=" + result + " ip=" + ip + " user=" + strconv.Quote(user)
	if detail != "" {
		line += " detail=" + strconv.Quote(detail)
	}
	log.Print(line)
}

// authGuard lazily creates the process-wide guard. Lazy keeps the many tests
// that build &Server{} literals working (handler tests get a default guard).
func (s *Server) authGuard() *authGuard {
	s.authOnce.Do(func() { s.auth = newAuthGuard() })
	return s.auth
}
