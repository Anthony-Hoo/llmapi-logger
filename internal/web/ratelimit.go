package web

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	loginFailureWindow = 5 * time.Minute
	loginFailureLimit  = 10
	// Beyond this many tracked addresses the limiter sweeps expired entries, so
	// a burst of one-shot source addresses cannot grow the map without bound.
	loginLimiterSweepThreshold = 1024
)

// loginLimiter throttles repeated failed logins per source address. It is
// deliberately in-memory and per-process: this is a single-machine deployment,
// and the goal is to make credential guessing slow rather than to coordinate a
// distributed quota. Successful logins clear the counter, so a legitimate user
// who mistypes their key a few times is never locked out afterwards.
type loginLimiter struct {
	mu      sync.Mutex
	windows map[string]*loginWindow
	now     func() time.Time
}

type loginWindow struct {
	failures  int
	expiresAt time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{windows: make(map[string]*loginWindow), now: time.Now}
}

// allow reports whether another login attempt may be made, and how long the
// caller must wait when it may not.
func (limiter *loginLimiter) allow(request *http.Request) (bool, time.Duration) {
	if limiter == nil {
		return true, 0
	}
	key := loginLimiterKey(request)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	window, exists := limiter.windows[key]
	if !exists || !limiter.now().Before(window.expiresAt) {
		return true, 0
	}
	if window.failures < loginFailureLimit {
		return true, 0
	}
	return false, window.expiresAt.Sub(limiter.now())
}

func (limiter *loginLimiter) recordFailure(request *http.Request) {
	if limiter == nil {
		return
	}
	key := loginLimiterKey(request)
	now := limiter.now()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.recordFailureLocked(key, now)
}

// checkAndRecord admits or refuses one attempt whose outcome is already
// known, and counts it when it failed, in a single critical section: a burst
// of concurrent failures from one address can never be admitted past the
// limit by checking before any of them is counted. A refused attempt is not
// counted again.
func (limiter *loginLimiter) checkAndRecord(request *http.Request, failed bool) (bool, time.Duration) {
	if limiter == nil {
		return true, 0
	}
	key := loginLimiterKey(request)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	if window, exists := limiter.windows[key]; exists && now.Before(window.expiresAt) && window.failures >= loginFailureLimit {
		return false, window.expiresAt.Sub(now)
	}
	if failed {
		limiter.recordFailureLocked(key, now)
	}
	return true, 0
}

func (limiter *loginLimiter) recordFailureLocked(key string, now time.Time) {
	window, exists := limiter.windows[key]
	if !exists || !now.Before(window.expiresAt) {
		window = &loginWindow{expiresAt: now.Add(loginFailureWindow)}
		limiter.windows[key] = window
	}
	window.failures++
	if len(limiter.windows) > loginLimiterSweepThreshold {
		for address, tracked := range limiter.windows {
			if !now.Before(tracked.expiresAt) {
				delete(limiter.windows, address)
			}
		}
	}
}

func (limiter *loginLimiter) recordSuccess(request *http.Request) {
	if limiter == nil {
		return
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	delete(limiter.windows, loginLimiterKey(request))
}

// loginLimiterKey buckets by address only. The management plane is expected to
// be reached directly or through a trusted local reverse proxy, so forwarded
// headers are not consulted: honouring them would let a caller pick their own
// bucket and bypass the limit entirely.
func loginLimiterKey(request *http.Request) string {
	if request == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		return host
	}
	return request.RemoteAddr
}

func writeLoginRateLimited(writer http.ResponseWriter, retryAfter time.Duration) {
	writeRateLimited(writer, retryAfter, "too many failed sign-in attempts, try again later")
}

// writeBearerRateLimited answers a bearer request from an address that sent
// too many wrong tokens. The code matches the sign-in limiter so clients
// handle both the same way.
func writeBearerRateLimited(writer http.ResponseWriter, retryAfter time.Duration) {
	writeRateLimited(writer, retryAfter, "too many failed bearer tokens from this address, try again later")
}

func writeRateLimited(writer http.ResponseWriter, retryAfter time.Duration, message string) {
	seconds := int(retryAfter.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	writer.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeError(writer, http.StatusTooManyRequests, "too_many_requests", message)
}
