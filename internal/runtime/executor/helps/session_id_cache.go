package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type sessionIDCacheEntry struct {
	value  string
	expire time.Time
}

var (
	sessionIDCache            = make(map[string]sessionIDCacheEntry)
	sessionIDCacheMu          sync.RWMutex
	sessionIDCacheCleanupOnce sync.Once
)

const (
	sessionIDTTL                = time.Hour
	sessionIDCacheCleanupPeriod = 15 * time.Minute
)

func startSessionIDCacheCleanup() {
	go func() {
		ticker := time.NewTicker(sessionIDCacheCleanupPeriod)
		defer ticker.Stop()
		for range ticker.C {
			purgeExpiredSessionIDs()
		}
	}()
}

func purgeExpiredSessionIDs() {
	now := time.Now()
	sessionIDCacheMu.Lock()
	for key, entry := range sessionIDCache {
		if !entry.expire.After(now) {
			delete(sessionIDCache, key)
		}
	}
	sessionIDCacheMu.Unlock()
}

func sessionIDCacheKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// openCodeSessionUUIDNamespace is a fixed namespace for deterministic UUID v5 generation
// from OpenCode session identifiers. Do not change: existing mappings depend on it.
var openCodeSessionUUIDNamespace = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("cliproxyapi.opencode.session"))

// StableSessionUUID maps an arbitrary session key to a deterministic UUID v5.
// Same input always produces the same UUID across restarts.
func StableSessionUUID(sessionKey string) string {
	return uuid.NewSHA1(openCodeSessionUUIDNamespace, []byte(sessionKey)).String()
}

// OpenCodeStableSessionUUID resolves a stable UUID from OpenCode request headers.
// Priority: X-Session-Affinity > X-Parent-Session-Id.
// Returns empty string when neither header is present.
func OpenCodeStableSessionUUID(headers http.Header) string {
	if headers == nil {
		return ""
	}
	if affinity := strings.TrimSpace(headers.Get("X-Session-Affinity")); affinity != "" {
		return StableSessionUUID(affinity)
	}
	if parent := strings.TrimSpace(headers.Get("X-Parent-Session-Id")); parent != "" {
		return StableSessionUUID(parent)
	}
	return ""
}

// CachedSessionID returns a stable session UUID per apiKey, refreshing the TTL on each access.
func CachedSessionID(apiKey string) string {
	if apiKey == "" {
		return uuid.New().String()
	}

	sessionIDCacheCleanupOnce.Do(startSessionIDCacheCleanup)

	key := sessionIDCacheKey(apiKey)
	now := time.Now()

	sessionIDCacheMu.RLock()
	entry, ok := sessionIDCache[key]
	valid := ok && entry.value != "" && entry.expire.After(now)
	sessionIDCacheMu.RUnlock()
	if valid {
		sessionIDCacheMu.Lock()
		entry = sessionIDCache[key]
		if entry.value != "" && entry.expire.After(now) {
			entry.expire = now.Add(sessionIDTTL)
			sessionIDCache[key] = entry
			sessionIDCacheMu.Unlock()
			return entry.value
		}
		sessionIDCacheMu.Unlock()
	}

	newID := uuid.New().String()

	sessionIDCacheMu.Lock()
	entry, ok = sessionIDCache[key]
	if !ok || entry.value == "" || !entry.expire.After(now) {
		entry.value = newID
	}
	entry.expire = now.Add(sessionIDTTL)
	sessionIDCache[key] = entry
	sessionIDCacheMu.Unlock()
	return entry.value
}
