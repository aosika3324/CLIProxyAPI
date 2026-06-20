package auth

import (
	"context"
	"math/rand"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// antiBanSettings is an immutable snapshot of the anti-ban controls relevant to
// request dispatch. It is swapped atomically via SetAntiBanConfig so the hot path
// reads a single pointer without locking.
type antiBanSettings struct {
	enabled              bool
	maxConcurrentPerAuth int
	concurrencyWait      time.Duration
	jitterMin            time.Duration
	jitterMax            time.Duration
	minInterval          time.Duration
	requireProxy         bool
}

// antiBanState holds the package-level anti-ban runtime: the active settings and
// the per-auth gates (semaphore + last-dispatch clock). It is shared by every
// Manager because credential identity (auth.ID) is global.
type antiBanState struct {
	settings atomicSettings

	mu    sync.Mutex
	gates map[string]*antiBanGate
}

// atomicSettings is a tiny atomic holder for *antiBanSettings. A nil value means
// anti-ban is disabled.
type atomicSettings struct {
	mu sync.RWMutex
	v  *antiBanSettings
}

func (a *atomicSettings) load() *antiBanSettings {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.v
}

func (a *atomicSettings) store(v *antiBanSettings) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.v = v
}

// antiBanGate is the per-credential coordination point. The buffered channel acts
// as a counting semaphore; lastDispatch enforces minimum spacing between calls.
type antiBanGate struct {
	sem chan struct{}

	clockMu      sync.Mutex
	lastDispatch time.Time
}

var antiBan = &antiBanState{gates: make(map[string]*antiBanGate)}

// datacenterBlocked holds auth IDs that the egress IP self-check flagged as
// datacenter/hosting IPs while strict mode is on. It is runtime-only (never
// persisted) and consulted by the selector availability filter, mirroring the
// require-proxy mechanism.
var datacenterBlocked struct {
	mu  sync.RWMutex
	ids map[string]struct{}
}

// SetDatacenterBlockedAuths replaces the set of auth IDs blocked because their
// egress IP was detected as a datacenter/hosting IP. Passing nil or an empty
// slice clears the set. Safe for concurrent use.
func SetDatacenterBlockedAuths(ids []string) {
	datacenterBlocked.mu.Lock()
	defer datacenterBlocked.mu.Unlock()
	if len(ids) == 0 {
		datacenterBlocked.ids = nil
		return
	}
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	datacenterBlocked.ids = set
}

// antiBanDatacenterBlocked reports whether the given auth ID is currently blocked
// by the egress IP self-check strict mode.
func antiBanDatacenterBlocked(authID string) bool {
	if authID == "" {
		return false
	}
	datacenterBlocked.mu.RLock()
	defer datacenterBlocked.mu.RUnlock()
	_, ok := datacenterBlocked.ids[authID]
	return ok
}

// SetAntiBanConfig installs the active anti-ban dispatch settings. Passing values
// that disable every control (or enabled=false) reverts to upstream behavior.
// concurrencyWaitMS <= 0 waits indefinitely for a free slot (bounded only by ctx).
func SetAntiBanConfig(enabled bool, maxConcurrentPerAuth, concurrencyWaitMS, jitterMinMS, jitterMaxMS, minIntervalMS int, requireProxy bool) {
	if !enabled {
		antiBan.settings.store(nil)
		return
	}
	s := &antiBanSettings{
		enabled:              true,
		maxConcurrentPerAuth: maxConcurrentPerAuth,
		concurrencyWait:      time.Duration(concurrencyWaitMS) * time.Millisecond,
		jitterMin:            time.Duration(jitterMinMS) * time.Millisecond,
		jitterMax:            time.Duration(jitterMaxMS) * time.Millisecond,
		minInterval:          time.Duration(minIntervalMS) * time.Millisecond,
		requireProxy:         requireProxy,
	}
	antiBan.settings.store(s)
}

// antiBanRequireProxy reports whether credentials must carry a per-auth proxy to be
// eligible for selection. Consulted by the selector availability filter.
func antiBanRequireProxy() bool {
	s := antiBan.settings.load()
	return s != nil && s.enabled && s.requireProxy
}

// gateFor returns (creating if needed) the gate for an auth ID, sized to the
// current concurrency limit. If the limit changed since the gate was created the
// semaphore is rebuilt; in-flight holders drain naturally against the old channel
// because release closes over the channel it acquired.
func (st *antiBanState) gateFor(id string, limit int) *antiBanGate {
	st.mu.Lock()
	defer st.mu.Unlock()
	g, ok := st.gates[id]
	if !ok {
		g = &antiBanGate{}
		if limit > 0 {
			g.sem = make(chan struct{}, limit)
		}
		st.gates[id] = g
		return g
	}
	// Resize the semaphore when the configured limit changes.
	if limit > 0 && (g.sem == nil || cap(g.sem) != limit) {
		g.sem = make(chan struct{}, limit)
	} else if limit <= 0 {
		g.sem = nil
	}
	return g
}

// antiBanRelease is returned by acquireAntiBanSlot and must be called exactly once
// after the request completes (or its stream drains). It is always non-nil.
type antiBanRelease func()

// acquireAntiBanSlot applies the anti-ban dispatch controls for the given auth:
//  1. block until a per-auth concurrency slot is free (or ctx/timeout fires),
//  2. wait out the larger of remaining min-interval spacing and a random jitter.
//
// It returns a release function (never nil) and an error only if the context was
// cancelled or the concurrency wait timed out. When anti-ban is disabled the
// release is a no-op and no waiting occurs.
func acquireAntiBanSlot(ctx context.Context, authID string) (antiBanRelease, error) {
	s := antiBan.settings.load()
	if s == nil || !s.enabled || authID == "" {
		return func() {}, nil
	}

	g := antiBan.gateFor(authID, s.maxConcurrentPerAuth)

	// Step 1: concurrency slot.
	release := antiBanRelease(func() {})
	if g.sem != nil {
		if err := acquireSem(ctx, g.sem, s.concurrencyWait); err != nil {
			return func() {}, err
		}
		sem := g.sem
		release = func() {
			select {
			case <-sem:
			default:
			}
		}
	}

	// Step 2: spacing + jitter. On cancellation, release the slot we hold.
	if wait := g.nextWait(s); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			release()
			return func() {}, ctx.Err()
		}
	}
	g.markDispatch()
	return release, nil
}

// acquireSem takes one slot from sem, honoring ctx and an optional wait timeout.
// wait <= 0 blocks until a slot frees or ctx is done.
func acquireSem(ctx context.Context, sem chan struct{}, wait time.Duration) error {
	// Fast path: a slot is immediately available.
	select {
	case sem <- struct{}{}:
		return nil
	default:
	}
	if wait <= 0 {
		select {
		case sem <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

// nextWait computes the pre-dispatch delay combining min-interval spacing (time
// still owed since the previous dispatch) and a random jitter in [min, max].
func (g *antiBanGate) nextWait(s *antiBanSettings) time.Duration {
	var spacing time.Duration
	if s.minInterval > 0 {
		g.clockMu.Lock()
		last := g.lastDispatch
		g.clockMu.Unlock()
		if !last.IsZero() {
			if elapsed := time.Since(last); elapsed < s.minInterval {
				spacing = s.minInterval - elapsed
			}
		}
	}
	jitter := randomJitter(s.jitterMin, s.jitterMax)
	if spacing > jitter {
		return spacing
	}
	return jitter
}

func (g *antiBanGate) markDispatch() {
	g.clockMu.Lock()
	g.lastDispatch = time.Now()
	g.clockMu.Unlock()
}

// randomJitter returns a random duration in [min, max]. When max <= 0 it returns
// 0. A non-positive min is treated as 0.
func randomJitter(min, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	if min < 0 {
		min = 0
	}
	if min >= max {
		return min
	}
	span := int64(max - min)
	return min + time.Duration(rand.Int63n(span+1))
}

// wrapStreamReleaseOnDrain returns a StreamResult whose chunk channel forwards
// every chunk and invokes release exactly once when the upstream channel closes
// (or the context is cancelled). This keeps a per-auth concurrency slot held for
// the full lifetime of a streaming response, not just until ExecuteStream returns.
func wrapStreamReleaseOnDrain(ctx context.Context, result *cliproxyexecutor.StreamResult, release antiBanRelease) *cliproxyexecutor.StreamResult {
	if result == nil {
		release()
		return result
	}
	if release == nil {
		return result
	}
	src := result.Chunks
	if src == nil {
		release()
		return result
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		var once sync.Once
		done := func() { once.Do(release) }
		defer done()
		defer close(out)
		for {
			select {
			case chunk, ok := <-src:
				if !ok {
					return
				}
				select {
				case out <- chunk:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: out}
}
