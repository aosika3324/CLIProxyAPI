package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// resetAntiBan restores global anti-ban state between tests.
func resetAntiBan() {
	antiBan.settings.store(nil)
	antiBan.mu.Lock()
	antiBan.gates = make(map[string]*antiBanGate)
	antiBan.mu.Unlock()
	SetDatacenterBlockedAuths(nil)
}

func TestAcquireAntiBanSlotDisabledIsNoop(t *testing.T) {
	resetAntiBan()
	release, err := acquireAntiBanSlot(context.Background(), "auth-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if release == nil {
		t.Fatal("release must never be nil")
	}
	release() // must not panic
}

func TestAcquireAntiBanSlotLimitsConcurrency(t *testing.T) {
	resetAntiBan()
	// Limit 1, no wait timeout, no jitter.
	SetAntiBanConfig(true, 1, 0, 0, 0, 0, false)
	defer resetAntiBan()

	rel1, err := acquireAntiBanSlot(context.Background(), "auth-1")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// Second acquire on same auth must block until rel1 is called.
	var acquired atomic.Bool
	var rel2 antiBanRelease
	done := make(chan struct{})
	go func() {
		r, errAcq := acquireAntiBanSlot(context.Background(), "auth-1")
		if errAcq == nil {
			acquired.Store(true)
			rel2 = r
		}
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	if acquired.Load() {
		t.Fatal("second acquire should still be blocked while slot held")
	}
	rel1()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("second acquire did not proceed after release")
	}
	if !acquired.Load() {
		t.Fatal("second acquire should have succeeded after release")
	}
	if rel2 != nil {
		rel2()
	}
}

func TestAcquireAntiBanSlotDifferentAuthsIndependent(t *testing.T) {
	resetAntiBan()
	SetAntiBanConfig(true, 1, 0, 0, 0, 0, false)
	defer resetAntiBan()

	rel1, err := acquireAntiBanSlot(context.Background(), "auth-1")
	if err != nil {
		t.Fatalf("acquire auth-1 failed: %v", err)
	}
	defer rel1()

	// A different auth has its own slot and must not block.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	rel2, err := acquireAntiBanSlot(ctx, "auth-2")
	if err != nil {
		t.Fatalf("acquire auth-2 should not block: %v", err)
	}
	rel2()
}

func TestAcquireAntiBanSlotWaitTimeout(t *testing.T) {
	resetAntiBan()
	// Limit 1, 30ms wait timeout.
	SetAntiBanConfig(true, 1, 30, 0, 0, 0, false)
	defer resetAntiBan()

	rel1, err := acquireAntiBanSlot(context.Background(), "auth-1")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	defer rel1()

	_, err = acquireAntiBanSlot(context.Background(), "auth-1")
	if err == nil {
		t.Fatal("expected timeout error when slot unavailable past wait window")
	}
}

func TestAcquireAntiBanSlotContextCancel(t *testing.T) {
	resetAntiBan()
	SetAntiBanConfig(true, 1, 0, 0, 0, 0, false)
	defer resetAntiBan()

	rel1, err := acquireAntiBanSlot(context.Background(), "auth-1")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}
	defer rel1()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, err = acquireAntiBanSlot(ctx, "auth-1")
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestRandomJitterBounds(t *testing.T) {
	if d := randomJitter(0, 0); d != 0 {
		t.Fatalf("zero max should give 0, got %v", d)
	}
	min := 10 * time.Millisecond
	max := 20 * time.Millisecond
	for i := 0; i < 200; i++ {
		d := randomJitter(min, max)
		if d < min || d > max {
			t.Fatalf("jitter %v out of [%v,%v]", d, min, max)
		}
	}
	if d := randomJitter(30*time.Millisecond, 10*time.Millisecond); d != 30*time.Millisecond {
		t.Fatalf("min>=max should return min, got %v", d)
	}
}

func TestAntiBanRequireProxy(t *testing.T) {
	resetAntiBan()
	defer resetAntiBan()
	if antiBanRequireProxy() {
		t.Fatal("require-proxy should be off when disabled")
	}
	SetAntiBanConfig(true, 0, 0, 0, 0, 0, true)
	if !antiBanRequireProxy() {
		t.Fatal("require-proxy should be on")
	}
	SetAntiBanConfig(false, 0, 0, 0, 0, 0, true)
	if antiBanRequireProxy() {
		t.Fatal("disabled anti-ban must override require-proxy")
	}
}

func TestDatacenterBlockedSet(t *testing.T) {
	resetAntiBan()
	defer resetAntiBan()
	if antiBanDatacenterBlocked("a") {
		t.Fatal("should be empty initially")
	}
	SetDatacenterBlockedAuths([]string{"a", "b"})
	if !antiBanDatacenterBlocked("a") || !antiBanDatacenterBlocked("b") {
		t.Fatal("a and b should be blocked")
	}
	if antiBanDatacenterBlocked("c") {
		t.Fatal("c should not be blocked")
	}
	SetDatacenterBlockedAuths(nil)
	if antiBanDatacenterBlocked("a") {
		t.Fatal("clearing should unblock")
	}
}

func TestWrapStreamReleaseOnDrain(t *testing.T) {
	resetAntiBan()
	src := make(chan cliproxyexecutor.StreamChunk, 2)
	src <- cliproxyexecutor.StreamChunk{Payload: []byte("a")}
	src <- cliproxyexecutor.StreamChunk{Payload: []byte("b")}
	close(src)

	var released atomic.Int32
	var once sync.Once
	release := func() { once.Do(func() { released.Add(1) }) }

	result := &cliproxyexecutor.StreamResult{Chunks: src}
	wrapped := wrapStreamReleaseOnDrain(context.Background(), result, release)

	count := 0
	for range wrapped.Chunks {
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 chunks, got %d", count)
	}
	// Give the goroutine a moment to run its deferred release.
	time.Sleep(20 * time.Millisecond)
	if released.Load() != 1 {
		t.Fatalf("release should fire exactly once on drain, got %d", released.Load())
	}
}

func TestWrapStreamReleaseOnNilResult(t *testing.T) {
	var released atomic.Int32
	wrapStreamReleaseOnDrain(context.Background(), nil, func() { released.Add(1) })
	if released.Load() != 1 {
		t.Fatal("nil result should release immediately")
	}
}
