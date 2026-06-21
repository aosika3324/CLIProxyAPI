package auth

import (
	"testing"
	"time"
)

func TestRequireProxyBlocksClaudeWithoutProxy(t *testing.T) {
	resetAntiBan()
	defer resetAntiBan()
	SetAntiBanConfig(true, 0, 0, 0, 0, 0, true)

	now := time.Now()

	noProxy := &Auth{ID: "c1", Provider: "claude", Status: StatusActive}
	blocked, reason, _ := isAuthBlockedForModel(noProxy, "", now)
	if !blocked || reason != blockReasonRequireProxy {
		t.Fatalf("claude without proxy should be blocked by require-proxy, got blocked=%v reason=%v", blocked, reason)
	}

	withProxy := &Auth{ID: "c2", Provider: "claude", Status: StatusActive, ProxyURL: "socks5://127.0.0.1:7897"}
	if blocked, _, _ := isAuthBlockedForModel(withProxy, "", now); blocked {
		t.Fatal("claude with proxy should not be blocked")
	}

	// Non-claude providers are unaffected by require-proxy.
	otherNoProxy := &Auth{ID: "g1", Provider: "gemini", Status: StatusActive}
	if blocked, _, _ := isAuthBlockedForModel(otherNoProxy, "", now); blocked {
		t.Fatal("non-claude provider must not be blocked by require-proxy")
	}
}

func TestDatacenterBlockedAuthIsBlocked(t *testing.T) {
	resetAntiBan()
	defer resetAntiBan()

	// Datacenter blocks only take effect while anti-ban is enabled.
	SetAntiBanConfig(true, 0, 0, 0, 0, 0, false)

	a := &Auth{ID: "dc1", Provider: "claude", Status: StatusActive, ProxyURL: "socks5://127.0.0.1:7897"}
	if blocked, _, _ := isAuthBlockedForModel(a, "", time.Now()); blocked {
		t.Fatal("should not be blocked before datacenter flag")
	}
	SetDatacenterBlockedAuths([]string{"dc1"})
	if blocked, _, _ := isAuthBlockedForModel(a, "", time.Now()); !blocked {
		t.Fatal("should be blocked once datacenter flag is set")
	}
}

// TestDisablingAntiBanReleasesDatacenterBlocks verifies that turning anti-ban off
// immediately frees credentials the strict self-check had held out of rotation,
// rather than stranding them until process restart.
func TestDisablingAntiBanReleasesDatacenterBlocks(t *testing.T) {
	resetAntiBan()
	defer resetAntiBan()

	SetAntiBanConfig(true, 0, 0, 0, 0, 0, false)
	SetDatacenterBlockedAuths([]string{"dc1"})

	a := &Auth{ID: "dc1", Provider: "claude", Status: StatusActive, ProxyURL: "socks5://127.0.0.1:7897"}
	if blocked, _, _ := isAuthBlockedForModel(a, "", time.Now()); !blocked {
		t.Fatal("precondition: dc1 should be blocked while enabled")
	}

	// Disabling anti-ban must release the block (both the read guard and the
	// SetAntiBanConfig(false) clear cover this).
	SetAntiBanConfig(false, 0, 0, 0, 0, 0, false)
	if blocked, _, _ := isAuthBlockedForModel(a, "", time.Now()); blocked {
		t.Fatal("dc1 must be released once anti-ban is disabled")
	}
	if got := GetDatacenterBlockedAuths(); len(got) != 0 {
		t.Fatalf("block set must be cleared on disable, got %v", got)
	}
}
