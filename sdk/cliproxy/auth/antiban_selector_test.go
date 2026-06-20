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

	a := &Auth{ID: "dc1", Provider: "claude", Status: StatusActive, ProxyURL: "socks5://127.0.0.1:7897"}
	if blocked, _, _ := isAuthBlockedForModel(a, "", time.Now()); blocked {
		t.Fatal("should not be blocked before datacenter flag")
	}
	SetDatacenterBlockedAuths([]string{"dc1"})
	if blocked, _, _ := isAuthBlockedForModel(a, "", time.Now()); !blocked {
		t.Fatal("should be blocked once datacenter flag is set")
	}
}
