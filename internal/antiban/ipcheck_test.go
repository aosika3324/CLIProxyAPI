package antiban

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestReportFlagsDatacenterAndStrictBlocks(t *testing.T) {
	var blocked []string
	c := &Checker{
		setBlock: func(ids []string) { blocked = ids },
	}
	settings := config.AntiBanIPCheck{StrictDatacenter: true, WarnSharedEgress: true}

	findings := []egressFinding{
		{authID: "a1", label: "acc-1", result: ipResult{ip: "1.1.1.1", isDatacenter: true, source: "ipapi.is"}},
		{authID: "a2", label: "acc-2", result: ipResult{ip: "2.2.2.2", isp: "NTT America", source: "ip-api.com"}},
	}
	c.report(findings, settings)

	if len(blocked) != 1 || blocked[0] != "a1" {
		t.Fatalf("expected a1 blocked for datacenter egress, got %v", blocked)
	}
}

func TestReportNonStrictDoesNotBlock(t *testing.T) {
	var blocked []string
	called := false
	c := &Checker{
		setBlock: func(ids []string) { called = true; blocked = ids },
	}
	settings := config.AntiBanIPCheck{StrictDatacenter: false, WarnSharedEgress: true}

	findings := []egressFinding{
		{authID: "a1", label: "acc-1", result: ipResult{ip: "1.1.1.1", isDatacenter: true, source: "ipapi.is"}},
	}
	c.report(findings, settings)

	// In non-strict mode setBlock must not be invoked at all.
	if called {
		t.Fatalf("non-strict mode must not call setBlock, got %v", blocked)
	}
}

func TestReportSharedEgressDoesNotBlock(t *testing.T) {
	var blocked []string
	c := &Checker{setBlock: func(ids []string) { blocked = ids }}
	settings := config.AntiBanIPCheck{StrictDatacenter: true, WarnSharedEgress: true}

	// Two clean credentials sharing one egress IP: warned (logged) but not blocked.
	findings := []egressFinding{
		{authID: "a1", label: "acc-1", result: ipResult{ip: "9.9.9.9", isp: "NTT", source: "ipapi.is"}},
		{authID: "a2", label: "acc-2", result: ipResult{ip: "9.9.9.9", isp: "NTT", source: "ipapi.is"}},
	}
	c.report(findings, settings)

	if len(blocked) != 0 {
		t.Fatalf("shared clean egress must not block, got %v", blocked)
	}
}

func TestStartNoopWhenDisabled(t *testing.T) {
	c := NewChecker(
		func() []AuthSnapshot { return nil },
		func() *config.Config { return &config.Config{} }, // AntiBan zero value: disabled
		func(ids []string) {},
		func() []string { return nil },
	)
	// Should return immediately without spawning anything.
	c.Start(context.Background())
}

// TestReportPreservesBlockOnTransientFailure verifies the critical recovery rule:
// a credential blocked on a prior pass stays blocked when its re-check fails
// transiently (network error), instead of being silently restored to rotation.
func TestReportPreservesBlockOnTransientFailure(t *testing.T) {
	var blocked []string
	c := &Checker{
		setBlock:   func(ids []string) { blocked = ids },
		getBlocked: func() []string { return []string{"a1"} }, // a1 was blocked before
	}
	settings := config.AntiBanIPCheck{StrictDatacenter: true}

	// a1's re-check fails this pass; a2 confirms clean.
	findings := []egressFinding{
		{authID: "a1", label: "acc-1", err: context.DeadlineExceeded},
		{authID: "a2", label: "acc-2", result: ipResult{ip: "2.2.2.2", isp: "NTT", source: "ipapi.is"}},
	}
	c.report(findings, settings)

	if len(blocked) != 1 || blocked[0] != "a1" {
		t.Fatalf("a1 must stay blocked across a transient failure, got %v", blocked)
	}
}

// TestReportClearsBlockOnConfirmedClean verifies a credential IS unblocked when a
// fresh pass confirms its egress IP is clean.
func TestReportClearsBlockOnConfirmedClean(t *testing.T) {
	var blocked []string
	c := &Checker{
		setBlock:   func(ids []string) { blocked = ids },
		getBlocked: func() []string { return []string{"a1"} },
	}
	settings := config.AntiBanIPCheck{StrictDatacenter: true}

	// a1 now resolves to a clean residential IP.
	findings := []egressFinding{
		{authID: "a1", label: "acc-1", result: ipResult{ip: "3.3.3.3", isp: "Comcast", source: "ipapi.is"}},
	}
	c.report(findings, settings)

	if len(blocked) != 0 {
		t.Fatalf("a1 must be unblocked after a confirmed-clean check, got %v", blocked)
	}
}
