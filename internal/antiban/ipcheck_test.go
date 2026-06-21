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

func TestReportNonStrictClearsBlocks(t *testing.T) {
	blocked := []string{"prev"}
	c := &Checker{
		setBlock:   func(ids []string) { blocked = ids },
		getBlocked: func() []string { return blocked },
	}
	settings := config.AntiBanIPCheck{StrictDatacenter: false, WarnSharedEgress: true}

	findings := []egressFinding{
		{authID: "a1", label: "acc-1", result: ipResult{ip: "1.1.1.1", isDatacenter: true, source: "ipapi.is"}},
	}
	c.report(findings, settings)

	// In non-strict mode no credential is held out of rotation, and any prior
	// block is released (setBlock(nil)).
	if blocked != nil {
		t.Fatalf("non-strict mode must release blocks, got %v", blocked)
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

// TestRunOnceClearsBlocksWhenDisabled verifies that an ip-check pass running while
// the feature (or ip-check) is disabled releases any prior strict-mode blocks,
// rather than leaving credentials stranded.
func TestRunOnceClearsBlocksWhenDisabled(t *testing.T) {
	var blocked = []string{"stale"}
	c := NewChecker(
		func() []AuthSnapshot { return nil },
		func() *config.Config { return &config.Config{} }, // anti-ban disabled
		func(ids []string) { blocked = ids },
		func() []string { return blocked },
	)
	c.RunOnce(context.Background())
	if blocked != nil {
		t.Fatalf("disabled ip-check pass must clear blocks, got %v", blocked)
	}
}

// TestReportStrictOffReleasesBlocks verifies that a pass with strict mode off
// releases prior blocks instead of leaving them in place.
func TestReportStrictOffReleasesBlocks(t *testing.T) {
	var blocked = []string{"prev"}
	c := &Checker{
		setBlock:   func(ids []string) { blocked = ids },
		getBlocked: func() []string { return blocked },
	}
	// Strict off: even a datacenter finding must not block, and prior blocks clear.
	settings := config.AntiBanIPCheck{StrictDatacenter: false, WarnSharedEgress: true}
	findings := []egressFinding{
		{authID: "x", label: "acc-x", result: ipResult{ip: "1.1.1.1", isDatacenter: true, source: "ipapi.is"}},
	}
	c.report(findings, settings)
	if blocked != nil {
		t.Fatalf("strict-off pass must clear blocks, got %v", blocked)
	}
}
