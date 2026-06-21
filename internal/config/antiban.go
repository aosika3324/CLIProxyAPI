// Package config provides configuration management for the CLI Proxy API server.
package config

import "strings"

// AntiBan groups Claude anti-ban controls that reduce the chance an account is
// flagged by Anthropic's risk system. The request-layer Claude Code fingerprint
// (Beta headers, billing header, User-Agent, session id) is always applied by the
// Claude executor; this block adds account-hygiene controls on top:
//
//   - per-account concurrency limiting (one terminal at a time semantics)
//   - request-rhythm jitter (avoid robotic, perfectly-spaced calls)
//   - account<->proxy hard binding (never egress on the server's bare IP)
//   - egress IP self-check (detect datacenter IPs and shared egress IPs)
//
// The whole block is opt-in: a zero value disables every control, preserving the
// upstream behavior.
type AntiBan struct {
	// Enabled turns the anti-ban controls on. When false, every field below is
	// ignored regardless of its value.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// MaxConcurrentPerAuth caps how many requests a single credential may have in
	// flight at once. <= 0 means unlimited. The document's red line "don't run
	// multiple claude processes at once" maps to a value of 1.
	MaxConcurrentPerAuth int `yaml:"max-concurrent-per-auth" json:"max-concurrent-per-auth"`

	// ConcurrencyWaitTimeoutMS bounds how long a request waits for a free slot when
	// MaxConcurrentPerAuth is reached. <= 0 waits indefinitely (until ctx is done).
	// This wait happens before any upstream connection is established, so it does
	// not violate the "no timeouts after connect" rule.
	ConcurrencyWaitTimeoutMS int `yaml:"concurrency-wait-timeout-ms" json:"concurrency-wait-timeout-ms"`

	// JitterMinMS and JitterMaxMS define an inclusive random pre-dispatch delay
	// applied before each upstream request, to break up robotic timing. When both
	// are <= 0 no jitter is applied. If only JitterMaxMS is set, the delay is in
	// [0, JitterMaxMS].
	JitterMinMS int `yaml:"jitter-min-ms" json:"jitter-min-ms"`
	JitterMaxMS int `yaml:"jitter-max-ms" json:"jitter-max-ms"`

	// MinRequestIntervalMS enforces a minimum spacing between two consecutive
	// dispatches on the same credential. <= 0 disables spacing. Spacing and jitter
	// stack: the larger of (spacing-remaining, jitter) is waited.
	MinRequestIntervalMS int `yaml:"min-request-interval-ms" json:"min-request-interval-ms"`

	// RequireProxy, when true, makes any Claude credential without a per-auth
	// proxy-url ineligible for selection, so a misconfigured account can never
	// leak the server's real IP. Other providers are unaffected.
	RequireProxy bool `yaml:"require-proxy" json:"require-proxy"`

	// IPCheck configures the egress IP self-check / collision detector.
	IPCheck AntiBanIPCheck `yaml:"ip-check" json:"ip-check"`
}

// AntiBanIPCheck configures the egress IP self-check that runs each credential's
// proxy through public IP-reputation databases and detects datacenter or shared
// egress IPs.
type AntiBanIPCheck struct {
	// Enabled turns the self-check on.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// IntervalMinutes re-runs the check on a timer. <= 0 runs it only once at
	// startup.
	IntervalMinutes int `yaml:"interval-minutes" json:"interval-minutes"`

	// TimeoutSeconds bounds each individual IP-reputation lookup. This is a
	// diagnostic probe that never carries provider traffic, so a timeout is
	// allowed here. <= 0 uses the default (10s).
	TimeoutSeconds int `yaml:"timeout-seconds" json:"timeout-seconds"`

	// StrictDatacenter, when true, marks a Claude credential unavailable if its
	// egress IP is detected as a datacenter/hosting IP (the deployment guide's
	// "datacenter IPs always get banned" rule). When false the result is only
	// logged as a warning.
	StrictDatacenter bool `yaml:"strict-datacenter" json:"strict-datacenter"`

	// WarnSharedEgress, when true (default when IPCheck.Enabled), logs a warning
	// when more than one credential resolves to the same egress IP (the deployment
	// guide's "one IP, many accounts = detected as account sharing" rule).
	WarnSharedEgress bool `yaml:"warn-shared-egress" json:"warn-shared-egress"`

	// WarnIPChange, when true (default when IPCheck.Enabled), logs a warning when a
	// credential's egress IP changes between checks (the deployment guide's
	// "frequent IP changes" / "the IP must not lapse" red lines: a residential user
	// does not hop IPs, so drift signals a proxy/renewal problem). Detection needs
	// IntervalMinutes > 0 to observe more than one sample.
	WarnIPChange bool `yaml:"warn-ip-change" json:"warn-ip-change"`

	// ExpectedCountry, when set to an ISO country code (e.g. "US"), warns whenever a
	// credential's egress IP resolves outside that country (the guide pins the exit
	// to a US residential IP). Empty disables the country check; a change of country
	// between checks is always warned when WarnIPChange is on.
	ExpectedCountry string `yaml:"expected-country" json:"expected-country"`
}

// NormalizeAntiBan clamps anti-ban values into sane ranges. It is safe to call on
// a zero value.
func (cfg *Config) NormalizeAntiBan() {
	ab := &cfg.AntiBan
	if ab.MaxConcurrentPerAuth < 0 {
		ab.MaxConcurrentPerAuth = 0
	}
	if ab.ConcurrencyWaitTimeoutMS < 0 {
		ab.ConcurrencyWaitTimeoutMS = 0
	}
	if ab.JitterMinMS < 0 {
		ab.JitterMinMS = 0
	}
	if ab.JitterMaxMS < 0 {
		ab.JitterMaxMS = 0
	}
	// Keep the jitter window ordered so callers can assume min <= max.
	if ab.JitterMaxMS > 0 && ab.JitterMinMS > ab.JitterMaxMS {
		ab.JitterMinMS, ab.JitterMaxMS = ab.JitterMaxMS, ab.JitterMinMS
	}
	if ab.MinRequestIntervalMS < 0 {
		ab.MinRequestIntervalMS = 0
	}
	if ab.IPCheck.IntervalMinutes < 0 {
		ab.IPCheck.IntervalMinutes = 0
	}
	if ab.IPCheck.TimeoutSeconds < 0 {
		ab.IPCheck.TimeoutSeconds = 0
	}
	// Normalize the expected country to an uppercase ISO code for comparison.
	ab.IPCheck.ExpectedCountry = strings.ToUpper(strings.TrimSpace(ab.IPCheck.ExpectedCountry))
}
