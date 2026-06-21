// Package antiban implements the egress IP self-check for Claude anti-ban.
//
// Each Claude credential should leave through its own clean residential IP. This
// checker dials each credential's configured proxy out to public IP-reputation
// databases and verifies the egress IP is not a datacenter/hosting IP, then warns
// when several credentials share one egress IP (which Anthropic can read as account
// sharing). It is a diagnostic probe and never carries provider traffic, so the
// per-lookup timeouts here are intentional and allowed.
package antiban

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

const defaultIPCheckTimeout = 10 * time.Second

// AuthSnapshot is the minimal credential view the checker needs.
type AuthSnapshot struct {
	ID       string
	Label    string
	Provider string
	ProxyURL string
}

// AuthLister returns the current set of credentials to inspect.
type AuthLister func() []AuthSnapshot

// BlockSetter installs the set of auth IDs to hold out of rotation (strict mode).
// It is typically coreauth.SetDatacenterBlockedAuths.
type BlockSetter func(ids []string)

// BlockGetter returns the auth IDs currently held out of rotation by strict mode.
// It is typically coreauth.GetDatacenterBlockedAuths and lets the checker preserve
// existing blocks across a pass where a credential's lookup transiently fails.
type BlockGetter func() []string

// ipResult captures what the reputation lookups concluded for one egress IP.
type ipResult struct {
	ip           string
	isDatacenter bool
	isHosting    bool
	isp          string
	hostname     string
	source       string
}

// egressFinding is the per-credential outcome of a check pass.
type egressFinding struct {
	authID string
	label  string
	result ipResult
	err    error
}

// Checker runs egress IP self-checks on a schedule.
type Checker struct {
	lister     AuthLister
	getCfg     func() *config.Config
	setBlock   BlockSetter
	getBlocked BlockGetter

	// running guards the background loop so Start is idempotent and re-entrant:
	// it can be called repeatedly (startup + every hot reload) without spawning
	// duplicate loops, and will (re)start the loop after it has exited (one-shot
	// completed, or the feature was toggled off then on again).
	running atomic.Bool
}

// NewChecker builds a checker. lister enumerates credentials, getCfg returns the
// live config (so hot-reloads take effect), setBlock installs strict-mode blocks
// (may be nil to disable strict enforcement), and getBlocked returns the current
// block set so transient lookup failures preserve existing blocks (may be nil).
func NewChecker(lister AuthLister, getCfg func() *config.Config, setBlock BlockSetter, getBlocked BlockGetter) *Checker {
	return &Checker{lister: lister, getCfg: getCfg, setBlock: setBlock, getBlocked: getBlocked}
}

// Start launches the self-check loop if the feature is enabled and the loop is not
// already running. It is safe to call repeatedly (startup and on every config hot
// reload): a no-op while running or disabled, it (re)starts the loop when the
// feature has just been enabled or a previous one-shot pass has finished. The loop
// stops when ctx is cancelled, the feature is disabled, or a one-shot pass ends.
func (c *Checker) Start(ctx context.Context) {
	if c == nil || c.lister == nil || c.getCfg == nil {
		return
	}
	cfg := c.getCfg()
	if cfg == nil || !cfg.AntiBan.Enabled || !cfg.AntiBan.IPCheck.Enabled {
		return
	}
	if !c.running.CompareAndSwap(false, true) {
		return // already running
	}
	go func() {
		defer c.running.Store(false)
		c.loop(ctx)
	}()
}

func (c *Checker) loop(ctx context.Context) {
	c.RunOnce(ctx)
	for {
		cfg := c.getCfg()
		if cfg == nil || !cfg.AntiBan.Enabled || !cfg.AntiBan.IPCheck.Enabled {
			return
		}
		interval := time.Duration(cfg.AntiBan.IPCheck.IntervalMinutes) * time.Minute
		if interval <= 0 {
			return // one-shot
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		c.RunOnce(ctx)
	}
}

// RunOnce performs a single self-check pass over all eligible credentials.
func (c *Checker) RunOnce(ctx context.Context) {
	cfg := c.getCfg()
	if cfg == nil || !cfg.AntiBan.Enabled || !cfg.AntiBan.IPCheck.Enabled {
		// The self-check is off: release any credentials a prior pass had held out
		// of rotation, so disabling ip-check (while anti-ban stays on) cannot leave
		// accounts permanently blocked.
		if c.setBlock != nil {
			c.setBlock(nil)
		}
		return
	}
	settings := cfg.AntiBan.IPCheck
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultIPCheckTimeout
	}
	// Global proxy fallback, mirroring NewUtlsHTTPClient: real traffic uses
	// auth.ProxyURL when set, otherwise cfg.ProxyURL. The check must probe the
	// same effective egress or its verdict would not reflect reality.
	globalProxy := strings.TrimSpace(cfg.ProxyURL)

	auths := c.lister()
	findings := make([]egressFinding, 0, len(auths))
	for _, a := range auths {
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "claude") {
			continue
		}
		name := authDisplayName(a)
		// Effective egress = per-auth proxy, else global proxy (same precedence
		// as the request path). Only when BOTH are empty does traffic leave on the
		// server's bare IP.
		proxyURL := strings.TrimSpace(a.ProxyURL)
		if proxyURL == "" {
			proxyURL = globalProxy
		}
		if proxyURL == "" {
			log.Warnf("anti-ban ip-check: credential %s has no per-auth or global proxy-url; egress would use the server IP", name)
			continue
		}
		result, errCheck := lookupEgress(ctx, proxyURL, timeout)
		findings = append(findings, egressFinding{authID: a.ID, label: name, result: result, err: errCheck})
	}

	c.report(findings, settings)
}

// report logs warnings, detects shared egress IPs, and applies strict-mode blocks.
func (c *Checker) report(findings []egressFinding, settings config.AntiBanIPCheck) {
	var datacenterIDs []string
	ipToAuths := make(map[string][]string)

	// Seed of credentials already blocked from a prior pass. A credential is only
	// unblocked by a fresh confirmed-clean result; a transient lookup failure must
	// NOT silently restore a known datacenter-egress credential to rotation.
	var prevBlocked map[string]struct{}
	if settings.StrictDatacenter && c.getBlocked != nil {
		ids := c.getBlocked()
		if len(ids) > 0 {
			prevBlocked = make(map[string]struct{}, len(ids))
			for _, id := range ids {
				prevBlocked[id] = struct{}{}
			}
		}
	}

	for _, f := range findings {
		if f.err != nil {
			log.Warnf("anti-ban ip-check: credential %s egress lookup failed: %v", f.label, f.err)
			// Carry forward an existing block across the transient failure.
			if _, ok := prevBlocked[f.authID]; ok {
				datacenterIDs = append(datacenterIDs, f.authID)
				log.Warnf("anti-ban ip-check: credential %s stays blocked (prior datacenter detection retained across failed re-check)", f.label)
			}
			continue
		}
		r := f.result
		ispDesc := r.isp
		if ispDesc == "" {
			ispDesc = "unknown ISP"
		}
		if r.isDatacenter || r.isHosting {
			log.Warnf("anti-ban ip-check: credential %s egress IP %s looks like a datacenter/hosting IP (isp=%q hostname=%q source=%s) — high ban risk",
				f.label, r.ip, ispDesc, r.hostname, r.source)
			if settings.StrictDatacenter {
				datacenterIDs = append(datacenterIDs, f.authID)
			}
		} else {
			log.Infof("anti-ban ip-check: credential %s egress IP %s OK (isp=%q source=%s)", f.label, r.ip, ispDesc, r.source)
		}
		if r.ip != "" {
			ipToAuths[r.ip] = append(ipToAuths[r.ip], f.label)
		}
	}

	if settings.WarnSharedEgress {
		for ip, labels := range ipToAuths {
			if len(labels) > 1 {
				sort.Strings(labels)
				log.Warnf("anti-ban ip-check: egress IP %s is shared by %d credentials (%s) — Anthropic may read this as account sharing",
					ip, len(labels), strings.Join(labels, ", "))
			}
		}
	}

	if c.setBlock != nil {
		if settings.StrictDatacenter {
			sort.Strings(datacenterIDs)
			c.setBlock(datacenterIDs)
			if len(datacenterIDs) > 0 {
				log.Warnf("anti-ban ip-check: %d credential(s) held out of rotation due to datacenter egress IPs", len(datacenterIDs))
			}
		} else {
			// Strict mode is off this pass: release any credentials a prior strict
			// pass had blocked, so toggling strict off cannot strand accounts.
			c.setBlock(nil)
		}
	}
}

func authDisplayName(a AuthSnapshot) string {
	if strings.TrimSpace(a.Label) != "" {
		return a.Label
	}
	if strings.TrimSpace(a.ID) != "" {
		return a.ID
	}
	return "(unknown)"
}

// lookupEgress resolves the egress IP and reputation by cross-verifying across
// public databases through the credential's proxy, mirroring the deployment
// guide's "cross-verify across three databases" rule: query every reachable source
// and treat the IP as risky if ANY source flags it as datacenter/hosting. At least
// one source must respond or the lookup errors.
func lookupEgress(ctx context.Context, proxyURL string, timeout time.Duration) (ipResult, error) {
	transport, mode, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		return ipResult{}, fmt.Errorf("build proxy transport: %w", errBuild)
	}
	if mode != proxyutil.ModeProxy || transport == nil {
		return ipResult{}, fmt.Errorf("proxy-url %q did not resolve to a usable proxy", proxyutil.Redact(proxyURL))
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	sources := []func(context.Context, *http.Client) (ipResult, bool){
		queryIPApiIs,  // is_datacenter / company / asn
		queryIPApiCom, // hosting / proxy flag + isp
		queryIPInfo,   // org / hostname (weakest)
	}

	merged := ipResult{}
	got := false
	var contributing []string
	for _, q := range sources {
		r, ok := q(ctx, client)
		if !ok {
			continue
		}
		got = true
		contributing = append(contributing, r.source)
		if merged.ip == "" {
			merged.ip = r.ip
		}
		// OR the risk signals: any source flagging datacenter/hosting wins.
		merged.isDatacenter = merged.isDatacenter || r.isDatacenter
		merged.isHosting = merged.isHosting || r.isHosting
		// Prefer the first non-empty ISP/hostname for human-readable context.
		if merged.isp == "" {
			merged.isp = r.isp
		}
		if merged.hostname == "" {
			merged.hostname = r.hostname
		}
	}
	if !got {
		return ipResult{}, fmt.Errorf("all egress IP reputation lookups failed")
	}
	merged.source = strings.Join(contributing, "+")
	return merged, nil
}

func fetchJSON(ctx context.Context, client *http.Client, url string, out any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("anti-ban ip-check: close body for %s: %v", url, errClose)
		}
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	if errDecode := json.NewDecoder(resp.Body).Decode(out); errDecode != nil {
		return false
	}
	return true
}

func queryIPApiIs(ctx context.Context, client *http.Client) (ipResult, bool) {
	var payload struct {
		IP           string `json:"ip"`
		IsDatacenter bool   `json:"is_datacenter"`
		Company      struct {
			Name string `json:"name"`
		} `json:"company"`
		ASN struct {
			Org string `json:"org"`
		} `json:"asn"`
		Datacenter struct {
			Datacenter string `json:"datacenter"`
		} `json:"datacenter"`
	}
	if !fetchJSON(ctx, client, "https://api.ipapi.is/", &payload) || payload.IP == "" {
		return ipResult{}, false
	}
	isp := payload.ASN.Org
	if isp == "" {
		isp = payload.Company.Name
	}
	return ipResult{
		ip:           payload.IP,
		isDatacenter: payload.IsDatacenter || payload.Datacenter.Datacenter != "",
		isp:          isp,
		source:       "ipapi.is",
	}, true
}

func queryIPApiCom(ctx context.Context, client *http.Client) (ipResult, bool) {
	var payload struct {
		Status  string `json:"status"`
		Query   string `json:"query"`
		ISP     string `json:"isp"`
		Org     string `json:"org"`
		Hosting bool   `json:"hosting"`
		Proxy   bool   `json:"proxy"`
	}
	// Request the hosting/proxy fields explicitly. A failed query still echoes a
	// non-empty "query", so we must gate on status=="success" too — otherwise a
	// failure (missing hosting/proxy fields default to false) is read as a clean IP.
	if !fetchJSON(ctx, client, "https://ip-api.com/json/?fields=status,query,isp,org,hosting,proxy", &payload) || payload.Query == "" || payload.Status != "success" {
		return ipResult{}, false
	}
	isp := payload.ISP
	if isp == "" {
		isp = payload.Org
	}
	return ipResult{
		ip:        payload.Query,
		isHosting: payload.Hosting || payload.Proxy,
		isp:       isp,
		source:    "ip-api.com",
	}, true
}

func queryIPInfo(ctx context.Context, client *http.Client) (ipResult, bool) {
	var payload struct {
		IP       string `json:"ip"`
		Org      string `json:"org"`
		Hostname string `json:"hostname"`
	}
	if !fetchJSON(ctx, client, "https://ipinfo.io/json", &payload) || payload.IP == "" {
		return ipResult{}, false
	}
	// ipinfo gives no explicit datacenter flag; only flag unambiguous hosting
	// hostnames. "cloud" is deliberately excluded: it matches far too many
	// legitimate residential PTR records and provider names (icloud, cloudflare,
	// ISP "cloudnet" reverse DNS), and a single weak signal here would block a
	// clean IP in strict mode via the OR-merge. Authoritative datacenter/hosting
	// detection is left to ipapi.is and ip-api.com.
	host := strings.ToLower(payload.Hostname)
	suspect := strings.Contains(host, "datacenter") || strings.Contains(host, "hosting")
	return ipResult{
		ip:           payload.IP,
		isDatacenter: suspect,
		isp:          payload.Org,
		hostname:     payload.Hostname,
		source:       "ipinfo.io",
	}, true
}
