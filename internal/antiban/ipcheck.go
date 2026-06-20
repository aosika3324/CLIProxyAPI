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
	lister   AuthLister
	getCfg   func() *config.Config
	setBlock BlockSetter
}

// NewChecker builds a checker. lister enumerates credentials, getCfg returns the
// live config (so hot-reloads take effect), and setBlock installs strict-mode
// blocks (may be nil to disable strict enforcement).
func NewChecker(lister AuthLister, getCfg func() *config.Config, setBlock BlockSetter) *Checker {
	return &Checker{lister: lister, getCfg: getCfg, setBlock: setBlock}
}

// Start launches the self-check. It runs once immediately, then on the configured
// interval (if any). It returns immediately; the loop stops when ctx is cancelled.
func (c *Checker) Start(ctx context.Context) {
	if c == nil || c.lister == nil || c.getCfg == nil {
		return
	}
	cfg := c.getCfg()
	if cfg == nil || !cfg.AntiBan.Enabled || !cfg.AntiBan.IPCheck.Enabled {
		return
	}
	go c.loop(ctx)
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
		return
	}
	settings := cfg.AntiBan.IPCheck
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultIPCheckTimeout
	}

	auths := c.lister()
	findings := make([]egressFinding, 0, len(auths))
	for _, a := range auths {
		if !strings.EqualFold(strings.TrimSpace(a.Provider), "claude") {
			continue
		}
		proxyURL := strings.TrimSpace(a.ProxyURL)
		name := authDisplayName(a)
		if proxyURL == "" {
			// Without a proxy the egress is the server's bare IP; require-proxy
			// (a separate control) handles eligibility. Here we just note it.
			log.Warnf("anti-ban ip-check: credential %s has no proxy-url; egress would use the server IP", name)
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

	for _, f := range findings {
		if f.err != nil {
			log.Warnf("anti-ban ip-check: credential %s egress lookup failed: %v", f.label, f.err)
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

	if c.setBlock != nil && settings.StrictDatacenter {
		sort.Strings(datacenterIDs)
		c.setBlock(datacenterIDs)
		if len(datacenterIDs) > 0 {
			log.Warnf("anti-ban ip-check: %d credential(s) held out of rotation due to datacenter egress IPs", len(datacenterIDs))
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

// lookupEgress resolves the egress IP and reputation by querying public databases
// through the credential's proxy. It tries ipapi.is first (richest signal), then
// falls back to ip-api.com and ipinfo.io. Any single source that flags datacenter
// or hosting is treated as authoritative.
func lookupEgress(ctx context.Context, proxyURL string, timeout time.Duration) (ipResult, error) {
	transport, mode, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		return ipResult{}, fmt.Errorf("build proxy transport: %w", errBuild)
	}
	if mode != proxyutil.ModeProxy || transport == nil {
		return ipResult{}, fmt.Errorf("proxy-url %q did not resolve to a usable proxy", proxyutil.Redact(proxyURL))
	}
	client := &http.Client{Transport: transport, Timeout: timeout}

	// ipapi.is: is_datacenter / company / asn fields.
	if r, ok := queryIPApiIs(ctx, client); ok {
		return r, nil
	}
	// ip-api.com: hosting flag + isp.
	if r, ok := queryIPApiCom(ctx, client); ok {
		return r, nil
	}
	// ipinfo.io: org/hostname (weaker signal, last resort).
	if r, ok := queryIPInfo(ctx, client); ok {
		return r, nil
	}
	return ipResult{}, fmt.Errorf("all egress IP reputation lookups failed")
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
	// Request the hosting/proxy fields explicitly via the fields bitmask.
	if !fetchJSON(ctx, client, "http://ip-api.com/json/?fields=status,query,isp,org,hosting,proxy", &payload) || payload.Query == "" {
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
	// ipinfo gives no explicit datacenter flag; flag obvious hosting hostnames.
	host := strings.ToLower(payload.Hostname)
	suspect := strings.Contains(host, "datacenter") || strings.Contains(host, "hosting") || strings.Contains(host, "cloud")
	return ipResult{
		ip:           payload.IP,
		isDatacenter: suspect,
		isp:          payload.Org,
		hostname:     payload.Hostname,
		source:       "ipinfo.io",
	}, true
}
