package config

import "testing"

func TestNormalizeAntiBanClampsNegatives(t *testing.T) {
	cfg := &Config{}
	cfg.AntiBan = AntiBan{
		Enabled:                  true,
		MaxConcurrentPerAuth:     -5,
		ConcurrencyWaitTimeoutMS: -1,
		JitterMinMS:              -3,
		JitterMaxMS:              -7,
		MinRequestIntervalMS:     -2,
		IPCheck: AntiBanIPCheck{
			IntervalMinutes: -10,
			TimeoutSeconds:  -4,
		},
	}
	cfg.NormalizeAntiBan()

	ab := cfg.AntiBan
	if ab.MaxConcurrentPerAuth != 0 || ab.ConcurrencyWaitTimeoutMS != 0 ||
		ab.JitterMinMS != 0 || ab.JitterMaxMS != 0 || ab.MinRequestIntervalMS != 0 {
		t.Fatalf("negatives should clamp to 0: %+v", ab)
	}
	if ab.IPCheck.IntervalMinutes != 0 || ab.IPCheck.TimeoutSeconds != 0 {
		t.Fatalf("negative ip-check values should clamp to 0: %+v", ab.IPCheck)
	}
}

func TestNormalizeAntiBanOrdersJitterWindow(t *testing.T) {
	cfg := &Config{}
	cfg.AntiBan = AntiBan{JitterMinMS: 500, JitterMaxMS: 100}
	cfg.NormalizeAntiBan()
	if cfg.AntiBan.JitterMinMS != 100 || cfg.AntiBan.JitterMaxMS != 500 {
		t.Fatalf("jitter window should be reordered to [100,500], got [%d,%d]",
			cfg.AntiBan.JitterMinMS, cfg.AntiBan.JitterMaxMS)
	}
}
