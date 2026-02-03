package agent

import (
	"testing"
	"time"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Use t.Setenv with empty values to ensure clean state
	// t.Setenv automatically restores original values after test
	envVars := []string{
		"KIJO_DATABASE_PATH",
		"KIJO_POLL_INTERVAL",
		"KIJO_NAMESPACES",
		"KIJO_CLUSTER_NAME",
		"KIJO_SAAS_ENDPOINT",
		"KIJO_SAAS_API_KEY",
		"KIJO_LOG_FORMAT",
		"KIJO_LOG_LEVEL",
		"KIJO_HEALTH_ADDR",
	}
	for _, v := range envVars {
		t.Setenv(v, "")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"DatabasePath", cfg.DatabasePath, "/data/kijo.db"},
		{"PollInterval", cfg.PollInterval, 5 * time.Minute},
		{"LogFormat", cfg.LogFormat, "json"},
		{"LogLevel", cfg.LogLevel, "info"},
		{"HealthAddr", cfg.HealthAddr, ":8080"},
		{"Namespaces", len(cfg.Namespaces), 0},
		{"ClusterName", cfg.ClusterName, ""},
		{"SaasEndpoint", cfg.SaasEndpoint, ""},
		{"SaasApiKey", cfg.SaasApiKey, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestLoadConfig_WithEnvVars(t *testing.T) {
	// t.Setenv automatically cleans up after test
	t.Setenv("KIJO_DATABASE_PATH", "/custom/path/kijo.db")
	t.Setenv("KIJO_POLL_INTERVAL", "10m")
	t.Setenv("KIJO_NAMESPACES", "default, kube-system, monitoring")
	t.Setenv("KIJO_CLUSTER_NAME", "production-cluster")
	t.Setenv("KIJO_SAAS_ENDPOINT", "https://app.kijo.io")
	t.Setenv("KIJO_SAAS_API_KEY", "secret-api-key")
	t.Setenv("KIJO_LOG_FORMAT", "text")
	t.Setenv("KIJO_LOG_LEVEL", "debug")
	t.Setenv("KIJO_HEALTH_ADDR", ":9090")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v, want nil", err)
	}

	if cfg.DatabasePath != "/custom/path/kijo.db" {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, "/custom/path/kijo.db")
	}
	if cfg.PollInterval != 10*time.Minute {
		t.Errorf("PollInterval = %v, want %v", cfg.PollInterval, 10*time.Minute)
	}
	if cfg.ClusterName != "production-cluster" {
		t.Errorf("ClusterName = %q, want %q", cfg.ClusterName, "production-cluster")
	}
	if cfg.SaasEndpoint != "https://app.kijo.io" {
		t.Errorf("SaasEndpoint = %q, want %q", cfg.SaasEndpoint, "https://app.kijo.io")
	}
	if cfg.SaasApiKey != "secret-api-key" {
		t.Errorf("SaasApiKey = %q, want %q", cfg.SaasApiKey, "secret-api-key")
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want %q", cfg.LogFormat, "text")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.HealthAddr != ":9090" {
		t.Errorf("HealthAddr = %q, want %q", cfg.HealthAddr, ":9090")
	}

	// Verify namespaces are parsed and trimmed correctly
	expectedNS := []string{"default", "kube-system", "monitoring"}
	if len(cfg.Namespaces) != len(expectedNS) {
		t.Errorf("Namespaces length = %d, want %d", len(cfg.Namespaces), len(expectedNS))
	}
	for i, ns := range expectedNS {
		if i < len(cfg.Namespaces) && cfg.Namespaces[i] != ns {
			t.Errorf("Namespaces[%d] = %q, want %q", i, cfg.Namespaces[i], ns)
		}
	}
}

func TestLoadConfig_InvalidPollInterval(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"invalid format", "notaduration"},
		{"missing unit", "10"},
		{"empty number", "m"},
		{"negative without unit", "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KIJO_POLL_INTERVAL", tt.value)

			_, err := LoadConfig()
			if err == nil {
				t.Errorf("LoadConfig() with KIJO_POLL_INTERVAL=%q should return error", tt.value)
			}
		})
	}
}

func TestConfig_HasSaasEndpoint(t *testing.T) {
	tests := []struct {
		name         string
		saasEndpoint string
		saasApiKey   string
		want         bool
	}{
		{
			name:         "both endpoint and key present",
			saasEndpoint: "https://app.kijo.io",
			saasApiKey:   "secret-key",
			want:         true,
		},
		{
			name:         "only endpoint present",
			saasEndpoint: "https://app.kijo.io",
			saasApiKey:   "",
			want:         false,
		},
		{
			name:         "only key present",
			saasEndpoint: "",
			saasApiKey:   "secret-key",
			want:         false,
		},
		{
			name:         "neither present",
			saasEndpoint: "",
			saasApiKey:   "",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				SaasEndpoint: tt.saasEndpoint,
				SaasApiKey:   tt.saasApiKey,
			}
			if got := cfg.HasSaasEndpoint(); got != tt.want {
				t.Errorf("HasSaasEndpoint() = %v, want %v", got, tt.want)
			}
		})
	}
}
