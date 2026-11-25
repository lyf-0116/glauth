package tls

import (
	"crypto/tls"
	"testing"
)

func TestValidateMinVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   uint16
		want    uint16
		wantErr bool
	}{
		{"zero falls back to default", 0, DefaultMinVersion, false},
		{"tls 1.2 accepted", tls.VersionTLS12, tls.VersionTLS12, false},
		{"tls 1.3 accepted", tls.VersionTLS13, tls.VersionTLS13, false},
		{"tls 1.1 rejected", tls.VersionTLS11, 0, true},
		{"tls 1.0 rejected", tls.VersionTLS10, 0, true},
		{"ssl 3.0 rejected", tls.VersionSSL30, 0, true},
		{"value above tls 1.3 rejected", tls.VersionTLS13 + 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateMinVersion(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for version %#x, got none", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestNewClientConfigEnforcesMinVersion(t *testing.T) {
	cfg, err := NewClientConfig(tls.VersionTLS13, true, "upstream.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS13)
	}
	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("MaxVersion = %#x, want %#x", cfg.MaxVersion, tls.VersionTLS13)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify was not propagated")
	}
	if cfg.ServerName != "upstream.example" {
		t.Fatalf("ServerName = %q, want upstream.example", cfg.ServerName)
	}
}

func TestNewClientConfigEmptyServerNameKeepsDialDefault(t *testing.T) {
	cfg, err := NewClientConfig(0, false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MinVersion != DefaultMinVersion {
		t.Fatalf("MinVersion = %#x, want default %#x", cfg.MinVersion, DefaultMinVersion)
	}
	if cfg.ServerName != "" {
		t.Fatalf("ServerName = %q, want empty so tls.Dial derives it", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should default to false")
	}
}

func TestNewConfigWithoutCertReturnsClientConfig(t *testing.T) {
	cfg, err := NewConfig(Options{MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
	}
	if len(cfg.Certificates) != 0 {
		t.Fatalf("expected no certificates, got %d", len(cfg.Certificates))
	}
	if cfg.PreferServerCipherSuites {
		t.Fatal("PreferServerCipherSuites only makes sense on a listener")
	}
}

func TestNewConfigRejectsInvalidMinVersion(t *testing.T) {
	if _, err := NewConfig(Options{MinVersion: tls.VersionTLS10}); err == nil {
		t.Fatal("expected TLS 1.0 minimum to be rejected")
	}
}

func TestNewConfigRejectsBadKeyPair(t *testing.T) {
	if _, err := NewConfig(Options{
		CertPEM:    []byte("not a certificate"),
		KeyPEM:     []byte("not a key"),
		MinVersion: tls.VersionTLS12,
	}); err == nil {
		t.Fatal("expected malformed key pair to be rejected")
	}
}
