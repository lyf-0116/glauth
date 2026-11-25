package toml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair creates a valid self-signed certificate/key pair and returns
// their on-disk paths.
func writeKeyPair(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "glauth test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(dir, "glauth.crt")
	keyPath := filepath.Join(dir, "glauth.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	certPath, keyPath := writeKeyPair(t)
	dir := filepath.Dir(certPath)
	cfgPath := filepath.Join(dir, "glauth.cfg")
	content := "[ldaps]\nenabled = true\nlisten = \"0.0.0.0:636\"\ncert = \"" + certPath + "\"\nkey = \"" + keyPath + "\"\n" + body
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestNewConfigDefaultsMinVersion(t *testing.T) {
	cfgPath := writeConfig(t, "")
	cfg, err := NewConfig(true, cfgPath, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TLS.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %#x, want TLS 1.2 default", cfg.TLS.MinVersion)
	}
}

func TestNewConfigParsesMinVersion(t *testing.T) {
	cfgPath := writeConfig(t, "[tls]\nminversion = 772\n")
	cfg, err := NewConfig(true, cfgPath, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TLS.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want TLS 1.3 (%#x)", cfg.TLS.MinVersion, tls.VersionTLS13)
	}
}

func TestNewConfigRejectsLegacyMinVersion(t *testing.T) {
	cfgPath := writeConfig(t, "[tls]\nminversion = 769\n")
	if _, err := NewConfig(true, cfgPath, map[string]interface{}{}); err == nil {
		t.Fatal("expected TLS 1.0 minimum to be rejected at load time")
	}
}
