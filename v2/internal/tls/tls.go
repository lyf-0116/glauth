package tls

import (
	tls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/rs/zerolog"
)

var (
	log zerolog.Logger
)

var secureCipherSuites = []uint16{
	// TLS 1.3 cipher suites (automatically used when TLS 1.3 is negotiated)
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,

	// TLS 1.2 ECDHE cipher suites (Forward Secrecy)
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

	// Additional secure TLS 1.2 cipher suites (CBC with HMAC-SHA256)
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	// 	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
}

// supportedVersions is the inclusive range of TLS versions the
// configuration is allowed to select as a minimum. Go's crypto/tls supports
// SSL 3.0 through TLS 1.3, but anything below TLS 1.2 is considered broken,
// so the policy floor is TLS 1.2.
const (
	MinSupportedVersion = tls.VersionTLS12
	MaxSupportedVersion = tls.VersionTLS13
)

// DefaultMinVersion is the policy applied when no minimum version is
// configured. It is shared by every listener and every outbound connection,
// so the strength of a handshake no longer depends on the call site.
const DefaultMinVersion = tls.VersionTLS12

// Options carries everything needed to build a tls.Config through the single
// constructor, replacing the per-call-site tls.Config literals that used to
// drift apart.
type Options struct {
	// CertPEM and KeyPEM hold the listener certificate. They are required for
	// server-side configs (LDAP StartTLS / LDAPS) and ignored when empty on
	// client-side configs.
	CertPEM []byte
	KeyPEM  []byte
	// MinVersion is the lowest acceptable TLS version; a zero value falls
	// back to DefaultMinVersion.
	MinVersion uint16
	// InsecureSkipVerify disables certificate verification on outbound
	// connections and must never be set on a listener.
	InsecureSkipVerify bool
	// ServerName, when set, pins the SNI / verification name for outbound
	// connections. Leaving it empty keeps the standard library behaviour of
	// deriving the name from the dial address.
	ServerName string
}

// ValidateMinVersion rejects versions outside the supported range, mapping a
// zero value to the policy default so callers can always pass configured
// values straight through.
func ValidateMinVersion(version uint16) (uint16, error) {
	if version == 0 {
		return DefaultMinVersion, nil
	}
	if version < MinSupportedVersion || version > MaxSupportedVersion {
		return 0, fmt.Errorf("invalid tls min version %#x: must be between %s (%#x) and %s (%#x)",
			version, tls.VersionName(MinSupportedVersion), MinSupportedVersion,
			tls.VersionName(MaxSupportedVersion), MaxSupportedVersion)
	}
	return version, nil
}

// NewConfig is the single constructor for every tls.Config in the project.
// Listener configs provide a certificate/key pair; outbound client configs
// leave them empty. Both paths receive the same validated minimum version.
func NewConfig(opts Options) (*tls.Config, error) {
	minVersion, err := ValidateMinVersion(opts.MinVersion)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		MinVersion:         minVersion,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		ServerName:         opts.ServerName,
	}

	if len(opts.CertPEM) == 0 && len(opts.KeyPEM) == 0 {
		return config, nil
	}

	cert, err := tls.X509KeyPair(opts.CertPEM, opts.KeyPEM)
	if err != nil {
		return nil, err
	}

	log.Debug().Str("key", string(opts.KeyPEM))
	log.Debug().Str("client.certificate", string(opts.CertPEM))
	log.Debug().Interface("certificate", cert)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, err := x509.SystemCertPool()

	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		log.Warn().Err(err).Msg("Using empty cert-pool")
	} else {
		log.Info().Msg("Using system cert-pool")
	}

	for _, cert := range DecodePEM(opts.CertPEM).Certificate {
		x509Cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Error().Err(err).Msg("issue parsing cert PEM")
		}
		rootCAs.AddCert(x509Cert)
	}

	log.Debug().Interface("root.ca", rootCAs)
	log.Debug().Interface("certificates", []tls.Certificate{cert})

	config.RootCAs = rootCAs
	config.Certificates = []tls.Certificate{cert}
	config.PreferServerCipherSuites = true
	config.CipherSuites = secureCipherSuites

	return config, nil
}

// NewClientConfig builds the tls.Config for an outbound connection. It keeps
// the minimum-version policy in one place while preserving the caller's
// verification and SNI choices; an empty ServerName lets the standard
// library derive the name from the dial address.
func NewClientConfig(minVersion uint16, insecureSkipVerify bool, serverName string) (*tls.Config, error) {
	return NewConfig(Options{
		MinVersion:         minVersion,
		InsecureSkipVerify: insecureSkipVerify,
		ServerName:         serverName,
	})
}

// DecodePEM builds a PEM certificate object
func DecodePEM(certPEM []byte) tls.Certificate {
	var cert tls.Certificate
	var certDER *pem.Block
	for {
		certDER, certPEM = pem.Decode(certPEM)
		if certDER == nil {
			break
		}
		if certDER.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDER.Bytes)
		}
	}

	return cert
}

func CipherSuiteNames(suites []uint16) []string {
	var names []string
	for _, suite := range suites {
		names = append(names, tls.CipherSuiteName(suite))
	}
	return names
}
