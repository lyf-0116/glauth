package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/GeertJohan/yubigo"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

type bindTestHandler struct {
	backend config.Backend
	cfg     config.Config
	log     zerolog.Logger
	user    config.User
}

func (h *bindTestHandler) GetBackend() config.Backend { return h.backend }
func (h *bindTestHandler) GetLog() *zerolog.Logger    { return &h.log }
func (h *bindTestHandler) GetCfg() *config.Config     { return &h.cfg }
func (h *bindTestHandler) GetYubikeyAuth() *yubigo.YubiAuth {
	return nil
}

func (h *bindTestHandler) FindUser(_ context.Context, userName string, _ bool) (bool, config.User, error) {
	if userName == h.user.Name {
		return true, h.user, nil
	}
	return false, config.User{}, nil
}

func (h *bindTestHandler) FindGroup(context.Context, string) (bool, config.Group, error) {
	return false, config.Group{}, nil
}

func (h *bindTestHandler) FindPosixAccounts(context.Context, string) ([]*ldap.Entry, error) {
	return nil, nil
}

func (h *bindTestHandler) FindPosixGroups(context.Context, string) ([]*ldap.Entry, error) {
	return nil, nil
}

func sha256Password(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

type updatingBindTestHandler struct {
	*bindTestHandler
	updateErr   error
	updatedHash string
}

func (h *updatingBindTestHandler) UpdatePasswordHash(_ context.Context, _ config.User, passwordHash string) error {
	if h.updateErr != nil {
		return h.updateErr
	}
	h.updatedHash = passwordHash
	h.bindTestHandler.user.PassSHA256 = passwordHash
	return nil
}

func bindTestConnection(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	return conn, peer
}

func TestLDAPOpsHelperBindRejectsUnauthenticatedAndPasswordlessBinds(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		user       config.User
		wantResult ldap.LDAPResultCode
	}{
		{
			name:       "named empty password is unauthenticated bind",
			password:   "",
			wantResult: ldap.LDAPResultUnwillingToPerform,
		},
		{
			name:       "arbitrary password without verifier",
			password:   "definitely-wrong",
			wantResult: ldap.LDAPResultInvalidCredentials,
		},
		{
			name: "failed app password does not fall through",
			user: config.User{
				Name:          "nopass",
				PassAppSHA256: []string{sha256Password("expected")},
			},
			password:   "definitely-wrong",
			wantResult: ldap.LDAPResultInvalidCredentials,
		},
		{
			name: "matching primary password succeeds",
			user: config.User{
				Name:       "nopass",
				PassSHA256: sha256Password("correct"),
			},
			password:   "correct",
			wantResult: ldap.LDAPResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.user
			if user.Name == "" {
				user.Name = "nopass"
			}
			h := &bindTestHandler{
				backend: config.Backend{
					BaseDN:             "dc=glauth,dc=com",
					NameFormatAsArray:  []string{"cn"},
					GroupFormatAsArray: []string{"ou"},
				},
				user: user,
				log:  zerolog.Nop(),
			}
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()

			helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))
			got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", tt.password, conn)
			if err != nil {
				t.Fatalf("Bind returned error: %v", err)
			}
			if got != tt.wantResult {
				t.Fatalf("Bind result = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestSHA256PasswordVerificationSupportsLegacyAndSaltedHashes(t *testing.T) {
	legacy := sha256Password("correct")
	if matches, isLegacy := verifySHA256Password(legacy, "correct"); !matches || !isLegacy {
		t.Fatalf("legacy hash verification = (%v, %v), want (true, true)", matches, isLegacy)
	}
	if matches, _ := verifySHA256Password(legacy, "wrong"); matches {
		t.Fatal("legacy hash accepted the wrong password")
	}

	first, err := newSaltedSHA256Hash("correct")
	if err != nil {
		t.Fatalf("newSaltedSHA256Hash returned error: %v", err)
	}
	second, err := newSaltedSHA256Hash("correct")
	if err != nil {
		t.Fatalf("newSaltedSHA256Hash returned error: %v", err)
	}
	if !strings.HasPrefix(first, saltedSHA256Prefix) {
		t.Fatalf("salted hash %q does not carry the format marker", first)
	}
	if first == second {
		t.Fatal("two salted hashes of the same password are identical")
	}
	if matches, isLegacy := verifySHA256Password(first, "correct"); !matches || isLegacy {
		t.Fatalf("salted hash verification = (%v, %v), want (true, false)", matches, isLegacy)
	}
	if matches, _ := verifySHA256Password(first, "wrong"); matches {
		t.Fatal("salted hash accepted the wrong password")
	}
}

func TestLDAPOpsHelperBindUpgradesLegacySHA256(t *testing.T) {
	h := &updatingBindTestHandler{
		bindTestHandler: &bindTestHandler{
			backend: config.Backend{
				BaseDN:             "dc=glauth,dc=com",
				NameFormatAsArray:  []string{"cn"},
				GroupFormatAsArray: []string{"ou"},
			},
			user: config.User{
				Name:       "nopass",
				PassSHA256: sha256Password("correct"),
			},
			log: zerolog.Nop(),
		},
	}
	conn, peer := bindTestConnection(t)

	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))
	got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", "correct", conn)
	if err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	if got != ldap.LDAPResultSuccess {
		t.Fatalf("Bind result = %v, want %v", got, ldap.LDAPResultSuccess)
	}
	if h.updatedHash == "" || !strings.HasPrefix(h.updatedHash, saltedSHA256Prefix) {
		t.Fatalf("stored hash was not upgraded: %q", h.updatedHash)
	}
	if matches, legacy := verifySHA256Password(h.updatedHash, "correct"); !matches || legacy {
		t.Fatalf("upgraded hash verification = (%v, %v), want (true, false)", matches, legacy)
	}
	peer.Close()
}

func TestLDAPOpsHelperBindIgnoresPasswordHashUpgradeFailure(t *testing.T) {
	h := &updatingBindTestHandler{
		bindTestHandler: &bindTestHandler{
			backend: config.Backend{
				BaseDN:             "dc=glauth,dc=com",
				NameFormatAsArray:  []string{"cn"},
				GroupFormatAsArray: []string{"ou"},
			},
			user: config.User{
				Name:       "nopass",
				PassSHA256: sha256Password("correct"),
			},
			log: zerolog.Nop(),
		},
		updateErr: errors.New("storage unavailable"),
	}
	conn, peer := bindTestConnection(t)

	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))
	got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", "correct", conn)
	if err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	if got != ldap.LDAPResultSuccess {
		t.Fatalf("Bind result = %v, want success despite upgrade failure", got)
	}
	peer.Close()
}

func TestConfigHandlerBindPersistsSaltedSHA256Upgrade(t *testing.T) {
	cfg := &config.Config{Users: []config.User{{
		Name:       "nopass",
		PassSHA256: sha256Password("correct"),
	}}}
	logger := zerolog.Nop()
	tracer := trace.NewNoopTracerProvider().Tracer("bind-test")
	h := configHandler{
		backend: config.Backend{
			BaseDN:             "dc=glauth,dc=com",
			NameFormatAsArray:  []string{"cn"},
			GroupFormatAsArray: []string{"ou"},
		},
		log:       &logger,
		cfg:       cfg,
		ldohelper: NewLDAPOpsHelper(tracer),
		monitor:   disabledBindTestMonitor{},
		tracer:    tracer,
	}
	conn, peer := bindTestConnection(t)

	got, err := h.Bind("cn=nopass,dc=glauth,dc=com", "correct", conn)
	if err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	if got != ldap.LDAPResultSuccess {
		t.Fatalf("Bind result = %v, want %v", got, ldap.LDAPResultSuccess)
	}
	if !strings.HasPrefix(cfg.Users[0].PassSHA256, saltedSHA256Prefix) {
		t.Fatalf("stored hash was not upgraded: %q", cfg.Users[0].PassSHA256)
	}
	if matches, legacy := verifySHA256Password(cfg.Users[0].PassSHA256, "correct"); !matches || legacy {
		t.Fatalf("upgraded stored hash verification = (%v, %v), want (true, false)", matches, legacy)
	}
	peer.Close()
}

func TestLDAPOpsHelperBindAppliesBackoffToBothPasswordFormats(t *testing.T) {
	rawBcrypt, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		hash string
		sha  bool
	}{
		{name: "bcrypt", hash: hex.EncodeToString(rawBcrypt)},
		{name: "sha256", hash: sha256Password("correct"), sha: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := config.User{Name: "nopass"}
			if tc.sha {
				user.PassSHA256 = tc.hash
			} else {
				user.PassBcrypt = tc.hash
			}
			h := &bindTestHandler{
				backend: config.Backend{
					BaseDN:             "dc=glauth,dc=com",
					NameFormatAsArray:  []string{"cn"},
					GroupFormatAsArray: []string{"ou"},
				},
				cfg: config.Config{Behaviors: config.Behaviors{
					LimitFailedBinds:    true,
					NumberOfFailedBinds: 2,
					PeriodOfFailedBinds: 30,
					BlockFailedBindsFor: 60,
				}},
				user: user,
				log:  zerolog.Nop(),
			}
			conn, peer := bindTestConnection(t)
			helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))

			for i := 0; i < 2; i++ {
				got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", "wrong", conn)
				if err != nil {
					t.Fatalf("failed Bind returned error: %v", err)
				}
				if got != ldap.LDAPResultInvalidCredentials {
					t.Fatalf("failed Bind result = %v, want invalid credentials", got)
				}
			}
			got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", "correct", conn)
			if err != nil {
				t.Fatalf("blocked Bind returned error: %v", err)
			}
			if got != ldap.LDAPResultUnwillingToPerform {
				t.Fatalf("blocked Bind result = %v, want unwilling to perform", got)
			}
			peer.Close()
		})
	}
}

func TestLDAPOpsHelperBindSuccessResetsFailureWindow(t *testing.T) {
	h := &bindTestHandler{
		backend: config.Backend{
			BaseDN:             "dc=glauth,dc=com",
			NameFormatAsArray:  []string{"cn"},
			GroupFormatAsArray: []string{"ou"},
		},
		cfg: config.Config{Behaviors: config.Behaviors{
			LimitFailedBinds:    true,
			NumberOfFailedBinds: 2,
			PeriodOfFailedBinds: 30,
			BlockFailedBindsFor: 60,
		}},
		user: config.User{
			Name:       "nopass",
			PassSHA256: sha256Password("correct"),
		},
		log: zerolog.Nop(),
	}
	conn, peer := bindTestConnection(t)
	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))

	for _, password := range []string{"wrong", "correct", "wrong"} {
		got, err := helper.Bind(context.Background(), h, "cn=nopass,dc=glauth,dc=com", password, conn)
		if err != nil {
			t.Fatalf("Bind(%q) returned error: %v", password, err)
		}
		if password == "correct" {
			if got != ldap.LDAPResultSuccess {
				t.Fatalf("Bind(%q) result = %v, want success", password, got)
			}
			continue
		}
		if got != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("Bind(%q) result = %v, want invalid credentials", password, got)
		}
	}
	peer.Close()
}

func TestLDAPOpsHelperBindAllowsAnonymousBind(t *testing.T) {
	h := &bindTestHandler{
		backend: config.Backend{BaseDN: "dc=glauth,dc=com"},
		log:     zerolog.Nop(),
	}
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-test"))
	got, err := helper.Bind(context.Background(), h, "", "", conn)
	if err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	if got != ldap.LDAPResultSuccess {
		t.Fatalf("Bind result = %v, want %v", got, ldap.LDAPResultSuccess)
	}
}
