package handler

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

type bindLimitAddr string

func (a bindLimitAddr) Network() string { return "tcp" }
func (a bindLimitAddr) String() string  { return string(a) }

type bindLimitConn struct {
	net.Conn
	addr net.Addr
}

func (c bindLimitConn) RemoteAddr() net.Addr { return c.addr }

func newBindLimitTestHandler(t *testing.T, source string, user ...config.User) (*bindTestHandler, net.Conn) {
	t.Helper()

	record := config.User{Name: "known"}
	if len(user) > 0 {
		record = user[0]
	}
	raw, peer := net.Pipe()
	t.Cleanup(func() {
		_ = raw.Close()
		_ = peer.Close()
	})

	handler := &bindTestHandler{
		backend: config.Backend{
			BaseDN:             "dc=example,dc=com",
			NameFormatAsArray:  []string{"cn"},
			GroupFormatAsArray: []string{"ou"},
		},
		cfg: config.Config{
			Behaviors: config.Behaviors{
				LimitFailedBinds:    true,
				NumberOfFailedBinds: 3,
				PeriodOfFailedBinds: time.Minute,
				BlockFailedBindsFor: time.Minute,
			},
		},
		log:  zerolog.Nop(),
		user: record,
	}
	return handler, bindLimitConn{Conn: raw, addr: bindLimitAddr(source)}
}

func bindLimitCall(t *testing.T, helper LDAPOpsHelper, handler LDAPOpsHandler, conn net.Conn, dn, password string) ldap.LDAPResultCode {
	t.Helper()
	code, err := helper.Bind(context.Background(), handler, dn, password, conn)
	if err != nil {
		t.Fatalf("Bind returned error: %v", err)
	}
	return code
}

func TestFeedbackBindGuardBlocksSourceAfterThreshold(t *testing.T) {
	handler, conn := newBindLimitTestHandler(t, "192.0.2.10:4000")
	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-limit-test"))

	dn := "cn=unknown,dc=example,dc=com"
	for i := 0; i < 3; i++ {
		if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("failure %d: code = %v, want InvalidCredentials", i+1, code)
		}
	}

	if code := bindLimitCall(t, helper, handler, conn, "cn=other,dc=example,dc=com", "wrong"); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("fourth attempt from source = %v, want UnwillingToPerform", code)
	}
}

func TestFeedbackBindGuardSuccessResetsFailureCount(t *testing.T) {
	password := "correct horse battery staple"
	handler, conn := newBindLimitTestHandler(t, "192.0.2.20:4000", config.User{
		Name:       "alice",
		PassSHA256: sha256Password(password),
	})
	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-limit-test"))
	dn := "cn=alice,dc=example,dc=com"

	for i := 0; i < 2; i++ {
		if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("failure %d: code = %v, want InvalidCredentials", i+1, code)
		}
	}
	if code := bindLimitCall(t, helper, handler, conn, dn, password); code != ldap.LDAPResultSuccess {
		t.Fatalf("correct bind = %v, want Success", code)
	}

	for i := 0; i < 2; i++ {
		if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("post-reset failure %d: code = %v, want InvalidCredentials", i+1, code)
		}
	}
	if code := bindLimitCall(t, helper, handler, conn, dn, password); code != ldap.LDAPResultSuccess {
		t.Fatalf("bind after reset window = %v, want Success", code)
	}
}

func TestFeedbackBindGuardBlocksPrincipalAcrossSources(t *testing.T) {
	password := "correct"
	handler, _ := newBindLimitTestHandler(t, "unused:1", config.User{
		Name:       "alice",
		PassSHA256: sha256Password(password),
	})
	store := NewMemoryBindFailureStore()
	helper := NewLDAPOpsHelperWithBindStore(trace.NewNoopTracerProvider().Tracer("bind-limit-test"), store)
	dn := "cn=alice,dc=example,dc=com"

	for i := 0; i < 3; i++ {
		_, conn := net.Pipe()
		conn = bindLimitConn{Conn: conn, addr: bindLimitAddr(fmt.Sprintf("198.51.100.%d:5000", i+1))}
		if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("failure from source %d: code = %v, want InvalidCredentials", i+1, code)
		}
	}

	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	conn := bindLimitConn{Conn: raw, addr: bindLimitAddr("203.0.113.9:5000")}
	if code := bindLimitCall(t, helper, handler, conn, dn, password); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("correct bind from new source = %v, want UnwillingToPerform", code)
	}
}

func TestFeedbackBindGuardSourceAndPrincipalCountersAreIndependent(t *testing.T) {
	handler, conn := newBindLimitTestHandler(t, "192.0.2.30:4000")
	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-limit-test"))

	for i, name := range []string{"alice", "bob", "carol"} {
		dn := "cn=" + name + ",dc=example,dc=com"
		if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("failure for %s (%d): code = %v", name, i+1, code)
		}
	}

	if code := bindLimitCall(t, helper, handler, conn, "cn=dave,dc=example,dc=com", "wrong"); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("source with three distinct principals = %v, want UnwillingToPerform", code)
	}
}

func TestFeedbackBindGuardStoreCanBeSharedByHelpers(t *testing.T) {
	password := "correct"
	handler, conn := newBindLimitTestHandler(t, "192.0.2.40:4000", config.User{
		Name:       "alice",
		PassSHA256: sha256Password(password),
	})
	store := NewMemoryBindFailureStore()
	tracer := trace.NewNoopTracerProvider().Tracer("bind-limit-test")
	first := NewLDAPOpsHelperWithBindStore(tracer, store)
	second := NewLDAPOpsHelperWithBindStore(tracer, store)
	dn := "cn=alice,dc=example,dc=com"

	for i := 0; i < 3; i++ {
		if code := bindLimitCall(t, first, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
			t.Fatalf("failure %d on first replica = %v", i+1, code)
		}
	}

	if code := bindLimitCall(t, second, handler, conn, dn, password); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("second replica = %v, want shared block UnwillingToPerform", code)
	}
}

func TestFeedbackMemoryBindFailureStorePrunesOldKeys(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBindFailureStore()
	policy := BindLimitPolicy{Threshold: 3, FailureWindow: time.Minute, BlockDuration: time.Minute}
	old := time.Now().Add(-time.Hour)
	recent := time.Now()

	if _, err := store.RecordBindFailure(ctx, "old", old, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordBindFailure(ctx, "recent", recent, policy); err != nil {
		t.Fatal(err)
	}
	if err := store.PruneBindFailures(ctx, recent, time.Minute); err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.records["old"]; ok {
		t.Fatal("old failure record was not pruned")
	}
	if _, ok := store.records["recent"]; !ok {
		t.Fatal("recent failure record was incorrectly pruned")
	}
}

func TestFeedbackBindGuardBlockExpires(t *testing.T) {
	password := "correct"
	handler, conn := newBindLimitTestHandler(t, "192.0.2.60:4000", config.User{
		Name:       "alice",
		PassSHA256: sha256Password(password),
	})
	handler.cfg.Behaviors.NumberOfFailedBinds = 1
	handler.cfg.Behaviors.BlockFailedBindsFor = 20 * time.Millisecond
	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-limit-test"))
	dn := "cn=alice,dc=example,dc=com"

	if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("wrong bind = %v, want InvalidCredentials", code)
	}
	if code := bindLimitCall(t, helper, handler, conn, dn, password); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("bind during block = %v, want UnwillingToPerform", code)
	}

	time.Sleep(40 * time.Millisecond)
	if code := bindLimitCall(t, helper, handler, conn, dn, password); code != ldap.LDAPResultSuccess {
		t.Fatalf("bind after block expiry = %v, want Success", code)
	}
}

func TestFeedbackBindGuardFailureWindowDecays(t *testing.T) {
	handler, conn := newBindLimitTestHandler(t, "192.0.2.70:4000")
	handler.cfg.Behaviors.NumberOfFailedBinds = 2
	handler.cfg.Behaviors.PeriodOfFailedBinds = 30 * time.Millisecond
	handler.cfg.Behaviors.BlockFailedBindsFor = time.Minute
	helper := NewLDAPOpsHelper(trace.NewNoopTracerProvider().Tracer("bind-limit-test"))
	dn := "cn=decay,dc=example,dc=com"

	if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("first failure = %v, want InvalidCredentials", code)
	}
	time.Sleep(45 * time.Millisecond)
	if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("failure after window = %v, want InvalidCredentials", code)
	}
	if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultInvalidCredentials {
		t.Fatalf("second failure in new window = %v, want InvalidCredentials", code)
	}
	if code := bindLimitCall(t, helper, handler, conn, dn, "wrong"); code != ldap.LDAPResultUnwillingToPerform {
		t.Fatalf("third failure should reach threshold = %v, want UnwillingToPerform on next call", code)
	}
}

func TestFeedbackBindGuardPolicyDurationCompatibility(t *testing.T) {
	raw := bindLimitPolicyFromConfig(&config.Config{Behaviors: config.Behaviors{
		LimitFailedBinds:      true,
		PeriodOfFailedBinds:   10,
		BlockFailedBindsFor:   60,
		PruneSourcesOlderThan: 600,
		PruneSourceTableEvery: 300,
	}})
	if raw.FailureWindow != 10*time.Second || raw.BlockDuration != 60*time.Second ||
		raw.Retention != 600*time.Second || raw.PruneInterval != 300*time.Second {
		t.Fatalf("raw integer settings parsed as %+v, want second units", raw)
	}

	durations := bindLimitPolicyFromConfig(&config.Config{Behaviors: config.Behaviors{
		LimitFailedBinds:      true,
		PeriodOfFailedBinds:   time.Second,
		BlockFailedBindsFor:   time.Minute,
		PruneSourcesOlderThan: time.Hour,
		PruneSourceTableEvery: time.Minute,
	}})
	if durations.FailureWindow != time.Second || durations.BlockDuration != time.Minute ||
		durations.Retention != time.Hour || durations.PruneInterval != time.Minute {
		t.Fatalf("duration settings parsed as %+v, want unchanged durations", durations)
	}
}
