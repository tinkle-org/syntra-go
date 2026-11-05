package syntrahttp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

func rateFixture(t *testing.T, limits ServerLimits, now time.Time) *Server {
	t.Helper()
	l, err := limits.normalize()
	if err != nil {
		t.Fatal(err)
	}
	return &Server{cfg: ServerConfig{Limits: l}, global: bucket{float64(l.OpenBurst), now}, sources: make(map[netip.Addr]bucket)}
}

func assertRate(t *testing.T, s *Server, source string, now time.Time, want int) {
	t.Helper()
	err := s.rateLockedAt(netip.MustParseAddr(source), now)
	if want == 0 && err == nil {
		return
	}
	var r rejection
	if !errors.As(err, &r) || int(r) != want || want == 0 {
		t.Fatalf("rate admission %s = %v, want status %d", source, err, want)
	}
}

func TestSourceRateRejectionPreservesOtherSourcesGlobalTokens(t *testing.T) {
	now := time.Now()
	s := rateFixture(t, ServerLimits{OpenBurst: 3, SourceOpenBurst: 1}, now)
	assertRate(t, s, "127.0.0.1", now, 0)
	for i := 0; i < 100; i++ {
		assertRate(t, s, "127.0.0.1", now, 429)
	}
	assertRate(t, s, "127.0.0.2", now, 0)
	assertRate(t, s, "127.0.0.3", now, 0)
	assertRate(t, s, "127.0.0.4", now, 429)
}

func TestFullSourceRegistryPreservesStatusAndGlobalTokens(t *testing.T) {
	now := time.Now()
	s := rateFixture(t, ServerLimits{SourceEntries: 1, OpenBurst: 2, SourceOpenBurst: 3, SourceOpensPerSecond: 3}, now)
	assertRate(t, s, "127.0.0.1", now, 0)
	for i := 0; i < 3; i++ {
		assertRate(t, s, "127.0.0.2", now, 503)
	}
	assertRate(t, s, "127.0.0.1", now, 0)
	assertRate(t, s, "127.0.0.2", now, 503)
	assertRate(t, s, "127.0.0.1", now, 429)
	if len(s.sources) != 1 {
		t.Fatalf("source registry grew past its bound: %d", len(s.sources))
	}
	assertRate(t, s, "127.0.0.2", now.Add(time.Second), 0)
}

func TestGlobalRateRejectionStillChargesAdmittedSource(t *testing.T) {
	now := time.Now()
	s := rateFixture(t, ServerLimits{OpenBurst: 1, OpensPerSecond: 10, SourceOpenBurst: 1, SourceOpensPerSecond: 1}, now)
	assertRate(t, s, "127.0.0.1", now, 0)
	assertRate(t, s, "127.0.0.2", now, 429)
	assertRate(t, s, "127.0.0.2", now.Add(100*time.Millisecond), 429)
	assertRate(t, s, "127.0.0.3", now.Add(100*time.Millisecond), 0)
}

func TestFullSourceRegistryReturnsNative503BeforeBody(t *testing.T) {
	_, security := securityConfigs(t, securechannel.Bootstrap, securechannel.HTTP)
	s := startServer(t, security, hostConfig(), nil, ServerLimits{SourceEntries: 1})
	s.mu.Lock()
	// Keep a different source registered and the global bucket empty for this
	// deterministic precedence check. Neither bucket can refill during the test.
	future := time.Now().Add(time.Hour)
	s.sources[netip.MustParseAddr("192.0.2.1")] = bucket{0, future}
	s.global = bucket{0, future}
	s.mu.Unlock()
	header, err := requestHeader(Open, testAuthority(t), Route{}, 0, 83)
	if err != nil {
		t.Fatal(err)
	}
	response, err := nativeRequest(t, s, header, nil)
	if err != nil || !bytes.HasPrefix(response, []byte("HTTP/1.1 503 ")) {
		t.Fatalf("full source registry: response=%q error=%v", response, err)
	}
	if st := s.Status(); st.Associations != 0 || st.Handshakes != 0 {
		t.Fatalf("registry rejection started protocol admission: %+v", st)
	}
}
