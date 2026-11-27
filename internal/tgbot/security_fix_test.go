package tgbot

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInstallScriptRejectsBadInputs(t *testing.T) {
	validPin := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validSPKI := "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	validURL := "https://example.com:8443"

	cases := []struct {
		name  string
		url   string
		pin   string
		spki  string
		token string
	}{
		{"url-injection", "https://example.com:8443;id", validPin, validSPKI, fakeInstallToken},
		{"url-http", "http://example.com:8443", validPin, validSPKI, fakeInstallToken},
		{"bad-pin", validURL, "not-a-pin", validSPKI, fakeInstallToken},
		{"bad-spki", validURL, validPin, "sha256//bad spki", fakeInstallToken},
		{"bad-token", validURL, validPin, validSPKI, "abc;rm -rf /"},
	}
	for _, tc := range cases {
		b := &Bot{cfg: Config{PublicURL: tc.url}, pin: tc.pin, spkiPin: tc.spki}
		out := b.InstallScript(tc.token)
		if strings.Contains(out, "curl ") || !strings.Contains(out, "不合法") {
			t.Fatalf("%s: expected error message, got %q", tc.name, out)
		}
	}
}

func TestAskWithSpecTimeoutCancelsCommand(t *testing.T) {
	b, _ := testBotWithOwner(t, 1001)
	defer b.st.Close()
	if _, err := b.askWithSpec("m1", "switch", "in1", "relay-out-1", nil, 30*time.Millisecond); err == nil {
		t.Fatal("expected timeout error")
	}
	if cmds := b.st.TakeCommands("m1"); len(cmds) != 0 {
		t.Fatalf("timed out command should be cancelled, got %+v", cmds)
	}
}

func TestIsStartCmd(t *testing.T) {
	for _, ok := range []string{"/start", "  /start  ", "/start arg", "/START", "/start@my_bot", "/start@MyBot payload"} {
		if !isStartCmd(ok) {
			t.Fatalf("want true for %q", ok)
		}
	}
	for _, bad := range []string{"", "/startxyz", "/start@", "/start@ arg", "hi /start", "/status"} {
		if isStartCmd(bad) {
			t.Fatalf("want false for %q", bad)
		}
	}
}

func TestSafeGoRecoversPanic(t *testing.T) {
	b := &Bot{}
	done := make(chan struct{})
	b.safeGo("test", func() {
		defer close(done)
		panic("boom")
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("safeGo did not finish")
	}
}

func TestHandleRegisterRateLimit(t *testing.T) {
	b, _ := testBotWithOwner(t, 1001)
	defer b.st.Close()
	mux := b.AgentMux()

	post := func(addr string) int {
		req := httptest.NewRequest("POST", "/v1/register", bytes.NewReader([]byte(`{"token":"bad"}`)))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < regFailLimit; i++ {
		if code := post("198.51.100.1:12345"); code != 403 {
			t.Fatalf("attempt %d: got %d want 403", i+1, code)
		}
	}
	if code := post("198.51.100.1:54321"); code != 429 {
		t.Fatalf("6th attempt from same IP: got %d want 429", code)
	}
	if code := post("198.51.100.2:12345"); code != 403 {
		t.Fatalf("other IP should not be rate limited: got %d want 403", code)
	}
}
