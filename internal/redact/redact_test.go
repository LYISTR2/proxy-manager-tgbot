package redact

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"testing"
)

// 仅用于测试的假 token，形态贴近 Telegram，但不是真实凭据。
const fakeToken = "123456789:AAFakeToken_forUnitTestsOnly012345"

func TestRedactBotAPIURLAndToken(t *testing.T) {
	full := "https://api.telegram.org/bot" + fakeToken + "/getUpdates"
	got := String(`Post "` + full + `": read tcp 10.0.0.1:12345->10.0.0.2:443: connection reset by peer`)
	if strings.Contains(got, fakeToken) {
		t.Fatalf("token leaked in: %s", got)
	}
	if !strings.Contains(got, "https://api.telegram.org/bot***/getUpdates") {
		t.Fatalf("url not masked as expected: %s", got)
	}

	// 无 scheme
	got = String("api.telegram.org/bot" + fakeToken + "/sendMessage")
	if strings.Contains(got, fakeToken) || !strings.Contains(got, "api.telegram.org/bot***/sendMessage") {
		t.Fatalf("host-only url: %s", got)
	}

	// 独立出现的 token
	got = String("unauthorized token=" + fakeToken)
	if strings.Contains(got, fakeToken) || !strings.Contains(got, "unauthorized token=***") {
		t.Fatalf("standalone token: %s", got)
	}
}

func TestRedactURLErrorAndFmt(t *testing.T) {
	full := "https://api.telegram.org/bot" + fakeToken + "/getUpdates"
	uerr := &url.Error{Op: "Post", URL: full, Err: io.ErrUnexpectedEOF}
	got := Error(uerr)
	if strings.Contains(got, fakeToken) {
		t.Fatal("url.Error leaked token")
	}
	if !strings.Contains(got, "https://api.telegram.org/bot***/getUpdates") {
		t.Fatalf("url.Error: %s", got)
	}

	wrapped := fmt.Errorf("getUpdates: %w", uerr)
	got = Error(wrapped)
	if strings.Contains(got, fakeToken) {
		t.Fatal("wrapped error leaked token")
	}

	got = String(fmt.Sprintf("getUpdates: %v", uerr))
	if strings.Contains(got, fakeToken) {
		t.Fatal("fmt v leaked token")
	}

	httpish := errors.New(`Post "http://api.telegram.org/bot` + fakeToken + `/getUpdates": EOF`)
	got = Error(httpish)
	if strings.Contains(got, fakeToken) || !strings.Contains(got, "http://api.telegram.org/bot***/getUpdates") {
		t.Fatalf("http error: %s", got)
	}
}

func TestRedactSSHPasswordAndPrivateKey(t *testing.T) {
	got := String("ssh://root:s3cretPass@192.0.2.10:22")
	if strings.Contains(got, "s3cretPass") || !strings.Contains(got, "ssh://root:***@192.0.2.10:22") {
		t.Fatalf("ssh url: %s", got)
	}
	got = String("LANDING_PASSWORD=abc$def SSH_PASSWORD=hunter2 password: visible")
	if strings.Contains(got, "abc$def") || strings.Contains(got, "hunter2") || strings.Contains(got, "visible") {
		t.Fatalf("password assign: %s", got)
	}
	if !strings.Contains(got, "LANDING_PASSWORD=***") || !strings.Contains(got, "SSH_PASSWORD=***") || !strings.Contains(got, "password: ***") {
		t.Fatalf("password assign not masked: %s", got)
	}

	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATAFORTEST\n-----END OPENSSH PRIVATE KEY-----"
	got = String("key follows\n" + pem + "\nok")
	if strings.Contains(got, "FAKEKEYDATAFORTEST") || !strings.Contains(got, "[redacted private key]") {
		t.Fatalf("pem: %s", got)
	}
}

func TestRedactLeavesBenignText(t *testing.T) {
	s := "TLS pin=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef listen=:8443 machine_id=0000aaaa1111bbbb"
	if String(s) != s {
		t.Fatalf("benign text changed: %s", String(s))
	}
	if String("") != "" {
		t.Fatal("empty")
	}
	if Error(nil) != "" {
		t.Fatal("nil error")
	}
}

func TestLogWriterRedacts(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(Writer(&buf), "", 0)
	full := "https://api.telegram.org/bot" + fakeToken + "/getUpdates"
	uerr := &url.Error{Op: "Post", URL: full, Err: io.ErrUnexpectedEOF}
	l.Printf("getUpdates: %v", uerr)
	out := buf.String()
	if strings.Contains(out, fakeToken) {
		t.Fatalf("log writer leaked: %s", out)
	}
	if !strings.Contains(out, "https://api.telegram.org/bot***/getUpdates") {
		t.Fatalf("log writer: %s", out)
	}
}
