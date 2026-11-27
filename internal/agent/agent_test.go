package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientRejectsEmptyPin(t *testing.T) {
	c := &Config{URL: "https://127.0.0.1:8443", TLSPin: ""}
	if _, err := c.client(); err == nil || !strings.Contains(err.Error(), "SBRELAY_TLS_PIN") {
		t.Fatalf("expected fail-closed error for empty pin, got %v", err)
	}
}

func TestHelperTimeout(t *testing.T) {
	dir := t.TempDir()
	fake := "#!/bin/sh\nexec /bin/sleep 5\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(fake), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	old := helperTimeout
	helperTimeout = 150 * time.Millisecond
	defer func() { helperTimeout = old }()

	c := &Config{Helper: "/nonexistent/helper"}
	start := time.Now()
	_, err := c.helper("status", nil)
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("helper did not time out promptly: %s", time.Since(start))
	}
}
