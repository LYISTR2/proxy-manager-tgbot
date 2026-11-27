package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sudo 把 "unable to resolve host" 告警打到 stderr 时，helper 输出仍应是干净 JSON。
func TestHelperIgnoresSudoStderrNoise(t *testing.T) {
	dir := t.TempDir()
	fake := "#!/bin/sh\necho 'sudo: unable to resolve host free.example: Name or service not known' >&2\necho '{\"ok\":true,\"op\":\"status\",\"status\":{\"relays\":[]}}'\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(fake), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	c := &Config{Helper: "/nonexistent/helper"}
	out, err := c.helper("status", nil)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("output not clean JSON: %q", out)
	}
	if !json.Valid(c.status()) {
		t.Fatal("status() not valid JSON")
	}
}

// helper 失败且 stdout 为空时，报错里带上 stderr 摘要。
func TestHelperFailureIncludesStderr(t *testing.T) {
	dir := t.TempDir()
	fake := "#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(fake), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	c := &Config{Helper: "/nonexistent/helper"}
	if _, err := c.helper("status", nil); err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("want stderr in error, got %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(c.status(), &v); err != nil || v["ok"] != false {
		t.Fatalf("status() should be ok=false JSON: %v", v)
	}
}
