package tgbot

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sbrelay/internal/store"
)

const fakeInstallToken = "aabbccddeeff00112233445566778899"

func TestInstallScriptUsesPinAndDoesNotUseBareInsecureCurl(t *testing.T) {
	b := &Bot{
		cfg:     Config{PublicURL: "https://example.com:8443"},
		pin:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		spkiPin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	s := b.InstallScript(fakeInstallToken)
	if !strings.Contains(s, "export HISTCONTROL=ignorespace") {
		t.Fatal("missing HISTCONTROL hint")
	}
	if !strings.Contains(s, " curl ") || !strings.Contains(s, "--pinnedpubkey sha256//") {
		t.Fatalf("expected leading-space curl with pin: %s", s)
	}
	if !strings.Contains(s, "SBRELAY_TOKEN="+fakeInstallToken+" bash -s --") || strings.Contains(s, "--token "+fakeInstallToken) {
		t.Fatal("token must be passed via SBRELAY_TOKEN env, not as a process argument")
	}
	if strings.Contains(s, "curl -k ") && !strings.Contains(s, "--pinnedpubkey") {
		t.Fatal("curl -k without pin")
	}
	if !strings.Contains(s, "-k --pinnedpubkey") && !strings.Contains(s, "--pinnedpubkey") {
		t.Fatal("missing pinnedpubkey")
	}
	if strings.Contains(s, "PLACEHOLDER") {
		t.Fatal("placeholder left in script")
	}
	if !strings.Contains(s, "https://example.com:8443/install-agent.sh") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "--uninstall") {
		t.Fatal("missing uninstall hint")
	}
}

func TestInstallAgentShContainsNoSecretsAndServesBinaries(t *testing.T) {
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join(findRepoRoot(t), "deploy", "install-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(dir, "install-agent.sh")
	if err := os.WriteFile(scriptPath, src, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sbrelay"), []byte("fake-bin-relay"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sbrelay-helper"), []byte("fake-bin-helper"), 0750); err != nil {
		t.Fatal(err)
	}
	// 不应被下发的敏感文件
	if err := os.WriteFile(filepath.Join(dir, "control.env"), []byte("SBRELAY_TG_TOKEN=should-not-serve\n"), 0600); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b := &Bot{st: st, cfg: Config{PkgDir: dir, PublicURL: "https://example.com:8443"}, pend: map[string]string{}, wait: map[string]chan json.RawMessage{}, expect: map[int64]expect{}}
	mux := b.AgentMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/install-agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("script: %d", resp.StatusCode)
	}
	text := string(body)
	for _, bad := range []string{"should-not-serve", "SBRELAY_TG_TOKEN=", fakeInstallToken, "BEGIN ", "PRIVATE KEY"} {
		if strings.Contains(text, bad) {
			t.Fatalf("script leaked %q", bad)
		}
	}
	if !strings.Contains(text, "--pinnedpubkey") || !strings.Contains(text, "--uninstall") {
		t.Fatal("script missing pin or uninstall")
	}
	if !strings.Contains(text, "落地") || !strings.Contains(text, "helper status") {
		t.Fatal("script should describe landing read-only vs relay")
	}

	// 二进制可下发
	for _, name := range []string{"/pkg/sbrelay", "/pkg/sbrelay-helper"} {
		r, err := http.Get(srv.URL + name)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || len(b) == 0 {
			t.Fatalf("%s: %d", name, r.StatusCode)
		}
	}
	// 敏感或未允许的文件不能下发
	for _, name := range []string{"/pkg/control.env", "/pkg/../control.env", "/pkg/state.json"} {
		r, err := http.Get(srv.URL + name)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode == 200 {
			t.Fatalf("should not serve %s", name)
		}
	}
}

func TestInstallScriptArgParseAndRoleHints(t *testing.T) {
	script := filepath.Join(findRepoRoot(t), "deploy", "install-agent.sh")
	cmd := exec.Command("bash", script, "--parse-only",
		"--url", "https://control.example:8443",
		"--pin", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"--pubkey", "sha256//ABCDEFGHIJK=",
		"--token", fakeInstallToken,
		"--role", "landing",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("parse: %v %s", err, out)
	}
	s := string(out)
	if strings.Contains(s, fakeInstallToken) {
		t.Fatalf("parse-only leaked token")
	}
	if !strings.Contains(s, "token_set=1") || !strings.Contains(s, "role=landing") {
		t.Fatalf("parse result: %s", s)
	}
	if !strings.Contains(s, "url=https://control.example:8443") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "pubkey=sha256//ABCDEFGHIJK=") {
		t.Fatal(s)
	}

	cmd = exec.Command("bash", script, "--parse-only", "--url", "https://x", "--pin", "aa", "--token", fakeInstallToken)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if strings.Contains(string(out), fakeInstallToken) {
		t.Fatal("leaked")
	}

	// 卸载参数
	cmd = exec.Command("bash", script, "--parse-only", "--uninstall")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if !strings.Contains(string(out), "uninstall=1") {
		t.Fatal(string(out))
	}
	cmd = exec.Command("bash", script, "--parse-only", "--purge")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if !strings.Contains(string(out), "uninstall=1") || !strings.Contains(string(out), "purge=1") {
		t.Fatal(string(out))
	}
}

func TestAddLandingInstallTokenAndReuse(t *testing.T) {
	b, _ := testBotWithOwner(t, 1001)
	b.pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	b.spkiPin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	b.cfg.PublicURL = "https://example.com:8443"
	reply, _, retry, err := b.applyName(expect{Kind: expectAddLanding}, "测试落地甲")
	if err != nil || retry || !strings.Contains(reply, "落地机「测试落地甲」") {
		t.Fatalf("%v %v %s", retry, err, reply)
	}
	if !strings.Contains(reply, "--pinnedpubkey") || !strings.Contains(reply, "install-agent.sh") {
		t.Fatal(reply)
	}
	// 重名
	_, _, retry, err = b.applyName(expect{Kind: expectAddLanding}, "测试落地甲")
	if !retry || err == nil {
		t.Fatal("expected dup")
	}
	tok, err := b.st.NewMachineInstallToken("一次性", store.RoleLanding, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux := b.AgentMux()
	body := []byte(`{"token":"` + tok.Token + `"}`)
	req := httptest.NewRequest("POST", "/v1/register", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid register: %d %s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	json.Unmarshal(rec.Body.Bytes(), &got)
	if got["role"] != "landing" {
		t.Fatalf("role %v", got)
	}
	req2 := httptest.NewRequest("POST", "/v1/register", strings.NewReader(string(body)))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != 403 {
		t.Fatalf("reuse: %d", rec2.Code)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "deploy", "install-agent.sh")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repo root not found")
	return ""
}

func TestScriptRoutesServeOnlyKnownScripts(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"pm.sh", "install-control.sh", "state.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/bash\necho "+n+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	b := &Bot{cfg: Config{PkgDir: dir}}
	for path, want := range map[string]int{"/pm.sh": 200, "/install-control.sh": 200, "/state.json": 404, "/pm.sh/../state.json": 404} {
		rr := httptest.NewRecorder()
		b.handleScript(rr, httptest.NewRequest("GET", "https://x"+path, nil))
		if rr.Code != want {
			t.Fatalf("%s: got %d want %d", path, rr.Code, want)
		}
	}
	rr := httptest.NewRecorder()
	b.handleScript(rr, httptest.NewRequest("POST", "https://x/pm.sh", nil))
	if rr.Code != 405 {
		t.Fatalf("POST got %d", rr.Code)
	}
}
