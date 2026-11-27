package tgbot

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testSSPassword = "AAAAAAAAAAAAAAAAAAAAAA=="

func findSingBox(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/workspace/sbtools/sing-box-1.14.3-linux-amd64/sing-box",
		"/usr/local/bin/sing-box",
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		candidates = append([]string{p}, candidates...)
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	t.Fatal("sing-box binary not found for check/rollback tests")
	return ""
}

func runSetup(t *testing.T, dir, role, bin string, extraEnv []string) (string, error) {
	t.Helper()
	script := filepath.Join(findRepoRoot(t), "deploy", "install-agent.sh")
	cmd := exec.Command("bash", script, "--setup-only", "--role", role)
	cmd.Env = append(os.Environ(),
		"SBRELAY_SINGBOX_DIR="+dir,
		"SBRELAY_SINGBOX_BIN="+bin,
		"SBRELAY_SS_PORT=23456",
		"SBRELAY_SS_PASSWORD="+testSSPassword,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), testSSPassword) {
		t.Fatalf("setup output leaked password")
	}
	return string(out), err
}

func readObj(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func tagsOfType(doc map[string]any, typ string) []string {
	var tags []string
	arr, _ := doc["inbounds"].([]any)
	for _, e := range arr {
		o, _ := e.(map[string]any)
		if o["type"] == typ {
			tags = append(tags, o["tag"].(string))
		}
	}
	return tags
}

func inboundTags(doc map[string]any) []string {
	var tags []string
	arr, _ := doc["inbounds"].([]any)
	for _, e := range arr {
		o, _ := e.(map[string]any)
		if tag, _ := o["tag"].(string); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func TestSetupSingboxEmptySkeletonRelayWritesInbound(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	// 非空但无入站的空骨架，另带一个不应被覆盖的字段
	if err := os.WriteFile(filepath.Join(dir, "relay.json"), []byte(`{
  "log": {"level": "warn"},
  "inbounds": [],
  "outbounds": [],
  "route": {"rules": []},
  "experimental": {"cache_file": {"enabled": false}}
}
`), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runSetup(t, dir, "relay", bin, nil)
	if err != nil {
		t.Fatalf("setup: %v %s", err, out)
	}
	if !strings.Contains(out, "sbrelay-ss2022-in") || strings.Contains(out, "已保留原配置") {
		t.Fatalf("should write inbound into empty skeleton: %s", out)
	}
	doc := readObj(t, filepath.Join(dir, "relay.json"))
	if doc["log"] == nil || doc["experimental"] == nil {
		t.Fatal("should not overwrite the whole file; extra fields lost")
	}
	tags := tagsOfType(doc, "shadowsocks")
	if len(tags) != 1 || tags[0] != "sbrelay-ss2022-in" {
		t.Fatalf("inbounds: %v", inboundTags(doc))
	}
	// 空的 outbounds 应保留为空（未整份替换成只有 inbound 的新文件也可以，但不能丢掉字段）
	outs, _ := doc["outbounds"].([]any)
	if len(outs) != 0 {
		t.Fatalf("outbounds should stay empty: %v", outs)
	}
	// 写入了 SS 密码，原 0644 的骨架应收紧为 0600
	if fi, err := os.Stat(filepath.Join(dir, "relay.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("relay.json with password should be 0600, got %v %v", fi.Mode().Perm(), err)
	}
}

func TestSetupSingboxExistingRelayNotOverwritten(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	orig := `{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "shadowsocks-in-20001",
      "listen": "::",
      "listen_port": 20001,
      "method": "2022-blake3-aes-128-gcm",
      "password": "AAAAAAAAAAAAAAAAAAAAAA=="
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "relay-out-20001",
      "server": "192.0.2.10",
      "server_port": 8888,
      "method": "2022-blake3-aes-128-gcm",
      "password": "AAAAAAAAAAAAAAAAAAAAAA=="
    }
  ],
  "route": {
    "rules": [
      {"inbound": "shadowsocks-in-20001", "outbound": "relay-out-20001"}
    ]
  }
}
`
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	out, err := runSetup(t, dir, "relay", bin, nil)
	if err != nil {
		t.Fatalf("setup: %v %s", err, out)
	}
	if !strings.Contains(out, "已保留原配置") {
		t.Fatalf("should skip existing relay: %s", out)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("existing real relay.json was modified")
	}
	if strings.Contains(string(after), "sbrelay-ss2022-in") {
		t.Fatal("should not add auto inbound on top of real relay")
	}
}

func TestSetupSingboxLandingAppendsWhenOnlyVLESS(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	orig := `{
  "log": {"level": "info"},
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in-45666",
      "listen": "::",
      "listen_port": 45666,
      "users": [{"uuid": "00000000-0000-4000-8000-000000000001"}]
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "final": "direct",
    "rules": [{"inbound": "vless-in-45666", "outbound": "direct"}]
  }
}
`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	out, err := runSetup(t, dir, "landing", bin, nil)
	if err != nil {
		t.Fatalf("setup: %v %s", err, out)
	}
	if !strings.Contains(out, "追加") && !strings.Contains(out, "sbrelay-landing-in") {
		t.Fatalf("should append landing inbound: %s", out)
	}
	doc := readObj(t, path)
	if tags := inboundTags(doc); strings.Join(tags, ",") != "vless-in-45666,sbrelay-landing-in" {
		t.Fatalf("inbounds changed unexpectedly: %v", tags)
	}
	// 已有出站/路由不得改动
	outs, _ := doc["outbounds"].([]any)
	if len(outs) != 1 {
		t.Fatalf("outbounds mutated: %v", outs)
	}
	route, _ := doc["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	if route["final"] != "direct" || len(rules) != 1 {
		t.Fatalf("route mutated: %v", route)
	}
	if fi, err := os.Stat(filepath.Join(dir, "config.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("config.json with appended password should be 0600, got %v %v", fi.Mode().Perm(), err)
	}
}

func TestSetupSingboxLandingKeepsExistingSS(t *testing.T) {
	bin := findSingBox(t)
	dir := t.TempDir()
	orig := `{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in-1",
      "listen": "::",
      "listen_port": 1111,
      "users": [{"uuid": "00000000-0000-4000-8000-000000000001"}]
    },
    {
      "type": "shadowsocks",
      "tag": "SS-aes128-in-45326",
      "listen": "::",
      "listen_port": 45326,
      "method": "2022-blake3-aes-128-gcm",
      "password": "AAAAAAAAAAAAAAAAAAAAAA=="
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
`
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	out, err := runSetup(t, dir, "landing", bin, nil)
	if err != nil {
		t.Fatalf("setup: %v %s", err, out)
	}
	if !strings.Contains(out, "已保留原配置") {
		t.Fatalf("should keep existing SS: %s", out)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("existing SS landing config was modified")
	}

	// 已有 sbrelay-landing-in 时同样保留（即使还有别的 SS）
	dir2 := t.TempDir()
	prefer := `{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "sbrelay-landing-in",
      "listen": "::",
      "listen_port": 30001,
      "method": "2022-blake3-aes-128-gcm",
      "password": "AAAAAAAAAAAAAAAAAAAAAA=="
    },
    {
      "type": "shadowsocks",
      "tag": "other-ss",
      "listen": "::",
      "listen_port": 30002,
      "method": "2022-blake3-aes-128-gcm",
      "password": "AAAAAAAAAAAAAAAAAAAAAA=="
    }
  ]
}
`
	p2 := filepath.Join(dir2, "config.json")
	if err := os.WriteFile(p2, []byte(prefer), 0644); err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(p2)
	out, err = runSetup(t, dir2, "landing", bin, nil)
	if err != nil {
		t.Fatalf("setup prefer: %v %s", err, out)
	}
	b2, _ := os.ReadFile(p2)
	if string(b1) != string(b2) {
		t.Fatal("preferred sbrelay-landing-in config was modified")
	}
}

func TestSetupSingboxCheckFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	skel := `{
  "inbounds": [],
  "outbounds": [],
  "route": {"rules": []}
}
`
	path := filepath.Join(dir, "relay.json")
	if err := os.WriteFile(path, []byte(skel), 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	failBin := filepath.Join(dir, "fake-check")
	if err := os.WriteFile(failBin, []byte("#!/bin/bash\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	out, err := runSetup(t, dir, "relay", failBin, nil)
	if err == nil {
		t.Fatalf("expected check failure, got: %s", out)
	}
	if !strings.Contains(out, "已回滚") {
		t.Fatalf("should mention rollback: %s", out)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("failed check did not restore the empty skeleton")
	}
}
