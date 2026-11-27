package helper

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"sbrelay/internal/relaycfg"
)

func setupEnv(t *testing.T) *Env {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"config.json", "relay.json", "relay_links.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		bin = "/workspace/sbtools/sing-box-1.14.3-linux-amd64/sing-box"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("没有本地 sing-box 1.14.3")
	}
	restarts := 0
	return &Env{
		Dir: dir, SingBox: bin, StateDir: filepath.Join(dir, "state"), Service: "sing-box",
		LockWait: 2 * time.Second, SettleWait: 0,
		Systemctl: func(args ...string) error {
			if len(args) > 0 && args[0] == "restart" {
				restarts++
			}
			return nil
		},
	}
}

func TestHelperEmptyStatus(t *testing.T) {
	e := setupEnv(t)
	os.WriteFile(e.relay(), []byte(`{"inbounds":[],"outbounds":[],"route":{"rules":[]}}`), 0600)
	res := e.Status()
	if !res.OK || res.Message != "没有中转可切换" || len(res.Status.Relays) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestHelperSwitchRollback(t *testing.T) {
	e := setupEnv(t)
	st := e.Status()
	if !st.OK || len(st.Status.Relays) != 2 {
		t.Fatalf("status %+v", st)
	}
	res := e.Switch(SwitchReq{Inbound: "shadowsocks-in-20001", Outbound: "relay-out-20002"}, "switch")
	if !res.OK {
		t.Fatalf("switch: %+v", res)
	}
	got, _ := relaycfg.Parse(mustRead(t, e.relay()), mustRead(t, e.links()))
	if got.Relays[0].Outbound != "relay-out-20002" || got.Relays[0].LandingAddr != "203.0.113.20:443" {
		t.Fatalf("after switch %+v", got.Relays[0])
	}
	rb := e.Rollback()
	if !rb.OK {
		t.Fatalf("rollback: %+v", rb)
	}
	got, _ = relaycfg.Parse(mustRead(t, e.relay()), mustRead(t, e.links()))
	if got.Relays[0].Outbound != "relay-out-20001" || got.Relays[0].LandingAddr != "203.0.113.10:8443" {
		t.Fatalf("after rollback %+v", got.Relays[0])
	}
	// 再回滚应拒绝
	rb2 := e.Rollback()
	if rb2.OK || rb2.Code != "nothing" {
		t.Fatalf("second rollback %+v", rb2)
	}
	// 另一条中转未动
	if got.Relays[1].Outbound != "relay-out-20002" {
		t.Fatalf("other relay changed %+v", got.Relays[1])
	}
	// 备份存在
	if res.Backup == "" {
		t.Fatal("no backup path")
	}
	if _, err := os.Stat(filepath.Join(res.Backup, "relay.json")); err != nil {
		t.Fatal(err)
	}
}

func TestHelperSwitchNoRelay(t *testing.T) {
	e := setupEnv(t)
	os.WriteFile(e.relay(), []byte(`{"inbounds":[],"outbounds":[],"route":{"rules":[]}}`), 0600)
	res := e.Switch(SwitchReq{Inbound: "x", Outbound: "relay-out-1"}, "switch")
	if res.OK || res.Code != "no_relay" {
		t.Fatalf("%+v", res)
	}
}

func TestHelperCheckFailDoesNotWrite(t *testing.T) {
	e := setupEnv(t)
	// 破坏目标出站，让 check 失败
	b, _ := os.ReadFile(e.relay())
	var raw map[string]any
	json.Unmarshal(b, &raw)
	// 把 relay-out-20002 的 server_port 改成非法值
	cmd := exec.Command("bash", "-c", `jq '(.outbounds[] | select(.tag=="relay-out-20002") | .server_port) = 99999' "`+e.relay()+`" > "`+e.relay()+`.t" && mv "`+e.relay()+`.t" "`+e.relay()+`"`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	before, _ := os.ReadFile(e.relay())
	res := e.Switch(SwitchReq{Inbound: "shadowsocks-in-20001", Outbound: "relay-out-20002"}, "switch")
	if res.OK || res.Code != "check_failed" {
		t.Fatalf("%+v", res)
	}
	after, _ := os.ReadFile(e.relay())
	if string(before) != string(after) {
		t.Fatal("check 失败后文件被改动")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 本机直出：真实 sing-box check 通过、写入后权限不变、能回滚到原落地。
func TestHelperSwitchLocalEgressRollback(t *testing.T) {
	e := setupEnv(t)
	before := mustRead(t, e.relay())
	res := e.Switch(SwitchReq{Inbound: "shadowsocks-in-20001", Outbound: relaycfg.LocalEgressTag}, "switch")
	if !res.OK || res.From != "relay-out-20001" || res.To != relaycfg.LocalEgressTag {
		t.Fatalf("switch to local: %+v", res)
	}
	if res.Status == nil || res.Status.Relays[0].Outbound != relaycfg.LocalEgressTag {
		t.Fatalf("status after switch: %+v", res.Status)
	}
	for _, p := range []string{e.relay(), e.links()} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("%s perm %v %v", p, fi.Mode().Perm(), err)
		}
	}
	if fi, err := os.Stat(filepath.Join(res.Backup, "relay.json")); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("backup perm: %v", err)
	}
	// 再选一次本机直出：noop，不重启不备份
	again := e.Switch(SwitchReq{Inbound: "shadowsocks-in-20001", Outbound: relaycfg.LocalEgressTag}, "switch")
	if again.OK || again.Code != "noop" {
		t.Fatalf("second local switch: %+v", again)
	}
	rb := e.Rollback()
	if !rb.OK || rb.From != relaycfg.LocalEgressTag || rb.To != "relay-out-20001" {
		t.Fatalf("rollback: %+v", rb)
	}
	got, _ := relaycfg.Parse(mustRead(t, e.relay()), mustRead(t, e.links()))
	if got.Relays[0].Outbound != "relay-out-20001" || got.Relays[0].LandingAddr != "203.0.113.10:8443" {
		t.Fatalf("after rollback %+v", got.Relays[0])
	}
	// 回滚后入站与原文件一致（本机直出出站保留，不影响 check）
	var a, b map[string]json.RawMessage
	json.Unmarshal(before, &a)
	json.Unmarshal(mustRead(t, e.relay()), &b)
	if string(a["inbounds"]) != string(b["inbounds"]) || string(a["route"]) != string(b["route"]) {
		t.Fatal("rollback did not restore inbounds/route")
	}
}

// sing-box check 失败时本机直出切换不落盘。
func TestHelperLocalEgressCheckFailDoesNotWrite(t *testing.T) {
	e := setupEnv(t)
	fake := filepath.Join(t.TempDir(), "fake-sing-box")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho check failed >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	e.SingBox = fake
	before := mustRead(t, e.relay())
	res := e.Switch(SwitchReq{Inbound: "shadowsocks-in-20001", Outbound: relaycfg.LocalEgressTag}, "switch")
	if res.OK || res.Code != "check_failed" {
		t.Fatalf("%+v", res)
	}
	if string(before) != string(mustRead(t, e.relay())) {
		t.Fatal("relay.json changed after failed check")
	}
}
