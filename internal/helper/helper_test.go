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
