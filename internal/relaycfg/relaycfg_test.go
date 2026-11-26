package relaycfg

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, n string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", n))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	st, err := Parse(read(t, "relay.json"), read(t, "relay_links.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Relays) != 2 || st.Relays[0].Outbound != "relay-out-20001" || st.Relays[0].NodeName != "JP-01" || st.Relays[0].ListenPort != 20001 {
		t.Fatalf("relays: %+v", st.Relays)
	}
	if len(st.Candidates) != 3 {
		t.Fatalf("candidates: %+v", st.Candidates)
	}
	for _, c := range st.Candidates {
		if c.Tag == "relay-out-20003" && (c.Label != "https" || c.HostPort() != "[2001:db8::30]:8080") {
			t.Fatalf("https label/hostport: %+v", c)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	st, err := Parse(read(t, "relay-empty.json"), nil)
	if err != nil || len(st.Relays) != 0 {
		t.Fatalf("%v %+v", err, st)
	}
	_, _, _, err = Switch(read(t, "relay-empty.json"), nil, "x", "relay-out-1")
	if !errors.Is(err, ErrNoRelay) {
		t.Fatalf("want ErrNoRelay, got %v", err)
	}
}

func TestSwitchAndBack(t *testing.T) {
	r0, l0 := read(t, "relay.json"), read(t, "relay_links.json")
	r1, l1, from, err := Switch(r0, l0, "shadowsocks-in-20001", "relay-out-20002")
	if err != nil || from != "relay-out-20001" {
		t.Fatal(err, from)
	}
	st, _ := Parse(r1, l1)
	if st.Relays[0].Outbound != "relay-out-20002" || st.Relays[0].LandingAddr != "203.0.113.20:443" || st.Relays[0].LandingType != "shadowsocks" {
		t.Fatalf("after switch %+v", st.Relays[0])
	}
	// 另一条中转不受影响
	if st.Relays[1].Outbound != "relay-out-20002" || st.Relays[1].NodeName != "US-01" {
		t.Fatalf("other relay changed %+v", st.Relays[1])
	}
	// 键顺序保持：inbounds 仍在 outbounds 前，密码等字段原样保留
	if strings.Index(string(r1), `"inbounds"`) > strings.Index(string(r1), `"outbounds"`) || !strings.Contains(string(r1), "FAKE-landing-b") {
		t.Fatal("order/content not preserved")
	}
	r2, l2, from2, err := Switch(r1, l1, "shadowsocks-in-20001", from)
	if err != nil || from2 != "relay-out-20002" {
		t.Fatal(err)
	}
	st2, _ := Parse(r2, l2)
	if st2.Relays[0].Outbound != "relay-out-20001" || st2.Relays[0].LandingAddr != "203.0.113.10:8443" || st2.Relays[0].LandingType != "vless" {
		t.Fatalf("after rollback %+v", st2.Relays[0])
	}
	// IPv6 落地按脚本写法不加括号；https 标签
	_, l3, _, err := Switch(r0, l0, "shadowsocks-in-20001", "relay-out-20003")
	if err != nil || !strings.Contains(string(l3), `"landing_addr": "2001:db8::30:8080"`) || !strings.Contains(string(l3), `"landing_type": "https"`) {
		t.Fatalf("ipv6/https links: %v\n%s", err, l3)
	}
}

func TestSwitchErrors(t *testing.T) {
	r0, l0 := read(t, "relay.json"), read(t, "relay_links.json")
	if _, _, _, err := Switch(r0, l0, "shadowsocks-in-20001", "relay-out-20001"); !errors.Is(err, ErrNoop) {
		t.Fatal(err)
	}
	if _, _, _, err := Switch(r0, l0, "nope", "relay-out-20002"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, _, _, err := Switch(r0, l0, "shadowsocks-in-20001", "relay-out-99999"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, bad := range []string{"direct", "ai", "relay-out-1;rm", "../x", ""} {
		if _, _, _, err := Switch(r0, l0, "shadowsocks-in-20001", bad); err == nil {
			t.Fatalf("accepted bad target %q", bad)
		}
	}
	// 没有 relay_links.json 时不生成它
	_, nl, _, err := Switch(r0, nil, "shadowsocks-in-20001", "relay-out-20002")
	if err != nil || nl != nil {
		t.Fatal(err, nl)
	}
}

// 用真实 sing-box 1.14.3 check 切换结果（SINGBOX_BIN 未设置则跳过）。
func TestSingboxCheck(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("SINGBOX_BIN 未设置")
	}
	r1, _, _, err := Switch(read(t, "relay.json"), read(t, "relay_links.json"), "shadowsocks-in-20001", "relay-out-20002")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "relay.json")
	os.WriteFile(p, r1, 0600)
	out, err := exec.Command(bin, "check", "-c", filepath.Join("..", "..", "testdata", "config.json"), "-c", p).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check 失败: %v %s", err, out)
	}
}
