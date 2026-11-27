package relaycfg

import (
	"encoding/json"
	"errors"
	"testing"
)

func inboundsJSON(t *testing.T, relay []byte) string {
	t.Helper()
	// 按语义比较（解析后再序列化），不受缩进影响
	var m map[string]any
	if err := json.Unmarshal(relay, &m); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m["inbounds"])
	return string(b)
}

func outboundsByTag(t *testing.T, relay []byte) map[string]map[string]any {
	t.Helper()
	var m struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(relay, &m); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, o := range m.Outbounds {
		tag, _ := o["tag"].(string)
		if _, dup := out[tag]; dup {
			t.Fatalf("duplicate outbound tag %s", tag)
		}
		out[tag] = o
	}
	return out
}

// 脚本建的中转（非自动入站）切到本机直出，再切回落地。
func TestSwitchToLocalEgressAndBack(t *testing.T) {
	r0, l0 := read(t, "relay.json"), read(t, "relay_links.json")
	nr, nl, from, err := Switch(r0, l0, "shadowsocks-in-20001", LocalEgressTag)
	if err != nil || from != "relay-out-20001" || nl == nil {
		t.Fatalf("switch to local: %v from=%q", err, from)
	}
	// 入站（客户端参数）一字不改
	if inboundsJSON(t, nr) != inboundsJSON(t, r0) {
		t.Fatal("inbounds changed")
	}
	outs := outboundsByTag(t, nr)
	lo := outs[LocalEgressTag]
	if lo == nil || lo["type"] != "direct" || len(lo) != 2 {
		t.Fatalf("local egress outbound: %+v", lo)
	}
	// 原有落地出站都保留，方便切回/回滚
	for _, tag := range []string{"relay-out-20001", "relay-out-20002", "relay-out-20003"} {
		if outs[tag] == nil {
			t.Fatalf("outbound %s removed", tag)
		}
	}
	st, err := Parse(nr, nl)
	if err != nil || len(st.Relays) != 2 {
		t.Fatalf("parse: %v %+v", err, st)
	}
	r := st.Relays[0]
	if r.Inbound != "shadowsocks-in-20001" || r.Outbound != LocalEgressTag || r.LandingAddr != "" || r.LandingType != "direct" {
		t.Fatalf("relay after local: %+v", r)
	}
	if !IsLocalEgress(r.Outbound) || st.Relays[1].Outbound != "relay-out-20002" {
		t.Fatalf("other relay or flag wrong: %+v", st.Relays)
	}
	// 本机直出不是落地候选
	for _, c := range st.Candidates {
		if c.Tag == LocalEgressTag {
			t.Fatal("local egress listed as landing candidate")
		}
	}
	// 再选本机直出：无需改动
	if _, _, _, err := Switch(nr, nl, "shadowsocks-in-20001", LocalEgressTag); !errors.Is(err, ErrNoop) {
		t.Fatalf("expected noop, got %v", err)
	}
	// 切回原落地（即回滚方向）
	nr2, nl2, from2, err := Switch(nr, nl, "shadowsocks-in-20001", "relay-out-20001")
	if err != nil || from2 != LocalEgressTag {
		t.Fatalf("back to landing: %v %q", err, from2)
	}
	st2, _ := Parse(nr2, nl2)
	if st2.Relays[0].Outbound != "relay-out-20001" || st2.Relays[0].LandingAddr != "203.0.113.10:8443" {
		t.Fatalf("after back: %+v", st2.Relays[0])
	}
	// 再切一次本机直出也不会重复添加出站
	nr3, _, _, err := Switch(nr2, nl2, "shadowsocks-in-20001", LocalEgressTag)
	if err != nil {
		t.Fatal(err)
	}
	outboundsByTag(t, nr3)
}

// 自动入站：初始 direct 视同本机直出；从落地切到本机直出；本机直出不接受落地参数。
func TestAutoRelayLocalEgress(t *testing.T) {
	initial := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"sbrelay-ss2022-in","listen":"::","listen_port":31234,"method":"2022-blake3-aes-128-gcm","password":"FAKE-RELAY-SS2022-PASSWORD=="}],"outbounds":[],"route":{"rules":[{"inbound":"sbrelay-ss2022-in","outbound":"direct"}]}}`)
	if _, _, from, err := Switch(initial, nil, AutoRelayInTag, LocalEgressTag); !errors.Is(err, ErrNoop) || from != "direct" {
		t.Fatalf("direct -> local should be noop: %v %q", err, from)
	}
	spec := &OutboundSpec{Tag: "relay-out-land01", Type: "shadowsocks", Server: "198.51.100.20", Port: 41234, Method: "2022-blake3-aes-128-gcm", Password: "FAKE-LANDING-SS2022-KEY=="}
	nr, _, _, err := SwitchWithSpec(initial, nil, AutoRelayInTag, "relay-out-land01", spec)
	if err != nil {
		t.Fatal(err)
	}
	nr2, nl2, from, err := Switch(nr, nil, AutoRelayInTag, LocalEgressTag)
	if err != nil || nl2 != nil || from != "relay-out-land01" {
		t.Fatalf("landing -> local: %v %q", err, from)
	}
	if inboundsJSON(t, nr2) != inboundsJSON(t, initial) {
		t.Fatal("inbounds changed")
	}
	st, _ := Parse(nr2, nil)
	if len(st.Relays) != 1 || st.Relays[0].Outbound != LocalEgressTag || st.RelayNode == nil || st.RelayNode.Port != 31234 {
		t.Fatalf("status: %+v", st)
	}
	if _, _, _, err := SwitchWithSpec(nr, nil, AutoRelayInTag, LocalEgressTag, spec); err == nil {
		t.Fatal("local egress with spec should be rejected")
	}
}

// relay.json 里已有同名但类型不对的出站时改正为 direct。
func TestLocalEgressFixesWrongType(t *testing.T) {
	r := []byte(`{"inbounds":[{"type":"shadowsocks","tag":"in-1","listen_port":20001,"method":"aes-128-gcm","password":"FAKE"}],"outbounds":[{"type":"shadowsocks","tag":"relay-out-1","server":"203.0.113.1","server_port":1,"method":"aes-128-gcm","password":"FAKE"},{"type":"block","tag":"sbrelay-local-direct"}],"route":{"rules":[{"inbound":"in-1","outbound":"relay-out-1"}]}}`)
	nr, _, _, err := Switch(r, nil, "in-1", LocalEgressTag)
	if err != nil {
		t.Fatal(err)
	}
	if o := outboundsByTag(t, nr)[LocalEgressTag]; o["type"] != "direct" {
		t.Fatalf("local egress type: %+v", o)
	}
}

func TestIsLocalEgress(t *testing.T) {
	for tag, want := range map[string]bool{LocalEgressTag: true, "direct": true, "relay-out-1": false, "": false, "relay-out-local": false} {
		if IsLocalEgress(tag) != want {
			t.Fatalf("IsLocalEgress(%q) != %v", tag, want)
		}
	}
}
