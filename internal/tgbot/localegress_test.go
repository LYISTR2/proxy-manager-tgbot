package tgbot

import (
	"encoding/json"
	"strings"
	"testing"

	"sbrelay/internal/relaycfg"
	"sbrelay/internal/store"
)

func findBtn(kb *Keyboard, text string) *Btn {
	if kb == nil {
		return nil
	}
	for _, r := range kb.InlineKeyboard {
		for i := range r {
			if strings.Contains(r[i].Text, text) {
				return &r[i]
			}
		}
	}
	return nil
}

// 选落地列表里有「本机直出」，选它生成的待确认项不带落地机（不需要落地 agent）。
func TestPickTextOffersLocalEgress(t *testing.T) {
	b, _, id := testBot(t)
	_, kb := b.pickText(id, 0)
	btn := findBtn(kb, "切到「本机直出」")
	if btn == nil || !strings.HasPrefix(btn.Data, "c:") {
		t.Fatalf("missing local egress option: %+v", kb)
	}
	pend := b.getPend(strings.TrimPrefix(btn.Data, "c:"))
	if pend != id+"|shadowsocks-in-20001|"+relaycfg.LocalEgressTag {
		t.Fatalf("pending: %q", pend)
	}
	ct, ckb := b.confirmText(strings.TrimPrefix(btn.Data, "c:"))
	if !strings.Contains(ct, "本机直出") || !strings.Contains(ct, "不经任何落地") || !strings.Contains(ct, "入站地址和密码不会改") {
		t.Fatalf("confirm text: %s", ct)
	}
	if findBtn(ckb, "确认切换") == nil {
		t.Fatal("no confirm button")
	}
	// 本机直出已被命名，不会要求先起名
	if _, named := b.outboundLabel(id, relaycfg.LocalEgressTag); !named {
		t.Fatal("local egress should be named")
	}
}

// 没有任何落地机时也能选本机直出。
func TestPickTextLocalEgressWithoutLandings(t *testing.T) {
	b, st, id := testBot(t)
	if err := st.With(func(s *store.State) error {
		s.Machines[id].LastJSON = json.RawMessage(`{"ok":true,"status":{"relays":[{"inbound":"sbrelay-ss2022-in","outbound":"relay-out-x"}],"candidates":[]}}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pt, kb := b.pickText(id, 0)
	if findBtn(kb, "切到「本机直出」") == nil || !strings.Contains(pt, "本机直出") {
		t.Fatalf("local egress should be offered without landings: %s %+v", pt, kb)
	}
}

// 当前就是本机直出：状态显示「当前出口：本机直出」，列表里标（当前）且不可再选。
func TestStatusShowsLocalEgress(t *testing.T) {
	b, st, id := testBot(t)
	if err := st.With(func(s *store.State) error {
		s.Machines[id].LastJSON = json.RawMessage(`{"ok":true,"status":{
			"relays":[
				{"inbound":"shadowsocks-in-20001","outbound":"sbrelay-local-direct","landing_type":"direct"},
				{"inbound":"shadowsocks-in-20002","outbound":"relay-out-20002","node_name":"Landing-B"}
			],
			"candidates":[{"tag":"relay-out-20002","type":"shadowsocks","label":"shadowsocks","server":"82.0.0.1","port":8888}]}}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mt, _, _ := b.machineText(id)
	if !strings.Contains(mt, "1. 当前出口：本机直出") || !strings.Contains(mt, "2. 当前落地：Landing-B") {
		t.Fatalf("machine text: %s", mt)
	}
	home, _ := b.homeText()
	if !strings.Contains(home, "本机直出") {
		t.Fatalf("home: %s", home)
	}
	_, kb := b.pickText(id, 0)
	cur := findBtn(kb, "本机直出（当前）")
	if cur == nil || cur.Data != "noop" || findBtn(kb, "切到「本机直出」") != nil {
		t.Fatalf("current local egress should be noop: %+v", kb)
	}
	// 本机直出不会被当成可改名的落地
	for _, h := range hintsFromStatus(parseStatus(st.Machine(id).LastJSON)) {
		if relaycfg.IsLocalEgress(h.Tag) {
			t.Fatalf("local egress in landing hints: %+v", h)
		}
	}
	// 自动入站初始 direct 也显示为本机直出，并视为当前
	if err := st.With(func(s *store.State) error {
		s.Machines[id].LastJSON = json.RawMessage(`{"ok":true,"status":{"relays":[{"inbound":"sbrelay-ss2022-in","outbound":"direct"}],"candidates":[]}}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mt, _, _ = b.machineText(id)
	if !strings.Contains(mt, "当前出口：本机直出（未选落地）") {
		t.Fatalf("direct text: %s", mt)
	}
	_, kb = b.pickText(id, 0)
	if findBtn(kb, "本机直出（当前）") == nil {
		t.Fatalf("direct should count as current local egress: %+v", kb)
	}
}

// 切换/回滚结果里显示「本机直出」而不是内部 tag。
func TestSwitchResultShowsLocalEgress(t *testing.T) {
	b, _, id := testBot(t)
	b.machineText(id) // 打开面板时会按状态给本地落地播种默认名
	s := b.formatSwitchResult("切换", id, json.RawMessage(`{"ok":true,"op":"switch","inbound":"shadowsocks-in-20001","from":"relay-out-20001","to":"sbrelay-local-direct"}`))
	if !strings.Contains(s, "Landing-A → 本机直出") {
		t.Fatalf("switch result: %s", s)
	}
	r := b.formatSwitchResult("回滚", id, json.RawMessage(`{"ok":true,"op":"rollback","inbound":"shadowsocks-in-20001","from":"sbrelay-local-direct","to":"relay-out-20001"}`))
	if !strings.Contains(r, "本机直出 → Landing-A") {
		t.Fatalf("rollback result: %s", r)
	}
}
