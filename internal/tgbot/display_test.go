package tgbot

import (
	"encoding/json"
	"strings"
	"testing"

	"sbrelay/internal/relaycfg"
	"sbrelay/internal/store"
)

func sampleStatus() json.RawMessage {
	return json.RawMessage(`{
		"ok": true,
		"status": {
			"relays": [
				{"inbound":"shadowsocks-in-20001","outbound":"relay-out-20001","node_name":"Landing-A","landing_addr":"82.0.0.1:8888"},
				{"inbound":"shadowsocks-in-20002","outbound":"relay-out-20002","node_name":"Landing-B","landing_addr":"82.0.0.1:8888"}
			],
			"candidates": [
				{"tag":"relay-out-20001","type":"shadowsocks","label":"shadowsocks","server":"82.0.0.1","port":8888},
				{"tag":"relay-out-20002","type":"shadowsocks","label":"shadowsocks","server":"82.0.0.1","port":8888}
			]
		}
	}`)
}

func testBot(t *testing.T) (*Bot, *store.Store, string) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "aabbccddeeff0011"
	if err := st.With(func(s *store.State) error {
		s.Machines[id] = &store.Machine{ID: id, Name: "HK-01", Role: store.RoleRelay, LastJSON: sampleStatus(), Online: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b := &Bot{st: st, pend: map[string]string{}, wait: map[string]chan json.RawMessage{}, expect: map[int64]expect{}}
	return b, st, id
}

func TestPanelUsesDefaultDisplayNames(t *testing.T) {
	b, _, id := testBot(t)
	home, _ := b.homeText()
	if !strings.Contains(home, "HK-01") || !strings.Contains(home, "Landing-A") || !strings.Contains(home, "Landing-B") {
		t.Fatalf("home: %s", home)
	}
	// 首页不要只甩出 IP 当主文案
	if strings.Contains(home, "82.0.0.1") {
		t.Fatalf("home should not lead with IP: %s", home)
	}
	mt, kb, _ := b.machineText(id)
	if !strings.Contains(mt, "HK-01") || !strings.Contains(mt, "当前落地：Landing-A") || !strings.Contains(mt, "Landing-B") {
		t.Fatalf("machine: %s", mt)
	}
	if !strings.Contains(mt, "不改线路入站") {
		t.Fatalf("should mention inbound unchanged: %s", mt)
	}
	hasRename := false
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			if btn.Data == "nr:"+id || strings.HasPrefix(btn.Data, "nl:") {
				hasRename = true
			}
		}
	}
	if !hasRename {
		t.Fatalf("missing rename buttons: %+v", kb)
	}
	pt, pkb := b.pickText(id, 0)
	if !strings.Contains(pt, "Landing-A") || !strings.Contains(pt, "不改入站") {
		t.Fatalf("pick: %s", pt)
	}
	if strings.Contains(pt, "切到「Landing-A」") {
		t.Fatal("current landing should not be a switch target")
	}
	foundB := false
	for _, row := range pkb.InlineKeyboard {
		for _, btn := range row {
			if strings.Contains(btn.Text, "Landing-B") {
				foundB = true
			}
			if strings.Contains(btn.Text, "82.0.0.1") {
				t.Fatalf("button should use display name, not IP: %s", btn.Text)
			}
		}
	}
	if !foundB {
		t.Fatalf("pick buttons: %+v", pkb)
	}
}

func TestRenameVisibleImmediately(t *testing.T) {
	b, st, id := testBot(t)
	_, _ = b.homeText() // seed defaults
	reply, _, retry, err := b.applyName(expect{Kind: expectRenameRelay, Machine: id}, "香港一号")
	if err != nil || retry || !strings.Contains(reply, "已改名为「香港一号」") {
		t.Fatalf("rename relay: retry=%v err=%v %s", retry, err, reply)
	}
	home, _ := b.homeText()
	if !strings.Contains(home, "香港一号") || strings.Contains(home, "● HK-01") {
		t.Fatalf("home after rename: %s", home)
	}
	if st.RelayDisplayName(id) != "香港一号" {
		t.Fatal("store not updated")
	}
	reply, _, retry, err = b.applyName(expect{Kind: expectRenameLanding, Machine: id, Tag: "relay-out-20001"}, "东京")
	if err != nil || retry || !strings.Contains(reply, "已把落地改名为「东京」") {
		t.Fatalf("rename landing: %v %v %s", retry, err, reply)
	}
	home, _ = b.homeText()
	if !strings.Contains(home, "东京") || strings.Contains(home, "Landing-A") {
		t.Fatalf("home after landing rename: %s", home)
	}
	mt, _, _ := b.machineText(id)
	if !strings.Contains(mt, "当前落地：东京") {
		t.Fatalf("machine: %s", mt)
	}
	// 确认文案用显示名，内部 tag 只作调试
	pid := b.putPend(id + "|shadowsocks-in-20001|relay-out-20002")
	ct, _ := b.confirmText(pid)
	if !strings.Contains(ct, "线路机「香港一号」") || !strings.Contains(ct, "落地「Landing-B」") {
		t.Fatalf("confirm: %s", ct)
	}
	if !strings.Contains(ct, "shadowsocks-in-20001") { // 调试附加
		t.Fatalf("confirm should still attach internal tag: %s", ct)
	}
}

func TestApplyNameValidation(t *testing.T) {
	b, _, id := testBot(t)
	_, _ = b.homeText()
	for _, text := range []string{"", "   "} {
		reply, _, retry, err := b.applyName(expect{Kind: expectRenameRelay, Machine: id}, text)
		if !retry || !strings.Contains(reply, "不能为空") || !strings.Contains(reply, "1–32 个字") {
			t.Fatalf("empty %q: retry=%v err=%v %s", text, retry, err, reply)
		}
	}
	reply, _, retry, _ := b.applyName(expect{Kind: expectRenameRelay, Machine: id}, strings.Repeat("香", 33))
	if !retry || !strings.Contains(reply, "最多 32 个字") || !strings.Contains(reply, "你输入了 33 个") {
		t.Fatalf("too long: %s", reply)
	}
	if _, _, retry, _ := b.applyName(expect{Kind: expectRenameRelay, Machine: id}, "香港一号"); retry {
		t.Fatal("valid rename should not retry")
	}
	// 第二台线路机不能叫同一个名字
	if err := b.st.With(func(s *store.State) error {
		s.Machines["other"] = &store.Machine{ID: "other", Name: "备用", Role: store.RoleRelay}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reply, _, retry, _ = b.applyName(expect{Kind: expectRenameRelay, Machine: "other"}, "香港一号")
	if !retry || !strings.Contains(reply, "已有线路机叫「香港一号」") {
		t.Fatalf("dup relay: %s", reply)
	}
	reply, _, retry, _ = b.applyName(expect{Kind: expectRenameLanding, Machine: id, Tag: "relay-out-20002"}, "Landing-A")
	if !retry || !strings.Contains(reply, "已有落地叫「Landing-A」") {
		t.Fatalf("dup landing: %s", reply)
	}
}

func TestNameThenSwitchAndUnnamed(t *testing.T) {
	b, _, id := testBot(t)
	// 一个没有 node_name 的新出站，不会被 seed
	raw := json.RawMessage(`{
		"ok": true,
		"status": {
			"relays": [
				{"inbound":"shadowsocks-in-20001","outbound":"relay-out-20001","node_name":"Landing-A"}
			],
			"candidates": [
				{"tag":"relay-out-20001","type":"shadowsocks","server":"82.0.0.1","port":8888},
				{"tag":"relay-out-20099","type":"shadowsocks","server":"203.0.113.2","port":443}
			]
		}
	}`)
	if err := b.st.With(func(s *store.State) error {
		s.Machines[id].LastJSON = raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pt, kb := b.pickText(id, 0)
	if !strings.Contains(pt, "Landing-A") {
		t.Fatal(pt)
	}
	foundNameFirst := false
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			if btn.Text == "起名并切到这个落地" && strings.HasPrefix(btn.Data, "ns:") {
				foundNameFirst = true
			}
		}
	}
	if !foundNameFirst {
		t.Fatalf("unnamed landing should require naming first: %+v", kb)
	}
	reply, ckb, retry, err := b.applyName(expect{Kind: expectNameThenSwitch, Machine: id, Tag: "relay-out-20099", Inbound: "shadowsocks-in-20001"}, "备用落地")
	if err != nil || retry || !strings.Contains(reply, "已把这个落地命名为「备用落地」") || !strings.Contains(reply, "切到落地「备用落地」") {
		t.Fatalf("name then switch: %v %v %s", retry, err, reply)
	}
	if ckb == nil {
		t.Fatal("expected confirm keyboard")
	}
}

func TestAddRelayRequiresName(t *testing.T) {
	b, _, _ := testBot(t)
	prompt := askNamePrompt(expectAddRelay)
	if !strings.Contains(prompt, "1–32 个字") || !strings.Contains(prompt, "不能重名") {
		t.Fatal(prompt)
	}
	reply, _, retry, _ := b.applyName(expect{Kind: expectAddRelay}, "")
	if !retry || !strings.Contains(reply, "不能为空") {
		t.Fatalf("%s", reply)
	}
	reply, _, retry, _ = b.applyName(expect{Kind: expectAddRelay}, "HK-01")
	if !retry || !strings.Contains(reply, "已有线路机叫「HK-01」") {
		t.Fatalf("%s", reply)
	}
	reply, _, retry, err := b.applyName(expect{Kind: expectAddRelay}, "新线路")
	if err != nil || retry || !strings.Contains(reply, "线路机「新线路」安装命令") {
		t.Fatalf("%v %v %s", retry, err, reply)
	}
}

func TestPickTextNilMachineAndBoundLandingFlow(t *testing.T) {
	b, st, id := testBot(t)
	// 不存在的机器不应 panic
	pt, _ := b.pickText("missing-id", 0)
	if !strings.Contains(pt, "找不到") {
		t.Fatalf("missing machine: %s", pt)
	}
	// 绑定一台落地机并上报 SS2022 信息
	if err := st.With(func(s *store.State) error {
		s.Machines["l1"] = &store.Machine{
			ID:     "l1",
			Name:   "JP<Tokyo>",
			Role:   store.RoleLanding,
			Online: true,
			LandingNode: &relaycfg.NodeInfo{
				Tag:      relaycfg.AutoLandingTag,
				Type:     "shadowsocks",
				Server:   "198.51.100.10",
				Port:     34567,
				Method:   "2022-blake3-aes-128-gcm",
				Password: "AAAAAAAAAAAAAAAAAAAAAA==",
			},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	home, _ := b.homeText()
	if !strings.Contains(home, "JP&lt;Tokyo&gt;") || !strings.Contains(home, "已就绪") {
		t.Fatalf("home should show escaped bound landing: %s", home)
	}
	pt, pkb := b.pickText(id, 0)
	found := false
	for _, r := range pkb.InlineKeyboard {
		for _, btn := range r {
			if strings.Contains(btn.Text, "JP<Tokyo>") && strings.HasPrefix(btn.Data, "c:") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("pickText should include bound landing machine: %s %+v", pt, pkb)
	}
	// 切换失败结果不应覆盖已有的 LastJSON
	b.ingestStatus(id, json.RawMessage(`{"ok":false,"op":"switch","error":"boom"}`))
	if parseStatus(st.Machine(id).LastJSON) == nil {
		t.Fatal("failed switch result overwrote valid status")
	}
}

func TestSwitchLandingButtonText(t *testing.T) {
	if got := switchLandingButtonText(0, 1); got != "换落地" {
		t.Fatalf("single: %s", got)
	}
	if got := switchLandingButtonText(0, 2); got != "给第 1 条中转换落地" {
		t.Fatalf("first of many: %s", got)
	}
	if got := switchLandingButtonText(1, 2); got != "给第 2 条中转换落地" {
		t.Fatalf("second of many: %s", got)
	}
}

func collectBtn(kb *Keyboard, prefix string) []string {
	var out []string
	if kb == nil {
		return out
	}
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			if strings.HasPrefix(btn.Data, prefix) {
				out = append(out, btn.Text)
			}
		}
	}
	return out
}

func TestMachineTextSwitchButtons(t *testing.T) {
	b, st, id := testBot(t)
	_, kb, _ := b.machineText(id)
	got := collectBtn(kb, "r:"+id+":")
	if len(got) != 2 || got[0] != "给第 1 条中转换落地" || got[1] != "给第 2 条中转换落地" {
		t.Fatalf("multi buttons: %v", got)
	}

	// 只留一条可切换入站
	if err := st.With(func(s *store.State) error {
		s.Machines[id].LastJSON = json.RawMessage(`{
			"ok": true,
			"status": {
				"relays": [
					{"inbound":"sbrelay-ss2022-in","outbound":"relay-out-20001","node_name":"Landing-A"}
				],
				"candidates": [
					{"tag":"relay-out-20001","type":"shadowsocks","label":"shadowsocks"}
				]
			}
		}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, kb, _ = b.machineText(id)
	got = collectBtn(kb, "r:"+id+":")
	if len(got) != 1 || got[0] != "换落地" {
		t.Fatalf("single button: %v", got)
	}
	for _, t2 := range got {
		if strings.Contains(t2, "给第") {
			t.Fatalf("single inbound should not use 给第: %s", t2)
		}
	}
}
