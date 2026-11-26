package tgbot

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"sbrelay/internal/relaycfg"
	"sbrelay/internal/store"
)

type expectKind string

const (
	expectAddRelay       expectKind = "add_relay"
	expectAddLanding     expectKind = "add_landing"
	expectRenameRelay    expectKind = "rename_relay"
	expectRenameLanding  expectKind = "rename_landing"
	expectNameThenSwitch expectKind = "name_then_switch"
)

type expect struct {
	Kind      expectKind
	Machine   string
	Tag       string // 落地 outbound tag
	Inbound   string
	Chat, Mid int64
}

func (b *Bot) setExpect(uid int64, e expect) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.expect == nil {
		b.expect = map[int64]expect{}
	}
	b.expect[uid] = e
}

func (b *Bot) popExpect(uid int64) (expect, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.expect[uid]
	if ok {
		delete(b.expect, uid)
	}
	return e, ok
}

func (b *Bot) peekExpect(uid int64) (expect, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.expect[uid]
	return e, ok
}

func (b *Bot) clearExpect(uid int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.expect, uid)
}

func hintsFromStatus(st *relaycfg.Status) []store.LandingHint {
	if st == nil {
		return nil
	}
	fromRelay := map[string]string{}
	for _, r := range st.Relays {
		if r.Outbound != "" && r.NodeName != "" && fromRelay[r.Outbound] == "" {
			fromRelay[r.Outbound] = r.NodeName
		}
	}
	seen := map[string]bool{}
	var hs []store.LandingHint
	for _, c := range st.Candidates {
		if c.Tag == "" || seen[c.Tag] {
			continue
		}
		seen[c.Tag] = true
		hs = append(hs, store.LandingHint{Tag: c.Tag, NodeName: fromRelay[c.Tag]})
	}
	for tag, n := range fromRelay {
		if seen[tag] {
			continue
		}
		hs = append(hs, store.LandingHint{Tag: tag, NodeName: n})
	}
	return hs
}

func (b *Bot) seedFromRaw(id string, raw []byte) {
	if st := parseStatus(raw); st != nil {
		b.st.SeedLandingDefaults(id, hintsFromStatus(st))
	}
}

func (b *Bot) landingName(mid, tag string) (string, bool) {
	n := b.st.LandingName(mid, tag)
	if n == "" {
		return "", false
	}
	return n, true
}

// landingTitle 面板主文案用显示名；未起名时用「未命名落地」。debug 为内部 tag，调用方按需附加。
func (b *Bot) landingTitle(mid, tag string) (title string, named bool) {
	if n, ok := b.landingName(mid, tag); ok {
		return n, true
	}
	return "未命名落地", false
}

func (b *Bot) relayTitle(m *store.Machine) string {
	if m == nil {
		return "线路机"
	}
	if m.Name != "" {
		return m.Name
	}
	return "未命名线路机"
}

func askNamePrompt(kind expectKind) string {
	switch kind {
	case expectAddRelay:
		return "请发送这台线路机的显示名，" + store.NameHint + "。线路机之间不能重名。\n发 /cancel 取消。"
	case expectAddLanding:
		return "请发送这台落地机的显示名，" + store.NameHint + "。落地机之间不能重名。\n发 /cancel 取消。"
	case expectRenameRelay:
		return "请发送线路机的新显示名，" + store.NameHint + "。线路机之间不能重名。\n发 /cancel 取消。"
	case expectRenameLanding:
		return "请发送这个落地的新显示名，" + store.NameHint + "。同一条线路机下的落地不能重名。\n发 /cancel 取消。"
	case expectNameThenSwitch:
		return "请先给这个落地起个显示名，" + store.NameHint + "。同一条线路机下的落地不能重名。起名后再确认切换。\n发 /cancel 取消。"
	default:
		return "请发送显示名，" + store.NameHint + "。\n发 /cancel 取消。"
	}
}

// applyName 处理改名/起名输入。ok=false 表示校验失败应保持等待并重试。
// 成功时返回要发给用户的面板正文和按钮。
func (b *Bot) applyName(e expect, text string) (reply string, k *Keyboard, retry bool, err error) {
	switch e.Kind {
	case expectAddRelay, expectAddLanding:
		role := store.RoleRelay
		kind := "线路机"
		if e.Kind == expectAddLanding {
			role = store.RoleLanding
			kind = "落地机"
		}
		tok, err := b.st.NewMachineInstallToken(text, role, 2*time.Hour)
		if err != nil {
			return store.NameErrorText(err), nil, true, err
		}
		script := b.InstallScript(tok.Token)
		msg := fmt.Sprintf("%s「%s」安装命令（2 小时内有效，只能用一次）。在机器上以 root 执行（建议先 export HISTCONTROL=ignorespace；命令行首有空格，尽量不进历史）：\n\n<pre>%s</pre>", kind, tok.Name, escape(script))
		return msg, nil, false, nil
	case expectRenameRelay:
		err := b.st.SetRelayName(e.Machine, text)
		if err != nil {
			return store.NameErrorText(err), nil, !isUnchanged(err), err
		}
		t, kb, _ := b.machineText(e.Machine)
		return "已改名为「" + b.st.RelayDisplayName(e.Machine) + "」。\n\n" + t, kb, false, nil
	case expectRenameLanding, expectNameThenSwitch:
		err := b.st.SetLandingName(e.Machine, e.Tag, text)
		if err != nil {
			return store.NameErrorText(err), nil, !isUnchanged(err), err
		}
		name := b.st.LandingName(e.Machine, e.Tag)
		if e.Kind == expectNameThenSwitch {
			pid := b.putPend(fmt.Sprintf("%s|%s|%s", e.Machine, e.Inbound, e.Tag))
			t, kb := b.confirmText(pid)
			return "已把这个落地命名为「" + name + "」。\n\n" + t, kb, false, nil
		}
		t, kb, _ := b.machineText(e.Machine)
		return "已把落地改名为「" + name + "」。\n\n" + t, kb, false, nil
	default:
		return "不知道这个输入是要做什么，已取消。", nil, false, nil
	}
}

func isUnchanged(err error) bool {
	return errors.Is(err, store.ErrNameUnchanged)
}

func debugTag(tag string) string {
	if tag == "" {
		return ""
	}
	return "（" + tag + "）"
}

func (b *Bot) landingRenameList(id string) (string, *Keyboard) {
	m := b.st.Machine(id)
	if m == nil {
		return "找不到这台机器。", kb(row(Btn{Text: "返回", Data: "home"}))
	}
	st := parseStatus(m.LastJSON)
	if st == nil || len(st.Candidates) == 0 {
		return "还没有可改名的落地。", kb(row(Btn{Text: "返回", Data: "m:" + id}))
	}
	b.st.SeedLandingDefaults(id, hintsFromStatus(st))
	var sb strings.Builder
	sb.WriteString("选择要改名的落地：\n")
	var rows [][]Btn
	for _, c := range st.Candidates {
		name, named := b.landingTitle(id, c.Tag)
		if !named {
			name = "未命名落地"
		}
		fmt.Fprintf(&sb, "· %s%s\n", name, debugTag(c.Tag))
		pid := b.putPend(id + "|" + c.Tag)
		rows = append(rows, row(Btn{Text: "重命名「" + name + "」", Data: "rl:" + pid}))
	}
	rows = append(rows, row(Btn{Text: "返回", Data: "m:" + id}))
	return strings.TrimRight(sb.String(), "\n"), kb(rows...)
}

func (b *Bot) formatSwitchResult(op, mid string, raw json.RawMessage) string {
	var r struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
		Error   string `json:"error"`
		Code    string `json:"code"`
		From    string `json:"from"`
		To      string `json:"to"`
		Inbound string `json:"inbound"`
		Backup  string `json:"backup"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return op + "完成，但结果无法解析。"
	}
	if r.Code == "no_relay" || r.Error == "没有中转可切换" {
		return "没有中转可切换。请先按 singbox-lite 正规路径导入落地 Token。"
	}
	if !r.OK {
		msg := r.Error
		if msg == "" {
			msg = r.Message
		}
		return op + "失败：" + msg
	}
	from, _ := b.landingTitle(mid, r.From)
	to, _ := b.landingTitle(mid, r.To)
	s := fmt.Sprintf("%s成功。\n线路机「%s」：%s → %s", op, b.st.RelayDisplayName(mid), from, to)
	if r.Inbound != "" {
		s += "\n（内部：" + r.Inbound + "：" + r.From + " → " + r.To + "）"
	}
	if r.Backup != "" {
		s += "\n备份：" + r.Backup
	}
	return s
}
