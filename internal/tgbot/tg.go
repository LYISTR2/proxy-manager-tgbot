// Package tgbot 是控制端：Telegram 面板 + agent 长轮询 HTTPS。
package tgbot

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"sbrelay/internal/redact"
	"sbrelay/internal/relaycfg"
	"sbrelay/internal/store"
)

type Config struct {
	Token     string
	DataDir   string
	Listen    string // 例如 :8443
	CertFile  string
	KeyFile   string
	PublicURL string // https://host:8443，写入安装脚本
	OwnerHint int64  // 环境变量预置的管理员 id，0 则首次 /start 绑定
	MachineID string // 仅 agent 用
	PkgDir    string // 下发给 agent 的二进制与安装脚本目录
}

type Bot struct {
	cfg     Config
	st      *store.Store
	http    *http.Client
	pin     string // 证书 DER SHA-256 hex，给 agent 校验
	spkiPin string // sha256//Base64(SPKI)，给 curl --pinnedpubkey
	// pending 把短回调映射到完整参数（避开 TG 64 字节限制）
	mu        sync.Mutex
	pend      map[string]string
	pendOrder []string
	wait      map[string]chan json.RawMessage // cmd id -> result
	expect    map[int64]expect                // 等待管理员发来的显示名
	nonceSeen map[string]int64                // machineID+nonce -> 过期 unix，防重放
	inFlight  map[string]bool                 // machineID -> 正在执行远程操作，防并发连点
	notified  map[string]bool                 // machineID -> 已推送过自动搭建的 SS2022 节点通知
}

func New(cfg Config) (*Bot, error) {
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.OwnerHint != 0 && st.Owner() == 0 {
		_ = st.SetOwner(cfg.OwnerHint)
	}
	return &Bot{
		cfg:       cfg,
		st:        st,
		http:      &http.Client{Timeout: 45 * time.Second},
		pend:      map[string]string{},
		wait:      map[string]chan json.RawMessage{},
		expect:    map[int64]expect{},
		nonceSeen: map[string]int64{},
		inFlight:  map[string]bool{},
		notified:  map[string]bool{},
	}, nil
}

func (b *Bot) Store() *store.Store { return b.st }

func (b *Bot) SetPin(p string) { b.pin = p }

func (b *Bot) SetPins(certHex, spki string) {
	b.pin = certHex
	b.spkiPin = spki
}

// ---------- Telegram 低层 ----------

type tgResp struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}
type Update struct {
	ID      int64    `json:"update_id"`
	Message *Message `json:"message"`
	CB      *CBQ     `json:"callback_query"`
}
type Message struct {
	ID   int64  `json:"message_id"`
	Text string `json:"text"`
	Chat *Chat  `json:"chat"`
	From *User  `json:"from"`
}
type Chat struct {
	ID int64 `json:"id"`
}
type User struct {
	ID int64 `json:"id"`
}
type CBQ struct {
	ID      string   `json:"id"`
	From    *User    `json:"from"`
	Data    string   `json:"data"`
	Message *Message `json:"message"`
}
type Keyboard struct {
	InlineKeyboard [][]Btn `json:"inline_keyboard"`
}
type Btn struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func (b *Bot) api(method string, payload any) (json.RawMessage, error) {
	if b.http == nil {
		return nil, fmt.Errorf("http client 未初始化")
	}
	var body io.Reader
	if payload != nil {
		j, _ := json.Marshal(payload)
		body = bytes.NewReader(j)
	}
	req, _ := http.NewRequest("POST", "https://api.telegram.org/bot"+b.cfg.Token+"/"+method, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr tgResp
	if err := json.Unmarshal(raw, &tr); err != nil {
		return nil, err
	}
	if !tr.OK {
		return nil, fmt.Errorf("telegram: %s", tr.Description)
	}
	return tr.Result, nil
}

func (b *Bot) send(chat int64, text string, kb *Keyboard) (int64, error) {
	p := map[string]any{"chat_id": chat, "text": text, "parse_mode": "HTML"}
	if kb != nil {
		p["reply_markup"] = kb
	}
	raw, err := b.api("sendMessage", p)
	if err != nil {
		return 0, err
	}
	var m Message
	json.Unmarshal(raw, &m)
	return m.ID, nil
}

func (b *Bot) edit(chat, mid int64, text string, kb *Keyboard) error {
	p := map[string]any{"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML"}
	if kb != nil {
		p["reply_markup"] = kb
	} else {
		p["reply_markup"] = Keyboard{}
	}
	_, err := b.api("editMessageText", p)
	if err != nil && !strings.Contains(err.Error(), "message is not modified") {
		return err
	}
	return nil
}

func (b *Bot) answer(id, text string) {
	_, _ = b.api("answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text})
}

func row(btns ...Btn) []Btn      { return btns }
func kb(rows ...[]Btn) *Keyboard { return &Keyboard{InlineKeyboard: rows} }

func (b *Bot) putPend(v string) string {
	id := store.RandHex(4)
	b.mu.Lock()
	if b.pend == nil {
		b.pend = map[string]string{}
	}
	b.pend[id] = v
	b.pendOrder = append(b.pendOrder, id)
	if len(b.pendOrder) > 2000 {
		drop := b.pendOrder[:len(b.pendOrder)-1500]
		for _, k := range drop {
			delete(b.pend, k)
		}
		b.pendOrder = append([]string(nil), b.pendOrder[len(b.pendOrder)-1500:]...)
	}
	b.mu.Unlock()
	return id
}

func (b *Bot) getPend(id string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pend[id]
}

func (b *Bot) tryLockMachine(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inFlight == nil {
		b.inFlight = map[string]bool{}
	}
	if b.inFlight[id] {
		return false
	}
	b.inFlight[id] = true
	return true
}

func (b *Bot) unlockMachine(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.inFlight, id)
}

// ---------- 面板文案 ----------

func onlineDot(m *store.Machine) string {
	if m.Online && time.Since(m.LastSeen) < 45*time.Second {
		return "●"
	}
	return "○"
}

func parseStatus(raw json.RawMessage) *relaycfg.Status {
	if len(raw) == 0 {
		return nil
	}
	// helper 的 Result 包了一层 status；如果 op 非空但 status 为 nil（例如 switch 失败或无状态），不降级成空 Status。
	var wrap struct {
		OK      bool             `json:"ok"`
		Op      string           `json:"op"`
		Error   string           `json:"error"`
		Message string           `json:"message"`
		Status  *relaycfg.Status `json:"status"`
		Service string           `json:"service"`
	}
	if json.Unmarshal(raw, &wrap) == nil {
		if wrap.Status != nil {
			return wrap.Status
		}
		if wrap.Op != "" || wrap.Error != "" {
			return nil
		}
	}
	var st relaycfg.Status
	if json.Unmarshal(raw, &st) == nil && (st.Relays != nil || st.Candidates != nil || st.RelayNode != nil || st.LandingNode != nil) {
		return &st
	}
	return nil
}

// formatSSLink 按 SIP002 生成 SS2022/SS 分享链接。
func formatSSLink(n *relaycfg.NodeInfo, displayName string) string {
	if n == nil || n.Server == "" || n.Port <= 0 || n.Method == "" || n.Password == "" {
		return ""
	}
	userinfo := base64.StdEncoding.EncodeToString([]byte(n.Method + ":" + n.Password))
	hostPort := net.JoinHostPort(n.Server, strconv.FormatInt(n.Port, 10))
	tag := url.PathEscape(displayName)
	return fmt.Sprintf("ss://%s@%s#%s", userinfo, hostPort, tag)
}

// outboundLabel 优先解析为「直连」、已绑定落地机的实时显示名，再回退到控制端保存的落地显示名。
func (b *Bot) outboundLabel(mid, outTag string) (string, bool) {
	if outTag == "direct" {
		return "直连（未选落地）", true
	}
	if strings.HasPrefix(outTag, relaycfg.OutPrefix) {
		lid := strings.TrimPrefix(outTag, relaycfg.OutPrefix)
		if lm := b.st.Machine(lid); lm != nil && !lm.Revoked && lm.Role == store.RoleLanding {
			return b.machineTitle(lm), true
		}
	}
	return b.landingTitle(mid, outTag)
}

func (b *Bot) homeText() (string, *Keyboard) {
	relays := b.st.Relays()
	landings := b.st.Landings()
	var sb strings.Builder
	sb.WriteString("线路切换面板\n")
	if len(relays) == 0 && len(landings) == 0 {
		sb.WriteString("还没有机器。\n1. 点「添加线路机」绑定线路机（自动搭建 SS2022 节点）；\n2. 点「添加落地机」绑定落地机（自动搭建 SS2022 落地）；\n3. 之后即可在不动客户端节点的情况下随时切换落地。")
		return sb.String(), kb(row(Btn{Text: "添加线路机", Data: "add"}, Btn{Text: "添加落地机", Data: "add-landing"}))
	}
	var rows [][]Btn
	if len(relays) > 0 {
		sb.WriteString("\n【线路机】\n")
		for _, m := range relays {
			title := b.relayTitle(m)
			line := fmt.Sprintf("%s %s", onlineDot(m), escape(title))
			st := parseStatus(m.LastJSON)
			if st != nil {
				b.st.SeedLandingDefaults(m.ID, hintsFromStatus(st))
			}
			if st == nil && !m.Online {
				line += " · 离线"
			} else if st != nil && len(st.Relays) == 0 {
				line += " · 没有中转可切换"
			} else if st != nil {
				parts := []string{}
				for _, r := range st.Relays {
					name, named := b.outboundLabel(m.ID, r.Outbound)
					if !named {
						name = "未命名落地"
					}
					parts = append(parts, escape(name))
				}
				line += " → " + strings.Join(parts, "、")
			}
			sb.WriteString(line + "\n")
			rows = append(rows, row(Btn{Text: "线路 · " + title, Data: "m:" + m.ID}))
		}
	} else {
		sb.WriteString("\n【线路机】暂无，请点「添加线路机」。\n")
	}

	if len(landings) > 0 {
		sb.WriteString("\n【落地机】\n")
		for _, m := range landings {
			title := b.machineTitle(m)
			ready := "等待上报"
			if m.LandingNode != nil && m.LandingNode.Server != "" && m.LandingNode.Port > 0 {
				ready = "已就绪"
			}
			sb.WriteString(fmt.Sprintf("%s %s · %s\n", onlineDot(m), escape(title), ready))
			rows = append(rows, row(Btn{Text: "落地 · " + title, Data: "lm:" + m.ID}))
		}
	} else {
		sb.WriteString("\n【落地机】暂无，请点「添加落地机」。\n")
	}

	rows = append(rows, row(Btn{Text: "刷新", Data: "home"}, Btn{Text: "添加线路机", Data: "add"}, Btn{Text: "添加落地机", Data: "add-landing"}))
	return strings.TrimRight(sb.String(), "\n"), kb(rows...)
}

// switchLandingButtonText：只有一条可切换入站时写「换落地」，多条时写「给第 N 条中转换落地」。
func switchLandingButtonText(index, total int) string {
	if total <= 1 {
		return "换落地"
	}
	return "给第 " + strconv.Itoa(index+1) + " 条中转换落地"
}

func (b *Bot) machineText(id string) (string, *Keyboard, error) {
	m := b.st.Machine(id)
	if m == nil || m.Revoked {
		return "找不到这台机器。", kb(row(Btn{Text: "返回", Data: "home"})), nil
	}
	if m.Role == store.RoleLanding {
		t, k := b.landingMachineText(id)
		return t, k, nil
	}
	st := parseStatus(m.LastJSON)
	if st != nil {
		b.st.SeedLandingDefaults(id, hintsFromStatus(st))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\n角色：线路机\n", onlineDot(m), escape(b.relayTitle(m)))
	if m.LastSeen.IsZero() {
		sb.WriteString("尚未连上控制端。\n")
	} else {
		fmt.Fprintf(&sb, "最近心跳：%s\n", m.LastSeen.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	var rows [][]Btn
	node := m.RelayNode
	if node == nil && st != nil {
		node = st.RelayNode
	}
	if node != nil && node.Port > 0 {
		fmt.Fprintf(&sb, "客户端节点：SS2022（端口 %d，切换落地不变）\n", node.Port)
		rows = append(rows, row(Btn{Text: "查看 SS2022 节点链接", Data: "node:" + id}))
	}
	if st == nil {
		sb.WriteString("还没有状态。点刷新会向 agent 要一次。")
		rows = append(rows, row(Btn{Text: "刷新状态", Data: "rs:" + id}))
	} else if len(st.Relays) == 0 {
		sb.WriteString("没有中转可切换。\n请重新运行安装脚本初始化，或检查 sing-box 状态。")
		rows = append(rows, row(Btn{Text: "刷新状态", Data: "rs:" + id}))
	} else {
		sb.WriteString("中转（只改落地出站，不改线路入站地址/端口/密码）：\n")
		for i, r := range st.Relays {
			lname, named := b.outboundLabel(id, r.Outbound)
			if !named {
				lname = "未命名落地"
			}
			fmt.Fprintf(&sb, "  %d. 当前落地：%s%s\n", i+1, escape(lname), escape(debugTag(r.Outbound)))
			rows = append(rows, row(Btn{Text: switchLandingButtonText(i, len(st.Relays)), Data: "r:" + id + ":" + strconv.Itoa(i)}))
		}
		rows = append(rows, row(Btn{Text: "回滚上次切换", Data: "rb:" + id}, Btn{Text: "刷新", Data: "rs:" + id}))
		if len(st.XrayRelays) > 0 {
			sb.WriteString("另有 Xray 中转，本版只展示，不切换。\n")
		}
	}
	rows = append(rows, row(Btn{Text: "重命名线路机", Data: "nr:" + id}, Btn{Text: "删除机器", Data: "del:" + id}))
	if st != nil && len(st.Candidates) > 0 {
		rows = append(rows, row(Btn{Text: "重命名本地落地", Data: "nl:" + id}))
	}
	rows = append(rows, row(Btn{Text: "返回", Data: "home"}))
	return strings.TrimRight(sb.String(), "\n"), kb(rows...), nil
}

func (b *Bot) nodeText(id string) (string, *Keyboard) {
	m := b.st.Machine(id)
	if m == nil || m.Revoked {
		return "找不到这台线路机。", kb(row(Btn{Text: "返回", Data: "home"}))
	}
	node := m.RelayNode
	if node == nil {
		if st := parseStatus(m.LastJSON); st != nil {
			node = st.RelayNode
		}
	}
	if node == nil || node.Port <= 0 {
		return "尚未获取到该线路机的 SS2022 节点信息，请先点刷新状态。", kb(row(Btn{Text: "返回", Data: "m:" + id}))
	}
	title := b.relayTitle(m)
	link := formatSSLink(node, title)
	var sb strings.Builder
	fmt.Fprintf(&sb, "线路机「%s」SS2022 节点\n", escape(title))
	fmt.Fprintf(&sb, "地址：<code>%s</code>\n", escape(or(node.Server, "待检测")))
	fmt.Fprintf(&sb, "端口：<code>%d</code>\n", node.Port)
	fmt.Fprintf(&sb, "加密：<code>%s</code>\n", escape(node.Method))
	fmt.Fprintf(&sb, "密码：<code>%s</code>\n", escape(node.Password))
	if link != "" {
		fmt.Fprintf(&sb, "\n分享链接：\n<pre>%s</pre>\n", escape(link))
	}
	sb.WriteString("\n提示：在面板切换落地机时，以上节点信息完全不会改变。")
	return sb.String(), kb(row(Btn{Text: "返回线路机", Data: "m:" + id}, Btn{Text: "首页", Data: "home"}))
}

func (b *Bot) landingMachineText(id string) (string, *Keyboard) {
	m := b.st.Machine(id)
	if m == nil || m.Revoked {
		return "找不到这台落地机。", kb(row(Btn{Text: "返回", Data: "home"}))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\n角色：落地机\n", onlineDot(m), escape(b.machineTitle(m)))
	if m.LastSeen.IsZero() {
		sb.WriteString("尚未连上控制端。\n")
	} else {
		fmt.Fprintf(&sb, "最近心跳：%s\n", m.LastSeen.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if m.LandingNode != nil && m.LandingNode.Server != "" && m.LandingNode.Port > 0 {
		fmt.Fprintf(&sb, "落地节点：已就绪（%s，端口 %d）\n", escape(m.LandingNode.Method), m.LandingNode.Port)
		sb.WriteString("在线路机里选择切换落地时，可直接切到这台落地机。")
	} else {
		sb.WriteString("落地节点：等待落地机 agent 上报 SS2022 信息。")
	}
	rows := [][]Btn{
		row(Btn{Text: "刷新状态", Data: "rs:" + id}),
		row(Btn{Text: "重命名落地机", Data: "nml:" + id}, Btn{Text: "删除落地机", Data: "del:" + id}),
		row(Btn{Text: "返回", Data: "home"}),
	}
	return strings.TrimRight(sb.String(), "\n"), kb(rows...)
}

func (b *Bot) pickText(id string, idx int) (string, *Keyboard) {
	m := b.st.Machine(id)
	if m == nil || m.Revoked {
		return "找不到这台机器。", kb(row(Btn{Text: "返回", Data: "home"}))
	}
	st := parseStatus(m.LastJSON)
	if st == nil || idx < 0 || idx >= len(st.Relays) {
		return "状态已过期，请刷新。", kb(row(Btn{Text: "返回", Data: "home"}))
	}
	b.st.SeedLandingDefaults(id, hintsFromStatus(st))
	r := st.Relays[idx]
	cur, _ := b.outboundLabel(id, r.Outbound)
	var sb strings.Builder
	fmt.Fprintf(&sb, "给线路机「%s」的这条中转选落地（当前 %s%s）\n只改出站，不改入站 %s 的地址、端口和密码。\n",
		escape(b.relayTitle(m)), escape(cur), escape(debugTag(r.Outbound)), escape(r.Inbound))

	var rows [][]Btn
	shownTag := map[string]bool{}
	totalChoices := 0

	// 1. 优先展示所有已绑定且已上报节点信息的落地机
	for _, lm := range b.st.Landings() {
		if lm.LandingNode == nil || lm.LandingNode.Server == "" || lm.LandingNode.Port <= 0 {
			continue
		}
		tag := relaycfg.OutPrefix + lm.ID
		shownTag[tag] = true
		totalChoices++
		lname := b.machineTitle(lm)
		if r.Outbound == tag {
			rows = append(rows, row(Btn{Text: onlineDot(lm) + " " + lname + "（当前）", Data: "noop"}))
			continue
		}
		pid := b.putPend(fmt.Sprintf("%s|%s|%s|%s", id, r.Inbound, tag, lm.ID))
		rows = append(rows, row(Btn{Text: fmt.Sprintf("%s 切到「%s」", onlineDot(lm), lname), Data: "c:" + pid}))
	}

	// 2. 兼容线路机本地已有的 relay-out-*（例如 singbox-lite 手动导入的出站）
	for _, c := range st.Candidates {
		if shownTag[c.Tag] {
			continue
		}
		totalChoices++
		lname, named := b.landingTitle(id, c.Tag)
		mark := ""
		if c.Tag == r.Outbound {
			mark = "（当前）"
		}
		if !named {
			lname = "未命名落地"
		}
		label := lname + mark
		if c.Tag == r.Outbound {
			rows = append(rows, row(Btn{Text: label, Data: "noop"}))
			continue
		}
		pid := b.putPend(fmt.Sprintf("%s|%s|%s", id, r.Inbound, c.Tag))
		if !named {
			rows = append(rows, row(Btn{Text: "起名并切到这个落地", Data: "ns:" + pid}))
			continue
		}
		rows = append(rows, row(Btn{Text: "切到「" + lname + "」", Data: "c:" + pid}))
	}

	if totalChoices == 0 {
		sb.WriteString("还没有可用的落地机。请先在首页点「添加落地机」并完成绑定。")
	} else if totalChoices == 1 && r.Outbound != "direct" {
		sb.WriteString("当前仅有 1 个可用落地；可再绑定更多落地机以便随时切换。")
	}
	rows = append(rows, row(Btn{Text: "返回", Data: "m:" + id}))
	return sb.String(), kb(rows...)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (b *Bot) confirmText(pid string) (string, *Keyboard) {
	p := b.getPend(pid)
	parts := strings.Split(p, "|")
	if len(parts) != 3 && len(parts) != 4 {
		return "选项已过期。", kb(row(Btn{Text: "返回", Data: "home"}))
	}
	mid, inbound, out := parts[0], parts[1], parts[2]
	m := b.st.Machine(mid)
	lname, _ := b.outboundLabel(mid, out)
	text := fmt.Sprintf("确认把线路机「%s」的这条中转切到落地「%s」？\n（内部：%s → %s）\n会短暂重启线路机 sing-box，转发可能中断几秒。入站地址和密码不会改。",
		escape(b.relayTitle(m)), escape(lname), escape(inbound), escape(out))
	return text, kb(row(Btn{Text: "确认切换", Data: "x:" + pid}, Btn{Text: "取消", Data: "m:" + mid}))
}

func (b *Bot) ask(machine, op, inbound, outbound string, timeout time.Duration) (json.RawMessage, error) {
	return b.askWithSpec(machine, op, inbound, outbound, nil, timeout)
}

func (b *Bot) askWithSpec(machine, op, inbound, outbound string, spec *relaycfg.OutboundSpec, timeout time.Duration) (json.RawMessage, error) {
	cmd := &store.PendingCmd{Machine: machine, Op: op, Inbound: inbound, Outbound: outbound, OutboundSpec: spec}
	if err := b.st.Enqueue(cmd); err != nil {
		return nil, err
	}
	ch := make(chan json.RawMessage, 1)
	b.mu.Lock()
	if b.wait == nil {
		b.wait = map[string]chan json.RawMessage{}
	}
	b.wait[cmd.ID] = ch
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.wait, cmd.ID); b.mu.Unlock() }()
	select {
	case r := <-ch:
		return r, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("agent 未在 %s 内响应（可能离线）", timeout)
	}
}

func (b *Bot) allowed(uid int64) bool {
	o := b.st.Owner()
	if o == 0 {
		return false
	}
	return uid == o
}

func (b *Bot) handleMsg(m *Message) {
	if m.From == nil || m.Chat == nil {
		return
	}
	uid := m.From.ID
	text := strings.TrimSpace(m.Text)
	cmd, arg, _ := strings.Cut(text, " ")
	cmd = strings.ToLower(cmd)

	if cmd == "/start" {
		b.clearExpect(uid)
		if b.st.Owner() == 0 {
			if err := b.st.SetOwner(uid); err != nil {
				b.send(m.Chat.ID, "绑定管理员失败。", nil)
				return
			}
			b.send(m.Chat.ID, "已把你绑定为管理员。之后只响应你的消息。", nil)
		} else if !b.allowed(uid) {
			return
		}
		t, k := b.homeText()
		b.send(m.Chat.ID, t, k)
		return
	}
	if !b.allowed(uid) {
		return
	}
	if cmd == "/cancel" {
		if _, ok := b.popExpect(uid); ok {
			b.send(m.Chat.ID, "已取消。", nil)
		}
		t, k := b.homeText()
		b.send(m.Chat.ID, t, k)
		return
	}
	if e, ok := b.peekExpect(uid); ok && !strings.HasPrefix(text, "/") {
		reply, k, retry, _ := b.applyName(e, text)
		if !retry {
			b.clearExpect(uid)
		}
		b.send(m.Chat.ID, reply, k)
		return
	}
	switch cmd {
	case "/help":
		b.send(m.Chat.ID, "命令：\n/start 首页\n/status 刷新列表\n/add 名字 添加线路机（自动搭建 SS2022 节点，"+store.NameHint+"）\n/add-landing 名字 添加落地机（自动搭建 SS2022 落地）\n/cancel 取消当前改名\n/help 本说明\n\n日常操作用按钮。添加机器后把面板给出的一行命令以 root 执行即可。", nil)
	case "/status", "/home":
		b.clearExpect(uid)
		t, k := b.homeText()
		b.send(m.Chat.ID, t, k)
	case "/add":
		name := strings.TrimSpace(arg)
		if name == "" {
			b.setExpect(uid, expect{Kind: expectAddRelay, Chat: m.Chat.ID})
			b.send(m.Chat.ID, askNamePrompt(expectAddRelay), nil)
			return
		}
		b.clearExpect(uid)
		b.sendInstall(m.Chat.ID, name, store.RoleRelay)
	case "/add-landing", "/addlanding":
		name := strings.TrimSpace(arg)
		if name == "" {
			b.setExpect(uid, expect{Kind: expectAddLanding, Chat: m.Chat.ID})
			b.send(m.Chat.ID, askNamePrompt(expectAddLanding), nil)
			return
		}
		b.clearExpect(uid)
		b.sendInstall(m.Chat.ID, name, store.RoleLanding)
	default:
		t, k := b.homeText()
		b.send(m.Chat.ID, t, k)
	}
}

func (b *Bot) sendInstall(chat int64, name string, role store.Role) {
	if role == "" {
		role = store.RoleRelay
	}
	tok, err := b.st.NewMachineInstallToken(name, role, 2*time.Hour)
	if err != nil {
		b.send(chat, escape(store.NameErrorText(err)), nil)
		return
	}
	script := b.InstallScript(tok.Token)
	kind := "线路机"
	extra := "安装完成后会自动搭建 SS2022 节点并推送链接给你。"
	if role == store.RoleLanding {
		kind = "落地机"
		extra = "安装完成后会自动搭建 SS2022 落地并上报给控制端，在线路机面板里即可直接切到它。"
	}
	msg := fmt.Sprintf("%s「%s」安装命令（2 小时内有效，只能用一次）。%s\n在机器上以 root 执行（建议先 export HISTCONTROL=ignorespace；命令行首有空格，尽量不进历史）：\n\n<pre>%s</pre>",
		kind, escape(tok.Name), extra, escape(script))
	if len(msg) > 3500 {
		b.send(chat, "安装脚本较长，分两步：先把脚本存成 /tmp/sbrelay-install.sh，再 bash 执行。一次性令牌已写入脚本。下面是脚本：", nil)
		b.send(chat, "<pre>"+escape(script)+"</pre>", nil)
		return
	}
	b.send(chat, msg, nil)
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func (b *Bot) handleCB(cb *CBQ) {
	if cb.From == nil || !b.allowed(cb.From.ID) || cb.Message == nil {
		return
	}
	uid := cb.From.ID
	chat, mid := cb.Message.Chat.ID, cb.Message.ID
	data := cb.Data
	// 点了别的按钮就取消进行中的改名，避免下一条文字被误当成新名字
	if data != "noop" && !strings.HasPrefix(data, "nr:") && !strings.HasPrefix(data, "nml:") && !strings.HasPrefix(data, "nl:") && !strings.HasPrefix(data, "rl:") && !strings.HasPrefix(data, "ns:") {
		b.clearExpect(uid)
	}
	switch {
	case data == "noop":
		b.answer(cb.ID, "当前已在使用该落地")
	case data == "home":
		t, k := b.homeText()
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case data == "add":
		b.setExpect(uid, expect{Kind: expectAddRelay, Chat: chat, Mid: mid})
		b.edit(chat, mid, askNamePrompt(expectAddRelay), kb(row(Btn{Text: "取消", Data: "home"})))
		b.answer(cb.ID, "请发送显示名")
	case data == "add-landing":
		b.setExpect(uid, expect{Kind: expectAddLanding, Chat: chat, Mid: mid})
		b.edit(chat, mid, askNamePrompt(expectAddLanding), kb(row(Btn{Text: "取消", Data: "home"})))
		b.answer(cb.ID, "请发送显示名")
	case strings.HasPrefix(data, "m:"):
		t, k, _ := b.machineText(strings.TrimPrefix(data, "m:"))
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "lm:"):
		t, k := b.landingMachineText(strings.TrimPrefix(data, "lm:"))
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "node:"):
		t, k := b.nodeText(strings.TrimPrefix(data, "node:"))
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "del:"):
		id := strings.TrimPrefix(data, "del:")
		m := b.st.Machine(id)
		if m == nil || m.Revoked {
			b.answer(cb.ID, "机器已不存在")
			t, k := b.homeText()
			b.edit(chat, mid, t, k)
			return
		}
		back := "m:" + id
		if m.Role == store.RoleLanding {
			back = "lm:" + id
		}
		b.edit(chat, mid, fmt.Sprintf("确认删除「%s」？\n删除后会吊销该机器的接入凭据（不会改动其本机 sing-box，如需卸载请在目标机器执行 pm 卸载）。", escape(b.machineTitle(m))),
			kb(row(Btn{Text: "确认删除", Data: "delx:" + id}, Btn{Text: "取消", Data: back})))
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "delx:"):
		id := strings.TrimPrefix(data, "delx:")
		if err := b.st.Revoke(id); err != nil {
			b.answer(cb.ID, err.Error())
		} else {
			b.answer(cb.ID, "已删除")
		}
		t, k := b.homeText()
		b.edit(chat, mid, t, k)
	case strings.HasPrefix(data, "nr:"):
		id := strings.TrimPrefix(data, "nr:")
		b.setExpect(uid, expect{Kind: expectRenameRelay, Machine: id, Chat: chat, Mid: mid})
		b.edit(chat, mid, askNamePrompt(expectRenameRelay), kb(row(Btn{Text: "取消", Data: "m:" + id})))
		b.answer(cb.ID, "请发送新名字")
	case strings.HasPrefix(data, "nml:"):
		id := strings.TrimPrefix(data, "nml:")
		b.setExpect(uid, expect{Kind: expectRenameLandingMachine, Machine: id, Chat: chat, Mid: mid})
		b.edit(chat, mid, askNamePrompt(expectRenameLandingMachine), kb(row(Btn{Text: "取消", Data: "lm:" + id})))
		b.answer(cb.ID, "请发送新名字")
	case strings.HasPrefix(data, "nl:"):
		id := strings.TrimPrefix(data, "nl:")
		t, k := b.landingRenameList(id)
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "rl:"):
		pid := strings.TrimPrefix(data, "rl:")
		parts := strings.Split(b.getPend(pid), "|")
		if len(parts) != 2 {
			b.answer(cb.ID, "选项已过期")
			return
		}
		b.setExpect(uid, expect{Kind: expectRenameLanding, Machine: parts[0], Tag: parts[1], Chat: chat, Mid: mid})
		b.edit(chat, mid, askNamePrompt(expectRenameLanding), kb(row(Btn{Text: "取消", Data: "nl:" + parts[0]})))
		b.answer(cb.ID, "请发送新名字")
	case strings.HasPrefix(data, "ns:"):
		pid := strings.TrimPrefix(data, "ns:")
		parts := strings.Split(b.getPend(pid), "|")
		if len(parts) != 3 {
			b.answer(cb.ID, "选项已过期")
			return
		}
		b.setExpect(uid, expect{Kind: expectNameThenSwitch, Machine: parts[0], Inbound: parts[1], Tag: parts[2], Chat: chat, Mid: mid})
		b.edit(chat, mid, askNamePrompt(expectNameThenSwitch), kb(row(Btn{Text: "取消", Data: "m:" + parts[0]})))
		b.answer(cb.ID, "请先给落地起名")
	case strings.HasPrefix(data, "rs:"):
		id := strings.TrimPrefix(data, "rs:")
		if !b.tryLockMachine(id) {
			b.answer(cb.ID, "该机器正在执行其他操作，请稍候")
			return
		}
		defer b.unlockMachine(id)
		b.answer(cb.ID, "正在向机器要状态…")
		raw, err := b.ask(id, "status", "", "", 25*time.Second)
		if err != nil {
			b.edit(chat, mid, "刷新失败："+escape(err.Error()), kb(row(Btn{Text: "返回", Data: "home"})))
			return
		}
		b.ingestStatus(id, raw)
		t, k, _ := b.machineText(id)
		b.edit(chat, mid, t, k)
	case strings.HasPrefix(data, "r:"):
		rest := strings.TrimPrefix(data, "r:")
		id, is, _ := strings.Cut(rest, ":")
		idx, _ := strconv.Atoi(is)
		t, k := b.pickText(id, idx)
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "c:"):
		t, k := b.confirmText(strings.TrimPrefix(data, "c:"))
		b.edit(chat, mid, t, k)
		b.answer(cb.ID, "")
	case strings.HasPrefix(data, "x:"):
		p := b.getPend(strings.TrimPrefix(data, "x:"))
		parts := strings.Split(p, "|")
		if len(parts) != 3 && len(parts) != 4 {
			b.answer(cb.ID, "选项已过期")
			return
		}
		machineID, inbound, outTag := parts[0], parts[1], parts[2]
		var spec *relaycfg.OutboundSpec
		if len(parts) == 4 && parts[3] != "" {
			lm := b.st.Machine(parts[3])
			if lm == nil || lm.Revoked || lm.LandingNode == nil || lm.LandingNode.Server == "" || lm.LandingNode.Port <= 0 {
				b.answer(cb.ID, "目标落地机已不可用")
				return
			}
			spec = &relaycfg.OutboundSpec{
				Tag:      outTag,
				Type:     lm.LandingNode.Type,
				Server:   lm.LandingNode.Server,
				Port:     lm.LandingNode.Port,
				Method:   lm.LandingNode.Method,
				Password: lm.LandingNode.Password,
			}
		} else {
			// 本地旧落地未起名不允许直接切
			if _, named := b.outboundLabel(machineID, outTag); !named {
				b.answer(cb.ID, "请先给落地起名")
				b.setExpect(uid, expect{Kind: expectNameThenSwitch, Machine: machineID, Inbound: inbound, Tag: outTag, Chat: chat, Mid: mid})
				b.edit(chat, mid, askNamePrompt(expectNameThenSwitch), kb(row(Btn{Text: "取消", Data: "m:" + machineID})))
				return
			}
		}
		if !b.tryLockMachine(machineID) {
			b.answer(cb.ID, "该线路机正在切换中，请稍候")
			return
		}
		defer b.unlockMachine(machineID)
		b.answer(cb.ID, "正在切换…")
		b.edit(chat, mid, "正在切换，线路机 sing-box 可能重启几秒…", nil)
		raw, err := b.askWithSpec(machineID, "switch", inbound, outTag, spec, 45*time.Second)
		if err != nil {
			b.edit(chat, mid, "切换失败："+escape(err.Error()), kb(row(Btn{Text: "返回", Data: "m:" + machineID})))
			return
		}
		b.ingestStatus(machineID, raw)
		b.edit(chat, mid, b.formatSwitchResult("切换", machineID, raw), kb(row(Btn{Text: "查看线路机", Data: "m:" + machineID}, Btn{Text: "首页", Data: "home"})))
	case strings.HasPrefix(data, "rb:"):
		id := strings.TrimPrefix(data, "rb:")
		if !b.tryLockMachine(id) {
			b.answer(cb.ID, "该线路机正在执行其他操作，请稍候")
			return
		}
		defer b.unlockMachine(id)
		b.answer(cb.ID, "正在回滚…")
		b.edit(chat, mid, "正在回滚上次切换…", nil)
		raw, err := b.ask(id, "rollback", "", "", 45*time.Second)
		if err != nil {
			b.edit(chat, mid, "回滚失败："+escape(err.Error()), kb(row(Btn{Text: "返回", Data: "m:" + id})))
			return
		}
		b.ingestStatus(id, raw)
		b.edit(chat, mid, b.formatSwitchResult("回滚", id, raw), kb(row(Btn{Text: "查看线路机", Data: "m:" + id}, Btn{Text: "首页", Data: "home"})))
	default:
		b.answer(cb.ID, "")
	}
}

// ingestStatus 仅当 raw 包含有效 Status 时才更新 LastJSON，避免把 switch/rollback 报错覆盖掉旧状态。
func (b *Bot) ingestStatus(id string, raw json.RawMessage) {
	st := parseStatus(raw)
	if st == nil {
		b.st.Touch(id, true, nil, nil, nil)
		return
	}
	b.st.SeedLandingDefaults(id, hintsFromStatus(st))
	m := b.st.Machine(id)
	wasEmpty := m != nil && m.RelayNode == nil && m.LandingNode == nil
	b.st.Touch(id, true, raw, st.RelayNode, st.LandingNode)
	if wasEmpty {
		b.notifyNodeReady(id, st)
	}
}

// notifyNodeReady 新绑定的线路机或落地机首次上报节点信息时，主动给管理员发一次通知（线路机附带 SS2022 链接）。
func (b *Bot) notifyNodeReady(id string, st *relaycfg.Status) {
	owner := b.st.Owner()
	if owner == 0 || b.http == nil || b.cfg.Token == "" {
		return
	}
	b.mu.Lock()
	if b.notified == nil {
		b.notified = map[string]bool{}
	}
	if b.notified[id] {
		b.mu.Unlock()
		return
	}
	b.notified[id] = true
	b.mu.Unlock()

	m := b.st.Machine(id)
	if m == nil || m.Revoked {
		return
	}
	if m.Role == store.RoleRelay && st.RelayNode != nil && st.RelayNode.Server != "" && st.RelayNode.Port > 0 {
		t, k := b.nodeText(id)
		go func() {
			_, _ = b.send(owner, "线路机已上线并自动搭建好 SS2022 节点：\n\n"+t, k)
		}()
	} else if m.Role == store.RoleLanding && st.LandingNode != nil && st.LandingNode.Server != "" && st.LandingNode.Port > 0 {
		go func() {
			_, _ = b.send(owner, fmt.Sprintf("落地机「%s」已上线并就绪（SS2022 端口 %d）。\n现在可以在线路机面板里直接切换到这台落地机。", escape(b.machineTitle(m)), st.LandingNode.Port),
				kb(row(Btn{Text: "打开首页", Data: "home"})))
		}()
	}
}

func formatResult(op string, raw json.RawMessage) string {
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
		return "没有中转可切换。请先检查线路机 sing-box 配置。"
	}
	if !r.OK {
		msg := r.Error
		if msg == "" {
			msg = r.Message
		}
		return op + "失败：" + escape(msg)
	}
	s := fmt.Sprintf("%s成功。\n中转 %s：%s → %s", op, escape(r.Inbound), escape(r.From), escape(r.To))
	if r.Backup != "" {
		s += "\n备份：" + escape(r.Backup)
	}
	return s
}

// ---------- 更新循环 ----------

func (b *Bot) PollTG(ctx context.Context) {
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		raw, err := b.api("getUpdates", map[string]any{"offset": offset, "timeout": 25, "allowed_updates": []string{"message", "callback_query"}})
		if err != nil {
			log.Printf("getUpdates: %s", redact.Error(err))
			time.Sleep(3 * time.Second)
			continue
		}
		var ups []Update
		if err := json.Unmarshal(raw, &ups); err != nil {
			continue
		}
		for _, u := range ups {
			offset = u.ID + 1
			u := u
			if u.Message != nil {
				go b.handleMsg(u.Message)
			}
			if u.CB != nil {
				go b.handleCB(u.CB)
			}
		}
	}
}

// PeekOwner 启动时扫一遍已有消息，尽量找到管理员。
func (b *Bot) PeekOwner() int64 {
	if id := b.st.Owner(); id != 0 {
		return id
	}
	raw, err := b.api("getUpdates", map[string]any{"timeout": 0, "allowed_updates": []string{"message"}})
	if err != nil {
		return 0
	}
	var ups []Update
	json.Unmarshal(raw, &ups)
	for _, u := range ups {
		if u.Message != nil && u.Message.From != nil && strings.HasPrefix(strings.TrimSpace(u.Message.Text), "/start") {
			_ = b.st.SetOwner(u.Message.From.ID)
			return u.Message.From.ID
		}
	}
	return 0
}

// ---------- agent HTTP ----------

func verify(secret, ts, nonce, body, sig string) bool {
	if secret == "" {
		return false
	}
	// 防重放：时间窗 2 分钟
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || abs(time.Now().Unix()-sec) > 120 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + nonce + "\n" + body))
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func (b *Bot) AgentMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/register", b.handleRegister)
	mux.HandleFunc("/v1/poll", b.handlePoll)
	mux.HandleFunc("/v1/result", b.handleResult)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/install-agent.sh", b.handleInstallAgentSh)
	mux.HandleFunc("/v1/install-agent.sh", b.handleInstallAgentSh)
	mux.HandleFunc("/pkg/", b.handlePkg)
	mux.HandleFunc("/pm.sh", b.handleScript)
	mux.HandleFunc("/install-control.sh", b.handleScript)
	return mux
}

func (b *Bot) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method", 405)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	mid, secret := store.RandHex(8), store.RandHex(32)
	m, err := b.st.ConsumeToken(req.Token, mid, secret)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"machine_id": m.ID, "secret": secret, "name": m.Name, "role": string(m.Role)})
}

func (b *Bot) handlePoll(w http.ResponseWriter, r *http.Request) {
	m, body, ok := b.auth(w, r)
	if !ok {
		return
	}
	var hb struct {
		Status json.RawMessage `json:"status"`
	}
	json.Unmarshal(body, &hb)
	b.ingestStatus(m.ID, hb.Status)
	cmds := b.st.TakeCommands(m.ID)
	type wire struct {
		ID           string                 `json:"id"`
		Op           string                 `json:"op"`
		Inbound      string                 `json:"inbound,omitempty"`
		Outbound     string                 `json:"outbound,omitempty"`
		OutboundSpec *relaycfg.OutboundSpec `json:"outbound_spec,omitempty"`
	}
	out := struct {
		Commands []wire `json:"commands"`
	}{Commands: []wire{}}
	for _, c := range cmds {
		out.Commands = append(out.Commands, wire{
			ID:           c.ID,
			Op:           c.Op,
			Inbound:      c.Inbound,
			Outbound:     c.Outbound,
			OutboundSpec: c.OutboundSpec,
		})
	}
	json.NewEncoder(w).Encode(out)
}

func (b *Bot) handleResult(w http.ResponseWriter, r *http.Request) {
	m, body, ok := b.auth(w, r)
	if !ok {
		return
	}
	var req struct {
		ID     string          `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(body, &req) != nil || req.ID == "" {
		http.Error(w, "bad json", 400)
		return
	}
	if err := b.st.Finish(m.ID, req.ID, req.Result); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	b.mu.Lock()
	ch := b.wait[req.ID]
	b.mu.Unlock()
	if ch != nil {
		select {
		case ch <- req.Result:
		default:
		}
	}
	w.Write([]byte(`{"ok":true}`))
}

func (b *Bot) auth(w http.ResponseWriter, r *http.Request) (*store.Machine, []byte, bool) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	id := r.Header.Get("X-Machine-Id")
	m := b.st.Machine(id)
	if m == nil || m.Revoked || !verify(m.Secret, r.Header.Get("X-Ts"), r.Header.Get("X-Nonce"), string(body), r.Header.Get("X-Sig")) {
		http.Error(w, "unauthorized", 401)
		return nil, nil, false
	}
	if !b.acceptNonce(m.ID, r.Header.Get("X-Ts"), r.Header.Get("X-Nonce")) {
		http.Error(w, "unauthorized", 401)
		return nil, nil, false
	}
	return m, body, true
}

// acceptNonce 拒绝 2 分钟时间窗内同一机器同一 nonce 的重放。
func (b *Bot) acceptNonce(machineID, ts, nonce string) bool {
	if machineID == "" || nonce == "" {
		return false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	key := machineID + "\x00" + nonce
	now := time.Now().Unix()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nonceSeen == nil {
		b.nonceSeen = map[string]int64{}
	}
	if len(b.nonceSeen) > 512 || now%32 == 0 {
		for k, exp := range b.nonceSeen {
			if exp < now {
				delete(b.nonceSeen, k)
			}
		}
	}
	if exp, ok := b.nonceSeen[key]; ok && exp >= now {
		return false
	}
	exp := sec + 120
	if exp < now+120 {
		exp = now + 120
	}
	b.nonceSeen[key] = exp
	return true
}

func (b *Bot) RunControl(ctx context.Context) error {
	if b.cfg.Listen == "" {
		return fmt.Errorf("未设置监听地址")
	}
	srv := &http.Server{Addr: b.cfg.Listen, Handler: b.AgentMux(), BaseContext: func(net.Listener) context.Context { return ctx }}
	go b.PollTG(ctx)
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	var err error
	if b.cfg.CertFile != "" && b.cfg.KeyFile != "" {
		err = srv.ListenAndServeTLS(b.cfg.CertFile, b.cfg.KeyFile)
	} else {
		err = srv.ListenAndServe()
	}
	// systemctl stop 触发的正常关闭不算失败，避免日志里每次都是 status=1/FAILURE
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func ListenFromEnv() string {
	if v := os.Getenv("SBRELAY_LISTEN"); v != "" {
		return v
	}
	return ":8443"
}
