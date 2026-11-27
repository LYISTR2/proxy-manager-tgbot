// Package relaycfg 只做纯函数：解析 sing-box 的 relay.json / relay_links.json / config.json，计算切换后的内容。
// 不碰文件系统，便于单测；落盘、加锁、check、重启都在 helper 里。
package relaycfg

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"sbrelay/internal/ojson"
)

const (
	OutPrefix      = "relay-out-"
	AutoRelayInTag = "sbrelay-ss2022-in"
	AutoLandingTag = "sbrelay-landing-in"
	// LocalEgressTag 是「本机直出」出站：线路机自己的 direct 出站，不经任何落地。
	// 由 sbrelay 写进 relay.json（不依赖 config.json 里是否有 direct），不带 relay-out- 前缀，
	// 因此不会被当成落地候选，也不会和脚本/落地机的出站重名。
	LocalEgressTag   = "sbrelay-local-direct"
	LocalEgressLabel = "本机直出"
)

// IsLocalEgress 判断出站是否为线路机本机直出：sbrelay 自建的本机直出出站，
// 或自动入站 sbrelay-ss2022-in 初始未选落地时的 "direct"。
func IsLocalEgress(tag string) bool {
	return tag == LocalEgressTag || tag == "direct"
}

// TagRe 限制 tag 字符集：tag 来自 TG 回调，必须防止注入奇怪字符进日志/配置。
var TagRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var (
	ErrNoRelay  = errors.New("没有中转可切换")
	ErrNoop     = errors.New("目标落地与当前相同")
	ErrNotFound = errors.New("找不到对应的中转或落地")
)

type Relay struct {
	Inbound     string `json:"inbound"`
	InboundType string `json:"inbound_type"`
	ListenPort  int64  `json:"listen_port"`
	Outbound    string `json:"outbound"`
	NodeName    string `json:"node_name,omitempty"`
	LandingAddr string `json:"landing_addr,omitempty"`
	LandingType string `json:"landing_type,omitempty"`
}

type Candidate struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`
	Label  string `json:"label"`
	Server string `json:"server"`
	Port   int64  `json:"port"`
	// UsedBy 是当前指向该出站的中转入口；为脚本删除风险提示用。
	UsedBy []string `json:"used_by,omitempty"`
}

// NodeInfo 表示自动搭建或本机已有的 SS2022/Shadowsocks 入站节点信息（用于线路机展示节点链接、落地机上报出站凭据）。
type NodeInfo struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	Server   string `json:"server,omitempty"`
	Port     int64  `json:"port"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}

// OutboundSpec 用于控制端下发已绑定落地机的出站配置，由 helper 写入 relay.json 的 outbounds。
type OutboundSpec struct {
	Tag      string `json:"tag"`
	Type     string `json:"type"`
	Server   string `json:"server"`
	Port     int64  `json:"server_port"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}

type Status struct {
	Relays      []Relay     `json:"relays"`
	Candidates  []Candidate `json:"candidates"`
	XrayRelays  []string    `json:"xray_relays,omitempty"`
	Warnings    []string    `json:"warnings,omitempty"`
	RelayNode   *NodeInfo   `json:"relay_node,omitempty"`
	LandingNode *NodeInfo   `json:"landing_node,omitempty"`
}

func parseObj(b []byte, what string) (*ojson.Object, error) {
	if len(strings.TrimSpace(string(b))) == 0 {
		return ojson.NewObject(), nil
	}
	v, err := ojson.Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s 解析失败: %w", what, err)
	}
	o, ok := v.(*ojson.Object)
	if !ok {
		return nil, fmt.Errorf("%s 顶层不是对象", what)
	}
	return o, nil
}

func objs(v any) []*ojson.Object {
	arr, _ := v.([]any)
	out := []*ojson.Object{}
	for _, e := range arr {
		if o, ok := e.(*ojson.Object); ok {
			out = append(out, o)
		}
	}
	return out
}

func rules(relay *ojson.Object) []*ojson.Object {
	r, ok := relay.Get("route")
	if !ok {
		return nil
	}
	ro, ok := r.(*ojson.Object)
	if !ok {
		return nil
	}
	rr, _ := ro.Get("rules")
	return objs(rr)
}

// 中转规则形如 {"inbound":"<tag>","outbound":"relay-out-<id>"}；
// 自动创建的线路机入站 sbrelay-ss2022-in 在尚未绑定落地时 outbound 为 "direct"，同样视为可切换中转。
func isRelayRule(r *ojson.Object) bool {
	in, ok1 := r.M["inbound"].(string)
	out, ok2 := r.M["outbound"].(string)
	if !ok1 || !ok2 || in == "" {
		return false
	}
	if strings.HasPrefix(out, OutPrefix) || out == LocalEgressTag {
		return true
	}
	return in == AutoRelayInTag && out == "direct"
}

// Label 复刻脚本 dest_label：http 出站开了 TLS 记为 https。
func Label(o *ojson.Object) string {
	t := o.Str("type")
	if t == "http" {
		if tv, ok := o.M["tls"].(*ojson.Object); ok {
			if en, _ := tv.M["enabled"].(bool); en {
				return "https"
			}
		}
	}
	return t
}

func extractNode(doc *ojson.Object, preferTag string) *NodeInfo {
	if doc == nil {
		return nil
	}
	inbV, _ := doc.Get("inbounds")
	var fallback *NodeInfo
	for _, o := range objs(inbV) {
		t := o.Str("type")
		port := o.Int("listen_port")
		if t == "" || port <= 0 {
			continue
		}
		info := &NodeInfo{
			Tag:      o.Str("tag"),
			Type:     t,
			Port:     port,
			Method:   o.Str("method"),
			Password: o.Str("password"),
		}
		if preferTag != "" && info.Tag == preferTag {
			return info
		}
		if fallback == nil && t == "shadowsocks" {
			fallback = info
		}
	}
	return fallback
}

// ExtractInbound 从 config.json 或 relay.json 中提取指定 tag（或首个 shadowsocks）入站节点信息。
func ExtractInbound(rawJSON []byte, preferTag string) (*NodeInfo, error) {
	doc, err := parseObj(rawJSON, "config.json")
	if err != nil {
		return nil, err
	}
	return extractNode(doc, preferTag), nil
}

func Parse(relayJSON, linksJSON []byte) (*Status, error) {
	relay, err := parseObj(relayJSON, "relay.json")
	if err != nil {
		return nil, err
	}
	links, err := parseObj(linksJSON, "relay_links.json")
	if err != nil {
		return nil, err
	}
	st := &Status{Relays: []Relay{}, Candidates: []Candidate{}}
	inb := map[string]*ojson.Object{}
	inbV, _ := relay.Get("inbounds")
	for _, o := range objs(inbV) {
		inb[o.Str("tag")] = o
	}
	st.RelayNode = extractNode(relay, AutoRelayInTag)

	used := map[string][]string{}
	seen := map[string]bool{}
	for _, r := range rules(relay) {
		if !isRelayRule(r) {
			continue
		}
		in, out := r.Str("inbound"), r.Str("outbound")
		if seen[in] {
			st.Warnings = append(st.Warnings, "入口 "+in+" 有多条中转规则，已跳过重复项")
			continue
		}
		seen[in] = true
		rel := Relay{Inbound: in, Outbound: out}
		if io, ok := inb[in]; ok {
			rel.InboundType, rel.ListenPort = io.Str("type"), io.Int("listen_port")
		}
		if lv, ok := links.Get(in); ok {
			if lo, ok := lv.(*ojson.Object); ok {
				rel.NodeName, rel.LandingAddr, rel.LandingType = lo.Str("node_name"), lo.Str("landing_addr"), lo.Str("landing_type")
			}
		}
		used[out] = append(used[out], in)
		st.Relays = append(st.Relays, rel)
	}
	outV, _ := relay.Get("outbounds")
	for _, o := range objs(outV) {
		tag := o.Str("tag")
		if !strings.HasPrefix(tag, OutPrefix) {
			continue
		}
		st.Candidates = append(st.Candidates, Candidate{Tag: tag, Type: o.Str("type"), Label: Label(o), Server: o.Str("server"), Port: o.Int("server_port"), UsedBy: used[tag]})
	}
	for _, k := range links.Keys {
		if lo, ok := links.M[k].(*ojson.Object); ok && lo.Str("engine") == "xray" {
			st.XrayRelays = append(st.XrayRelays, k)
		}
	}
	return st, nil
}

// ValidateSpec 校验下发的落地出站配置。
func ValidateSpec(sp *OutboundSpec) error {
	if sp == nil {
		return nil
	}
	if !TagRe.MatchString(sp.Tag) || !strings.HasPrefix(sp.Tag, OutPrefix) {
		return fmt.Errorf("出站 tag 不合法")
	}
	if sp.Type != "shadowsocks" {
		return fmt.Errorf("暂不支持的出站类型 %q", sp.Type)
	}
	if sp.Server == "" || len(sp.Server) > 128 || strings.ContainsAny(sp.Server, " \t\r\n/\\") {
		return fmt.Errorf("落地地址不合法")
	}
	if sp.Port < 1 || sp.Port > 65535 {
		return fmt.Errorf("落地端口不合法")
	}
	if sp.Method == "" || sp.Password == "" {
		return fmt.Errorf("缺少加密方式或密码")
	}
	return nil
}

func specToObj(sp *OutboundSpec) *ojson.Object {
	o := ojson.NewObject()
	o.Set("type", sp.Type)
	o.Set("tag", sp.Tag)
	o.Set("server", sp.Server)
	o.Set("server_port", sp.Port)
	o.Set("method", sp.Method)
	o.Set("password", sp.Password)
	return o
}

func upsertOutbound(relay *ojson.Object, sp *OutboundSpec) *ojson.Object {
	obj := specToObj(sp)
	outV, ok := relay.Get("outbounds")
	arr, _ := outV.([]any)
	if !ok || arr == nil {
		arr = []any{}
	}
	for i, e := range arr {
		if o, ok := e.(*ojson.Object); ok && o.Str("tag") == sp.Tag {
			arr[i] = obj
			relay.Set("outbounds", arr)
			return obj
		}
	}
	arr = append(arr, obj)
	relay.Set("outbounds", arr)
	return obj
}

// ensureLocalEgress 确保 relay.json 里有本机直出出站 {"type":"direct","tag":LocalEgressTag}；
// 同名但不是 direct 的出站会被改正，避免把流量送到别处。
func ensureLocalEgress(relay *ojson.Object) *ojson.Object {
	outV, ok := relay.Get("outbounds")
	arr, _ := outV.([]any)
	if !ok || arr == nil {
		arr = []any{}
	}
	for i, e := range arr {
		if o, ok := e.(*ojson.Object); ok && o.Str("tag") == LocalEgressTag {
			if o.Str("type") == "direct" {
				return o
			}
			obj := ojson.NewObject()
			obj.Set("type", "direct")
			obj.Set("tag", LocalEgressTag)
			arr[i] = obj
			relay.Set("outbounds", arr)
			return obj
		}
	}
	obj := ojson.NewObject()
	obj.Set("type", "direct")
	obj.Set("tag", LocalEgressTag)
	relay.Set("outbounds", append(arr, obj))
	return obj
}

// Switch 把 inbound 对应中转规则的 outbound 改为 target，并同步 relay_links.json 的落地元数据。
// links 文件不存在时传 nil，返回的 newLinks 也为 nil（不凭空创建脚本的文件）。
func Switch(relayJSON, linksJSON []byte, inbound, target string) (newRelay, newLinks []byte, from string, err error) {
	return SwitchWithSpec(relayJSON, linksJSON, inbound, target, nil)
}

// SwitchWithSpec 支持在切换前先写入/更新目标落地出站（来自已绑定的落地机），且绝不修改 inbounds。
// 当 target == "direct" 且 inbound == AutoRelayInTag 时允许切回直连（例如回滚到初始态）。
// 当 target == LocalEgressTag 时切到本机直出：任何中转入站都可用，不需要落地出站参数。
func SwitchWithSpec(relayJSON, linksJSON []byte, inbound, target string, spec *OutboundSpec) (newRelay, newLinks []byte, from string, err error) {
	allowDirect := inbound == AutoRelayInTag && target == "direct"
	local := target == LocalEgressTag
	if !TagRe.MatchString(inbound) || !TagRe.MatchString(target) || (!allowDirect && !local && !strings.HasPrefix(target, OutPrefix)) {
		return nil, nil, "", fmt.Errorf("参数不合法")
	}
	if local && spec != nil {
		return nil, nil, "", fmt.Errorf("本机直出不需要落地出站参数")
	}
	if spec != nil {
		if spec.Tag == "" {
			spec.Tag = target
		}
		if spec.Tag != target {
			return nil, nil, "", fmt.Errorf("出站 tag 与目标不一致")
		}
		if err := ValidateSpec(spec); err != nil {
			return nil, nil, "", err
		}
	}
	relay, err := parseObj(relayJSON, "relay.json")
	if err != nil {
		return nil, nil, "", err
	}

	var tgt *ojson.Object
	specChanged := false
	if spec != nil {
		// 检查旧的同 tag 出站是否内容有变化（例如落地机换了端口/密码）
		outV, _ := relay.Get("outbounds")
		for _, o := range objs(outV) {
			if o.Str("tag") == target {
				if o.Str("server") != spec.Server || o.Int("server_port") != spec.Port || o.Str("method") != spec.Method || o.Str("password") != spec.Password {
					specChanged = true
				}
			}
		}
		tgt = upsertOutbound(relay, spec)
	} else if local {
		tgt = ensureLocalEgress(relay)
	} else if !allowDirect {
		outV, _ := relay.Get("outbounds")
		for _, o := range objs(outV) {
			if o.Str("tag") == target {
				tgt = o
			}
		}
	}

	var hit *ojson.Object
	any := false
	for _, r := range rules(relay) {
		if !isRelayRule(r) {
			continue
		}
		any = true
		if r.Str("inbound") == inbound {
			if hit != nil {
				return nil, nil, "", fmt.Errorf("入口 %s 有多条中转规则，拒绝自动修改", inbound)
			}
			hit = r
		}
	}
	if !any {
		return nil, nil, "", ErrNoRelay
	}
	if hit == nil || (!allowDirect && tgt == nil) {
		return nil, nil, "", ErrNotFound
	}
	from = hit.Str("outbound")
	if from == target && !specChanged {
		return nil, nil, from, ErrNoop
	}
	// 自动入站初始的 "direct" 与本机直出出口相同，不必为此重启 sing-box
	if local && IsLocalEgress(from) {
		return nil, nil, from, ErrNoop
	}
	hit.Set("outbound", target)
	newRelay = ojson.Marshal(relay)
	if linksJSON != nil {
		links, err := parseObj(linksJSON, "relay_links.json")
		if err != nil {
			return nil, nil, "", err
		}
		if lv, ok := links.Get(inbound); ok {
			if lo, ok := lv.(*ojson.Object); ok {
				if tgt != nil && !local {
					// 脚本写法是 "${dest_addr}:${dest_port}"，IPv6 不加括号，这里保持一致。
					lo.Set("landing_addr", tgt.Str("server")+":"+strconv.FormatInt(tgt.Int("server_port"), 10))
					lo.Set("landing_type", Label(tgt))
				} else {
					lo.Set("landing_addr", "")
					lo.Set("landing_type", "direct")
				}
			}
		}
		newLinks = ojson.Marshal(links)
	}
	return newRelay, newLinks, from, nil
}

// HostPort 给延迟探测用；IPv6 需要加括号。
func (c Candidate) HostPort() string {
	return net.JoinHostPort(c.Server, strconv.FormatInt(c.Port, 10))
}
