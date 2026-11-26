// Package relaycfg 只做纯函数：解析 singbox-lite 的 relay.json / relay_links.json，计算切换后的内容。
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

const OutPrefix = "relay-out-"

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

type Status struct {
	Relays     []Relay     `json:"relays"`
	Candidates []Candidate `json:"candidates"`
	XrayRelays []string    `json:"xray_relays,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
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

// 脚本的中转规则形如 {"inbound":"<tag>","outbound":"relay-out-<port>"}，inbound 是字符串。
func isRelayRule(r *ojson.Object) bool {
	in, ok1 := r.M["inbound"].(string)
	out, ok2 := r.M["outbound"].(string)
	return ok1 && ok2 && in != "" && strings.HasPrefix(out, OutPrefix)
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

// Switch 把 inbound 对应中转规则的 outbound 改为 target，并同步 relay_links.json 的落地元数据。
// links 文件不存在时传 nil，返回的 newLinks 也为 nil（不凭空创建脚本的文件）。
func Switch(relayJSON, linksJSON []byte, inbound, target string) (newRelay, newLinks []byte, from string, err error) {
	if !TagRe.MatchString(inbound) || !TagRe.MatchString(target) || !strings.HasPrefix(target, OutPrefix) {
		return nil, nil, "", fmt.Errorf("参数不合法")
	}
	relay, err := parseObj(relayJSON, "relay.json")
	if err != nil {
		return nil, nil, "", err
	}
	var tgt *ojson.Object
	outV, _ := relay.Get("outbounds")
	for _, o := range objs(outV) {
		if o.Str("tag") == target {
			tgt = o
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
	if hit == nil || tgt == nil {
		return nil, nil, "", ErrNotFound
	}
	from = hit.Str("outbound")
	if from == target {
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
				// 脚本写法是 "${dest_addr}:${dest_port}"，IPv6 不加括号，这里保持一致。
				lo.Set("landing_addr", tgt.Str("server")+":"+strconv.FormatInt(tgt.Int("server_port"), 10))
				lo.Set("landing_type", Label(tgt))
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
