// Package helper 是 root 侧唯一入口的实现：读状态 / 切换 / 回滚。
// 路径在 cmd/sbrelay-helper 里写死，sudoers 只放行固定参数，切换参数从 stdin 读并严格校验。
package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"sbrelay/internal/relaycfg"
)

const maxBackups = 20

type Env struct {
	Dir          string // /usr/local/etc/sing-box
	SingBox      string // /usr/local/bin/sing-box
	StateDir     string // /var/lib/sbrelay-helper
	PublicIPFile string // /etc/sbrelay/public_ip（可选，install-agent 写入）
	Service      string // sing-box
	LockWait     time.Duration
	Systemctl    func(args ...string) error // 便于测试替换
	SettleWait   time.Duration
}

func (e *Env) relay() string { return filepath.Join(e.Dir, "relay.json") }
func (e *Env) links() string { return filepath.Join(e.Dir, "relay_links.json") }
func (e *Env) main() string  { return filepath.Join(e.Dir, "config.json") }

type Result struct {
	OK      bool              `json:"ok"`
	Op      string            `json:"op"`
	Message string            `json:"message,omitempty"`
	Error   string            `json:"error,omitempty"`
	Code    string            `json:"code,omitempty"`
	From    string            `json:"from,omitempty"`
	To      string            `json:"to,omitempty"`
	Inbound string            `json:"inbound,omitempty"`
	Backup  string            `json:"backup,omitempty"`
	Status  *relaycfg.Status  `json:"status,omitempty"`
	Service string            `json:"service,omitempty"`
	Last    *LastSwitch       `json:"last,omitempty"`
	Extra   map[string]string `json:"extra,omitempty"`
}

// LastSwitch 记录最近一次成功切换，回滚只在配置未被他人改动时允许。
type LastSwitch struct {
	Inbound    string `json:"inbound"`
	From       string `json:"from"`
	To         string `json:"to"`
	AfterSHA   string `json:"after_sha256"`
	Backup     string `json:"backup"`
	At         string `json:"at"`
	RolledBack bool   `json:"rolled_back,omitempty"`
}

type SwitchReq struct {
	Inbound      string                 `json:"inbound"`
	Outbound     string                 `json:"outbound"`
	OutboundSpec *relaycfg.OutboundSpec `json:"outbound_spec,omitempty"`
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func readOpt(p string) ([]byte, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (e *Env) publicIP() string {
	p := e.PublicIPFile
	if p == "" {
		p = "/etc/sbrelay/public_ip"
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (e *Env) serviceState() string {
	if e.Systemctl != nil {
		if err := e.Systemctl("is-active", "--quiet", e.Service); err == nil {
			return "active"
		}
		return "inactive"
	}
	out, _ := exec.Command("/usr/bin/systemctl", "is-active", e.Service).Output()
	return strings.TrimSpace(string(out))
}

func (e *Env) loadLast() *LastSwitch {
	b, err := os.ReadFile(filepath.Join(e.StateDir, "last.json"))
	if err != nil {
		return nil
	}
	var l LastSwitch
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	return &l
}

func (e *Env) parseCurrentStatus() (*relaycfg.Status, error) {
	r, err := readOpt(e.relay())
	if err != nil {
		return nil, err
	}
	l, err := readOpt(e.links())
	if err != nil {
		return nil, err
	}
	st, err := relaycfg.Parse(r, l)
	if err != nil {
		return nil, err
	}
	ip := e.publicIP()
	if st.RelayNode != nil && st.RelayNode.Server == "" && ip != "" {
		st.RelayNode.Server = ip
	}
	// 落地机配置在 config.json（包含 sbrelay-landing-in 或首个 shadowsocks 入站）
	if cfgBytes, cerr := readOpt(e.main()); cerr == nil && len(cfgBytes) > 0 {
		if ln, lerr := relaycfg.ExtractInbound(cfgBytes, relaycfg.AutoLandingTag); lerr == nil && ln != nil {
			if ln.Server == "" && ip != "" {
				ln.Server = ip
			}
			st.LandingNode = ln
		}
	}
	return st, nil
}

func (e *Env) Status() Result {
	st, err := e.parseCurrentStatus()
	if err != nil {
		return Result{Op: "status", Error: err.Error()}
	}
	res := Result{OK: true, Op: "status", Status: st, Service: e.serviceState(), Last: e.loadLast()}
	if len(st.Relays) == 0 {
		res.Message = "没有中转可切换"
	}
	return res
}

// lock 与脚本 _with_state_lock 用同一个文件，脚本也是 flock -n 轮询，所以这里同样轮询。
func (e *Env) lock() (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(e.Dir, ".singboxlite.lock"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(e.LockWait)
	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return f, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("状态锁被占用（可能有人正在用 sb 菜单），稍后再试")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// writeAtomic 同目录临时文件 + fsync + rename，尽量保留原文件权限，不存在时默认 0600。
func writeAtomic(path string, b []byte) error {
	mode := os.FileMode(0600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sbrelay-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	return os.Rename(tmp.Name(), path)
}

func (e *Env) pruneBackups() {
	root := filepath.Join(e.StateDir, "backups")
	ents, err := os.ReadDir(root)
	if err != nil || len(ents) <= maxBackups {
		return
	}
	var names []string
	for _, ent := range ents {
		if ent.IsDir() {
			names = append(names, ent.Name())
		}
	}
	if len(names) <= maxBackups {
		return
	}
	sort.Strings(names)
	for _, n := range names[:len(names)-maxBackups] {
		_ = os.RemoveAll(filepath.Join(root, n))
	}
}

func (e *Env) backup(r, l []byte) (string, error) {
	rb := make([]byte, 3)
	rand.Read(rb)
	d := filepath.Join(e.StateDir, "backups", time.Now().UTC().Format("20060102T150405Z")+"-"+hex.EncodeToString(rb))
	if err := os.MkdirAll(d, 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(d, "relay.json"), r, 0600); err != nil {
		return "", err
	}
	if l != nil {
		if err := os.WriteFile(filepath.Join(d, "relay_links.json"), l, 0600); err != nil {
			return "", err
		}
	}
	e.pruneBackups()
	return d, nil
}

func (e *Env) restartHealthy() error {
	if err := e.Systemctl("restart", e.Service); err != nil {
		return fmt.Errorf("重启 %s 失败: %v", e.Service, err)
	}
	time.Sleep(e.SettleWait)
	if err := e.Systemctl("is-active", "--quiet", e.Service); err != nil {
		return fmt.Errorf("%s 重启后未处于运行状态", e.Service)
	}
	return nil
}

// Switch 完整流程：锁 → 备份 → 计算 → check → 原子替换 → 重启 → 健康检查；失败恢复原文件并再次重启。
func (e *Env) Switch(req SwitchReq, op string) Result {
	res := Result{Op: op, Inbound: req.Inbound, To: req.Outbound}
	f, err := e.lock()
	if err != nil {
		res.Error, res.Code = err.Error(), "locked"
		return res
	}
	defer f.Close()
	return e.switchLocked(req, res)
}

func (e *Env) switchLocked(req SwitchReq, res Result) Result {
	r, err := os.ReadFile(e.relay())
	if err != nil {
		res.Error = "读取 relay.json 失败: " + err.Error()
		return res
	}
	l, err := readOpt(e.links())
	if err != nil {
		res.Error = "读取 relay_links.json 失败: " + err.Error()
		return res
	}
	nr, nl, from, err := relaycfg.SwitchWithSpec(r, l, req.Inbound, req.Outbound, req.OutboundSpec)
	res.From = from
	if err != nil {
		res.Error = err.Error()
		switch {
		case errors.Is(err, relaycfg.ErrNoRelay):
			res.Code = "no_relay"
		case errors.Is(err, relaycfg.ErrNoop):
			res.Code = "noop"
		}
		return res
	}
	bdir, err := e.backup(r, l)
	if err != nil {
		res.Error = "备份失败，未做任何改动: " + err.Error()
		return res
	}
	res.Backup = bdir
	// check 用同目录临时文件，保证与真实文件同一组合（-c config.json -c relay.json）。
	tmp, err := os.CreateTemp(e.Dir, ".sbrelay-check-*.json")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	tmp.Write(nr)
	tmp.Chmod(0600)
	tmp.Close()
	defer os.Remove(tmp.Name())
	if out, err := exec.Command(e.SingBox, "check", "-c", e.main(), "-c", tmp.Name()).CombinedOutput(); err != nil {
		res.Error = "sing-box check 未通过，未做改动: " + trim(string(out))
		res.Code = "check_failed"
		return res
	}
	if err := writeAtomic(e.relay(), nr); err != nil {
		res.Error = "写入失败，未改动: " + err.Error()
		return res
	}
	if nl != nil {
		if err := writeAtomic(e.links(), nl); err != nil {
			_ = writeAtomic(e.relay(), r)
			res.Error = "写入 relay_links.json 失败，已恢复: " + err.Error()
			return res
		}
	}
	if err := e.restartHealthy(); err != nil {
		restoreErr := writeAtomic(e.relay(), r)
		if l != nil {
			if lerr := writeAtomic(e.links(), l); lerr != nil && restoreErr == nil {
				restoreErr = lerr
			}
		}
		rerr := e.restartHealthy()
		res.Error = "切换后服务异常，已自动回滚到原配置: " + err.Error()
		if restoreErr != nil {
			res.Error += "；恢复文件失败: " + restoreErr.Error()
		}
		if rerr != nil {
			res.Error += "；回滚后重启也失败: " + rerr.Error() + "（备份在 " + bdir + "）"
		}
		res.Code = "rolled_back"
		return res
	}
	last := LastSwitch{Inbound: req.Inbound, From: from, To: req.Outbound, AfterSHA: sum(nr), Backup: bdir, At: time.Now().UTC().Format(time.RFC3339)}
	if res.Op == "rollback" {
		last.RolledBack = true
	}
	lb, _ := json.Marshal(last)
	if err := writeAtomic(filepath.Join(e.StateDir, "last.json"), lb); err != nil {
		log.Printf("写入 last.json 失败: %v", err)
	}
	st, _ := e.parseCurrentStatus()
	res.OK, res.Service, res.Last, res.Status = true, e.serviceState(), &last, st
	return res
}

// Rollback 把最近一次切换反向再切一次；若之后 relay.json 被改过（例如 sb 菜单），拒绝回滚以免覆盖别人的修改。
func (e *Env) Rollback() Result {
	res := Result{Op: "rollback"}
	f, err := e.lock()
	if err != nil {
		res.Error, res.Code = err.Error(), "locked"
		return res
	}
	defer f.Close()
	last := e.loadLast()
	if last == nil || last.RolledBack {
		res.Error, res.Code = "没有可回滚的切换", "nothing"
		return res
	}
	cur, err := os.ReadFile(e.relay())
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if sum(cur) != last.AfterSHA {
		res.Error, res.Code = "上次切换后 relay.json 已被其他操作修改，拒绝自动回滚（备份在 "+last.Backup+"）", "changed"
		return res
	}
	res.Inbound, res.To = last.Inbound, last.From
	return e.switchLocked(SwitchReq{Inbound: last.Inbound, Outbound: last.From}, res)
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
