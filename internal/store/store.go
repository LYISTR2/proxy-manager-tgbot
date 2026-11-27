// Package store 用 JSON 文件保存控制端状态（零第三方依赖，效果等同小型 SQLite）。
package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"sbrelay/internal/relaycfg"
)

type Role string

const (
	RoleRelay   Role = "relay"
	RoleLanding Role = "landing"
)

type Machine struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Role        Role               `json:"role"`
	Secret      string             `json:"secret"` // HMAC 密钥，不进 TG 消息
	Created     time.Time          `json:"created"`
	LastSeen    time.Time          `json:"last_seen,omitempty"`
	Online      bool               `json:"online"`
	LastJSON    json.RawMessage    `json:"last_status,omitempty"`
	RelayNode   *relaycfg.NodeInfo `json:"relay_node,omitempty"`
	LandingNode *relaycfg.NodeInfo `json:"landing_node,omitempty"`
	Revoked     bool               `json:"revoked,omitempty"`
}

type InstallToken struct {
	Token   string    `json:"token"`
	Name    string    `json:"name"`
	Role    Role      `json:"role"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

type PendingCmd struct {
	ID           string                 `json:"id"`
	Machine      string                 `json:"machine"`
	Op           string                 `json:"op"` // status, switch, rollback
	Inbound      string                 `json:"inbound,omitempty"`
	Outbound     string                 `json:"outbound,omitempty"`
	OutboundSpec *relaycfg.OutboundSpec `json:"outbound_spec,omitempty"`
	Created      time.Time              `json:"created"`
	DispatchedAt time.Time              `json:"dispatched_at,omitempty"`
	Done         bool                   `json:"done"`
	Result       json.RawMessage        `json:"result,omitempty"`
}

type State struct {
	OwnerID      int64                        `json:"owner_id"`
	Machines     map[string]*Machine          `json:"machines"`
	Tokens       map[string]*InstallToken     `json:"tokens"`
	Commands     map[string]*PendingCmd       `json:"commands"`
	LandingNames map[string]map[string]string `json:"landing_names,omitempty"` // machineID -> outbound tag -> 显示名
}

type Store struct {
	path      string
	lockFile  *os.File
	mu        sync.Mutex
	s         State
	lastFlush time.Time
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "state.json")
	lockPath := p + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("打开状态锁文件失败: %w", err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("状态文件锁被占用（%s），请确认没有其他 sbrelay 进程正在使用同一数据目录: %w", lockPath, err)
	}
	unlock := func() {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		_ = lf.Close()
	}
	st := &Store{path: p, lockFile: lf, s: State{
		Machines:     map[string]*Machine{},
		Tokens:       map[string]*InstallToken{},
		Commands:     map[string]*PendingCmd{},
		LandingNames: map[string]map[string]string{},
	}}
	b, err := os.ReadFile(p)
	if err == nil {
		if err := json.Unmarshal(b, &st.s); err != nil {
			unlock()
			return nil, err
		}
		if st.s.Machines == nil {
			st.s.Machines = map[string]*Machine{}
		}
		if st.s.Tokens == nil {
			st.s.Tokens = map[string]*InstallToken{}
		}
		if st.s.Commands == nil {
			st.s.Commands = map[string]*PendingCmd{}
		}
		if st.s.LandingNames == nil {
			st.s.LandingNames = map[string]map[string]string{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		unlock()
		return nil, err
	}
	return st, nil
}

// Close 释放状态文件排他锁。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lockFile == nil {
		return nil
	}
	_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	err := s.lockFile.Close()
	s.lockFile = nil
	return err
}

func cloneNodeInfo(n *relaycfg.NodeInfo) *relaycfg.NodeInfo {
	if n == nil {
		return nil
	}
	cp := *n
	return &cp
}

func cloneMachine(m *Machine) *Machine {
	if m == nil {
		return nil
	}
	cp := *m
	if m.LastJSON != nil {
		cp.LastJSON = append(json.RawMessage(nil), m.LastJSON...)
	}
	cp.RelayNode = cloneNodeInfo(m.RelayNode)
	cp.LandingNode = cloneNodeInfo(m.LandingNode)
	return &cp
}

func cloneOutboundSpec(sp *relaycfg.OutboundSpec) *relaycfg.OutboundSpec {
	if sp == nil {
		return nil
	}
	cp := *sp
	return &cp
}

func clonePendingCmd(c *PendingCmd) *PendingCmd {
	if c == nil {
		return nil
	}
	cp := *c
	cp.OutboundSpec = cloneOutboundSpec(c.OutboundSpec)
	if c.Result != nil {
		cp.Result = append(json.RawMessage(nil), c.Result...)
	}
	return &cp
}

func (s *Store) pruneLocked(now time.Time) {
	for id, c := range s.s.Commands {
		if c == nil || (c.Done && now.Sub(c.Created) > 10*time.Minute) || now.Sub(c.Created) > 30*time.Minute {
			delete(s.s.Commands, id)
		}
	}
	for k, t := range s.s.Tokens {
		if t == nil || (t.Used && now.After(t.Expires)) || now.Sub(t.Expires) > 24*time.Hour {
			delete(s.s.Tokens, k)
		}
	}
}

func (s *Store) save() error {
	now := time.Now()
	s.pruneLocked(now)
	b, err := json.MarshalIndent(s.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.lastFlush = now
	return nil
}

func (s *Store) With(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.s); err != nil {
		return err
	}
	return s.save()
}

func (s *Store) View(fn func(*State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.s)
}

func RandHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) Owner() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.OwnerID
}

func (s *Store) SetOwner(id int64) error {
	return s.With(func(st *State) error {
		if st.OwnerID != 0 && st.OwnerID != id {
			return errors.New("已绑定其他管理员")
		}
		st.OwnerID = id
		return nil
	})
}

func (s *Store) NewInstallToken(name string, role Role, ttl time.Duration) (*InstallToken, error) {
	tok := &InstallToken{Token: RandHex(16), Name: name, Role: role, Expires: time.Now().Add(ttl)}
	err := s.With(func(st *State) error { st.Tokens[tok.Token] = tok; return nil })
	return tok, err
}

func (s *Store) ConsumeToken(token, mid, secret string) (*Machine, error) {
	var m *Machine
	err := s.With(func(st *State) error {
		t, ok := st.Tokens[token]
		if !ok || t.Used || time.Now().After(t.Expires) {
			return errors.New("注册令牌无效或已过期")
		}
		t.Used = true
		created := &Machine{ID: mid, Name: t.Name, Role: t.Role, Secret: secret, Created: time.Now()}
		st.Machines[mid] = created
		m = cloneMachine(created)
		return nil
	})
	return m, err
}

func (s *Store) Machine(id string) *Machine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneMachine(s.s.Machines[id])
}

func (s *Store) Enqueue(m *PendingCmd) error {
	if m.ID == "" {
		m.ID = RandHex(8)
	}
	m.Created = time.Now()
	return s.With(func(st *State) error { st.Commands[m.ID] = clonePendingCmd(m); return nil })
}

// TakeCommands 取出待下发命令；60 秒内已派发过且未完成的命令不重复派发，避免网络抖动导致重复执行。
// 没有命令派发时不写盘，避免每 3 秒心跳触发全量持久化。
func (s *Store) TakeCommands(machine string) []*PendingCmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	var out []*PendingCmd
	for _, c := range s.s.Commands {
		if c == nil || c.Done || c.Machine != machine {
			continue
		}
		if now.Sub(c.Created) >= 2*time.Minute {
			continue
		}
		if !c.DispatchedAt.IsZero() && now.Sub(c.DispatchedAt) < 60*time.Second {
			continue
		}
		c.DispatchedAt = now
		out = append(out, clonePendingCmd(c))
	}
	if len(out) > 0 {
		_ = s.save()
	}
	return out
}

// Finish 标记命令完成，并校验命令确实归属于上报的 machineID（防止越权提交结果）。
func (s *Store) Finish(machineID, id string, result json.RawMessage) error {
	return s.With(func(st *State) error {
		c := st.Commands[id]
		if c == nil {
			return errors.New("未知命令")
		}
		if machineID == "" || c.Machine != machineID {
			return errors.New("无权提交该命令结果")
		}
		c.Done = true
		c.Result = append(json.RawMessage(nil), result...)
		return nil
	})
}

// Cancel 撤销尚未完成的命令（例如控制端等待超时），防止 60 秒后被重复派发。
func (s *Store) Cancel(id string) error {
	return s.With(func(st *State) error {
		c := st.Commands[id]
		if c == nil || c.Done {
			return nil
		}
		c.Done = true
		c.Result = json.RawMessage(`{"ok":false,"error":"timeout"}`)
		return nil
	})
}

func (s *Store) Command(id string) *PendingCmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePendingCmd(s.s.Commands[id])
}

func (s *Store) machinesByRole(role Role) []*Machine {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Machine
	for _, m := range s.s.Machines {
		if m != nil && m.Role == role && !m.Revoked {
			out = append(out, cloneMachine(m))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *Store) Relays() []*Machine {
	return s.machinesByRole(RoleRelay)
}

func (s *Store) Landings() []*Machine {
	return s.machinesByRole(RoleLanding)
}

func nodeEqual(a, b *relaycfg.NodeInfo) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// Touch 更新心跳与状态；仅在状态发生变化或距上次写盘超过 15 秒时才落盘，降低高频 IO。
func (s *Store) Touch(id string, online bool, status json.RawMessage, relayNode, landingNode *relaycfg.NodeInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.s.Machines[id]
	if m == nil {
		return
	}
	now := time.Now()
	changed := m.Online != online || m.LastSeen.IsZero()
	m.LastSeen = now
	m.Online = online
	if len(status) > 0 && !bytes.Equal(m.LastJSON, status) {
		m.LastJSON = append(json.RawMessage(nil), status...)
		changed = true
	}
	if relayNode != nil && !nodeEqual(m.RelayNode, relayNode) {
		cp := *relayNode
		m.RelayNode = &cp
		changed = true
	}
	if landingNode != nil && !nodeEqual(m.LandingNode, landingNode) {
		cp := *landingNode
		m.LandingNode = &cp
		changed = true
	}
	if changed || now.Sub(s.lastFlush) >= 15*time.Second {
		_ = s.save()
	}
}

func (s *Store) Revoke(id string) error {
	return s.With(func(st *State) error {
		m := st.Machines[id]
		if m == nil {
			return errors.New("找不到这台机器")
		}
		m.Revoked = true
		m.Online = false
		m.Secret = ""
		return nil
	})
}
