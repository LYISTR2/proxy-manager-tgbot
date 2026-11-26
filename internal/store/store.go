// Package store 用 JSON 文件保存控制端状态（零第三方依赖，效果等同小型 SQLite）。
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Role string

const (
	RoleRelay   Role = "relay"
	RoleLanding Role = "landing"
)

type Machine struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Role     Role            `json:"role"`
	Secret   string          `json:"secret"` // HMAC 密钥，不进 TG 消息
	Created  time.Time       `json:"created"`
	LastSeen time.Time       `json:"last_seen,omitempty"`
	Online   bool            `json:"online"`
	LastJSON json.RawMessage `json:"last_status,omitempty"`
	Revoked  bool            `json:"revoked,omitempty"`
}

type InstallToken struct {
	Token   string    `json:"token"`
	Name    string    `json:"name"`
	Role    Role      `json:"role"`
	Expires time.Time `json:"expires"`
	Used    bool      `json:"used"`
}

type PendingCmd struct {
	ID       string          `json:"id"`
	Machine  string          `json:"machine"`
	Op       string          `json:"op"` // status, switch, rollback
	Inbound  string          `json:"inbound,omitempty"`
	Outbound string          `json:"outbound,omitempty"`
	Created  time.Time       `json:"created"`
	Done     bool            `json:"done"`
	Result   json.RawMessage `json:"result,omitempty"`
}

type State struct {
	OwnerID      int64                        `json:"owner_id"`
	Machines     map[string]*Machine          `json:"machines"`
	Tokens       map[string]*InstallToken     `json:"tokens"`
	Commands     map[string]*PendingCmd       `json:"commands"`
	LandingNames map[string]map[string]string `json:"landing_names,omitempty"` // machineID -> outbound tag -> 显示名
}

type Store struct {
	path string
	mu   sync.Mutex
	s    State
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "state.json")
	st := &Store{path: p, s: State{Machines: map[string]*Machine{}, Tokens: map[string]*InstallToken{}, Commands: map[string]*PendingCmd{}}}
	b, err := os.ReadFile(p)
	if err == nil {
		if err := json.Unmarshal(b, &st.s); err != nil {
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
		return nil, err
	}
	return st, nil
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
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
		m = &Machine{ID: mid, Name: t.Name, Role: t.Role, Secret: secret, Created: time.Now()}
		st.Machines[mid] = m
		return nil
	})
	return m, err
}

func (s *Store) Machine(id string) *Machine {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.Machines[id]
}

func (s *Store) Enqueue(m *PendingCmd) error {
	if m.ID == "" {
		m.ID = RandHex(8)
	}
	m.Created = time.Now()
	return s.With(func(st *State) error { st.Commands[m.ID] = m; return nil })
}

func (s *Store) TakeCommands(machine string) []*PendingCmd {
	var out []*PendingCmd
	s.With(func(st *State) error {
		for _, c := range st.Commands {
			if !c.Done && c.Machine == machine && time.Since(c.Created) < 2*time.Minute {
				out = append(out, c)
			}
		}
		return nil
	})
	return out
}

func (s *Store) Finish(id string, result json.RawMessage) error {
	return s.With(func(st *State) error {
		c := st.Commands[id]
		if c == nil {
			return errors.New("未知命令")
		}
		c.Done = true
		c.Result = result
		return nil
	})
}

func (s *Store) Command(id string) *PendingCmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.s.Commands[id]
}

func (s *Store) Relays() []*Machine {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Machine
	for _, m := range s.s.Machines {
		if m.Role == RoleRelay && !m.Revoked {
			out = append(out, m)
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

func (s *Store) Touch(id string, online bool, status json.RawMessage) {
	s.With(func(st *State) error {
		if m := st.Machines[id]; m != nil {
			m.LastSeen = time.Now()
			m.Online = online
			if status != nil {
				m.LastJSON = status
			}
		}
		return nil
	})
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
