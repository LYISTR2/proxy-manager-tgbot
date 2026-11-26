package store

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// 显示名只存在控制端，不写进 sing-box 配置或客户端链接。
const (
	MaxNameRunes = 32
	NameHint     = "1–32 个字（汉字、英文均可）"
)

var (
	ErrNameEmpty     = errors.New("名字不能为空")
	ErrNameTooLong   = errors.New("名字太长")
	ErrNameBadChar   = errors.New("名字里不能有换行、制表符或控制字符")
	ErrNameTaken     = errors.New("名字已被占用")
	ErrNameUnchanged = errors.New("与当前名字相同")
)

// NormalizeName 去掉首尾空白并校验长度、字符。成功时返回规范化后的名字。
func NormalizeName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ErrNameEmpty
	}
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsControl(r) {
			return "", ErrNameBadChar
		}
	}
	n := utf8.RuneCountInString(s)
	if n > MaxNameRunes {
		return "", fmt.Errorf("%w：最多 %d 个字（你输入了 %d 个）", ErrNameTooLong, MaxNameRunes, n)
	}
	return s, nil
}

func NameErrorText(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrNameEmpty):
		return "名字不能为空。请再发一次，" + NameHint + "。"
	case errors.Is(err, ErrNameTooLong):
		return err.Error() + "。请再发一次，" + NameHint + "。"
	case errors.Is(err, ErrNameBadChar):
		return "名字里不能有换行、制表符或控制字符。请再发一次，" + NameHint + "。"
	case errors.Is(err, ErrNameTaken):
		return err.Error()
	case errors.Is(err, ErrNameUnchanged):
		return "与当前名字相同，没有改动。"
	default:
		return err.Error()
	}
}

func (s *Store) ensureLandingMap(st *State, machineID string) map[string]string {
	if st.LandingNames == nil {
		st.LandingNames = map[string]map[string]string{}
	}
	m := st.LandingNames[machineID]
	if m == nil {
		m = map[string]string{}
		st.LandingNames[machineID] = m
	}
	return m
}

func relayNameTaken(st *State, name, exceptID string) bool {
	return machineNameTaken(st, name, RoleRelay, exceptID)
}

func landingNameTaken(st *State, machineID, name, exceptTag string) bool {
	for tag, n := range st.LandingNames[machineID] {
		if tag == exceptTag {
			continue
		}
		if n == name {
			return true
		}
	}
	return false
}

// SetRelayName 修改线路机显示名，立刻写入内存和 state.json（无需重启控制端）。
func (s *Store) SetRelayName(id, name string) error {
	return s.SetMachineName(id, RoleRelay, name)
}

// SetMachineName 修改线路机或落地机显示名，同角色内不重名。
func (s *Store) SetMachineName(id string, role Role, name string) error {
	n, err := NormalizeName(name)
	if err != nil {
		return err
	}
	kind := "线路机"
	if role == RoleLanding {
		kind = "落地机"
	}
	return s.With(func(st *State) error {
		m := st.Machines[id]
		if m == nil || m.Revoked || m.Role != role {
			return errors.New("找不到这台" + kind)
		}
		if m.Name == n {
			return ErrNameUnchanged
		}
		if machineNameTaken(st, n, role, id) {
			return fmt.Errorf("%w：已有%s叫「%s」，请换一个名字", ErrNameTaken, kind, n)
		}
		m.Name = n
		return nil
	})
}

// SetLandingName 按「线路机 + outbound tag」保存落地显示名。
func (s *Store) SetLandingName(machineID, outboundTag, name string) error {
	n, err := NormalizeName(name)
	if err != nil {
		return err
	}
	if outboundTag == "" {
		return errors.New("缺少落地标识")
	}
	return s.With(func(st *State) error {
		m := st.Machines[machineID]
		if m == nil || m.Revoked {
			return errors.New("找不到这台线路机")
		}
		mp := s.ensureLandingMap(st, machineID)
		if cur, ok := mp[outboundTag]; ok && cur == n {
			return ErrNameUnchanged
		}
		if landingNameTaken(st, machineID, n, outboundTag) {
			return fmt.Errorf("%w：这台线路机下已有落地叫「%s」，请换一个名字", ErrNameTaken, n)
		}
		mp[outboundTag] = n
		return nil
	})
}

func (s *Store) LandingName(machineID, outboundTag string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s.LandingNames == nil {
		return ""
	}
	return s.s.LandingNames[machineID][outboundTag]
}

func (s *Store) LandingNames(machineID string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.s.LandingNames[machineID] {
		out[k] = v
	}
	return out
}

func (s *Store) RelayDisplayName(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.s.Machines[id]
	if m == nil {
		return ""
	}
	return m.Name
}

// LandingHint 给 SeedLandingDefaults 用。
type LandingHint struct {
	Tag      string // relay-out-*
	NodeName string
}

// SeedLandingDefaults 只填充还没有显示名的落地，用脚本里的 node_name（如 Landing-A）做默认可改名。
// 不覆盖用户已改过的名字；默认名冲突时跳过；没有任何新增时不写盘。
func (s *Store) SeedLandingDefaults(machineID string, hints []LandingHint) {
	if len(hints) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.s.Machines[machineID]
	if m == nil || m.Revoked {
		return
	}
	mp := s.ensureLandingMap(&s.s, machineID)
	changed := false
	for _, h := range hints {
		if h.Tag == "" {
			continue
		}
		if cur := mp[h.Tag]; cur != "" {
			continue
		}
		n, err := NormalizeName(h.NodeName)
		if err != nil {
			continue
		}
		if landingNameTaken(&s.s, machineID, n, h.Tag) {
			continue
		}
		mp[h.Tag] = n
		changed = true
	}
	if changed {
		_ = s.save()
	}
}

// NewRelayInstallToken 签发线路机一次性安装令牌。
func (s *Store) NewRelayInstallToken(name string, ttl time.Duration) (*InstallToken, error) {
	return s.NewMachineInstallToken(name, RoleRelay, ttl)
}

// NewMachineInstallToken 签发线路机或落地机一次性安装令牌。名字必填，同角色内不能重名。
func (s *Store) NewMachineInstallToken(name string, role Role, ttl time.Duration) (*InstallToken, error) {
	if role != RoleRelay && role != RoleLanding {
		return nil, fmt.Errorf("未知角色")
	}
	n, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	kind := "线路机"
	if role == RoleLanding {
		kind = "落地机"
	}
	var tok *InstallToken
	err = s.With(func(st *State) error {
		if machineNameTaken(st, n, role, "") {
			return fmt.Errorf("%w：已有%s叫「%s」，请换一个名字", ErrNameTaken, kind, n)
		}
		tok = &InstallToken{Token: RandHex(16), Name: n, Role: role, Expires: time.Now().Add(ttl)}
		st.Tokens[tok.Token] = tok
		return nil
	})
	return tok, err
}

func machineNameTaken(st *State, name string, role Role, exceptID string) bool {
	for id, m := range st.Machines {
		if m == nil || m.Revoked || m.Role != role || id == exceptID {
			continue
		}
		if m.Name == name {
			return true
		}
	}
	now := time.Now()
	for _, t := range st.Tokens {
		if t == nil || t.Used || t.Role != role || now.After(t.Expires) {
			continue
		}
		if t.Name == name {
			return true
		}
	}
	return false
}
