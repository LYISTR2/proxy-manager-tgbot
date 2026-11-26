package store

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNormalizeName(t *testing.T) {
	ok, err := NormalizeName("  香港节点  ")
	if err != nil || ok != "香港节点" {
		t.Fatalf("got %q %v", ok, err)
	}
	if _, err := NormalizeName("   "); !errors.Is(err, ErrNameEmpty) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := NormalizeName(""); !errors.Is(err, ErrNameEmpty) {
		t.Fatalf("blank: %v", err)
	}
	if _, err := NormalizeName("有\n换行"); !errors.Is(err, ErrNameBadChar) {
		t.Fatalf("newline: %v", err)
	}
	long := strings.Repeat("香", MaxNameRunes+1)
	if _, err := NormalizeName(long); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("too long: %v", err)
	}
	if utf8.RuneCountInString(long) != 33 {
		t.Fatal(utf8.RuneCountInString(long))
	}
	exact := strings.Repeat("香", MaxNameRunes)
	got, err := NormalizeName(exact)
	if err != nil || got != exact {
		t.Fatalf("32 runes should pass: %v", err)
	}
	if txt := NameErrorText(err); txt != "" {
		t.Fatal(txt)
	}
	if !strings.Contains(NameErrorText(errors.Join(ErrNameTooLong, errors.New("x"))), "再发一次") &&
		!strings.Contains(NameErrorText(fmtWrapTooLong()), "最多 32") {
		// NameErrorText on the wrapped too-long error from NormalizeName:
	}
	_, err = NormalizeName(long)
	if !strings.Contains(NameErrorText(err), "最多 32 个字") || !strings.Contains(NameErrorText(err), "你输入了 33 个") {
		t.Fatalf("hint: %s", NameErrorText(err))
	}
	if !strings.Contains(NameErrorText(ErrNameEmpty), NameHint) {
		t.Fatal(NameErrorText(ErrNameEmpty))
	}
}

func fmtWrapTooLong() error { _, err := NormalizeName(strings.Repeat("字", 33)); return err }

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func addRelay(t *testing.T, st *Store, id, name string) {
	t.Helper()
	if err := st.With(func(s *State) error {
		s.Machines[id] = &Machine{ID: id, Name: name, Role: RoleRelay}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRelayRenameAndDuplicate(t *testing.T) {
	st := openTest(t)
	addRelay(t, st, "m1", "HK-01")
	addRelay(t, st, "m2", "SG-01")
	if err := st.SetRelayName("m1", "香港一号"); err != nil {
		t.Fatal(err)
	}
	if st.RelayDisplayName("m1") != "香港一号" {
		t.Fatalf("got %q", st.RelayDisplayName("m1"))
	}
	// 立刻能读到，无需重新 Open
	if err := st.SetRelayName("m2", "香港一号"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("want taken, got %v", err)
	}
	if !strings.Contains(NameErrorText(errOr(st.SetRelayName("m2", "香港一号"))), "已有线路机叫「香港一号」") {
		t.Fatal(NameErrorText(errOr(st.SetRelayName("m2", "香港一号"))))
	}
	if err := st.SetRelayName("m1", "  香港一号  "); !errors.Is(err, ErrNameUnchanged) {
		t.Fatalf("same: %v", err)
	}
	if err := st.SetRelayName("m1", ""); !errors.Is(err, ErrNameEmpty) {
		t.Fatal(err)
	}
	if err := st.SetRelayName("m1", strings.Repeat("东", 33)); !errors.Is(err, ErrNameTooLong) {
		t.Fatal(err)
	}
	if err := st.SetRelayName("nope", "东京"); err == nil {
		t.Fatal("missing machine")
	}
}

func errOr(err error) error { return err }

func TestLandingRenameScope(t *testing.T) {
	st := openTest(t)
	addRelay(t, st, "m1", "HK-01")
	addRelay(t, st, "m2", "JP-01")
	if err := st.SetLandingName("m1", "relay-out-20001", "Landing-A"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLandingName("m1", "relay-out-20002", "Landing-B"); err != nil {
		t.Fatal(err)
	}
	// 同一线路机下重名
	if err := st.SetLandingName("m1", "relay-out-20002", "Landing-A"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("want taken, got %v", err)
	}
	// 不同线路机可以用同一个落地显示名
	if err := st.SetLandingName("m2", "relay-out-20001", "Landing-A"); err != nil {
		t.Fatal(err)
	}
	if st.LandingName("m1", "relay-out-20001") != "Landing-A" || st.LandingName("m2", "relay-out-20001") != "Landing-A" {
		t.Fatal(st.LandingNames("m1"), st.LandingNames("m2"))
	}
	if err := st.SetLandingName("m1", "relay-out-20001", "东京"); err != nil {
		t.Fatal(err)
	}
	if st.LandingName("m1", "relay-out-20001") != "东京" {
		t.Fatal("rename not visible immediately")
	}
	if err := st.SetLandingName("m1", "relay-out-20001", ""); !errors.Is(err, ErrNameEmpty) {
		t.Fatal(err)
	}
}

func TestSeedLandingDefaultsDoesNotOverwrite(t *testing.T) {
	st := openTest(t)
	addRelay(t, st, "m1", "HK-01")
	st.SeedLandingDefaults("m1", []LandingHint{
		{Tag: "relay-out-20001", NodeName: "Landing-A"},
		{Tag: "relay-out-20002", NodeName: "Landing-B"},
		{Tag: "relay-out-20003", NodeName: ""},          // 无效，跳过
		{Tag: "relay-out-20004", NodeName: "  "},        // 空，跳过
		{Tag: "relay-out-20005", NodeName: "Landing-A"}, // 与已种子名冲突，跳过
	})
	if st.LandingName("m1", "relay-out-20001") != "Landing-A" || st.LandingName("m1", "relay-out-20002") != "Landing-B" {
		t.Fatal(st.LandingNames("m1"))
	}
	if st.LandingName("m1", "relay-out-20003") != "" || st.LandingName("m1", "relay-out-20005") != "" {
		t.Fatalf("should skip: %v", st.LandingNames("m1"))
	}
	if err := st.SetLandingName("m1", "relay-out-20001", "东京"); err != nil {
		t.Fatal(err)
	}
	st.SeedLandingDefaults("m1", []LandingHint{{Tag: "relay-out-20001", NodeName: "Landing-A"}})
	if st.LandingName("m1", "relay-out-20001") != "东京" {
		t.Fatal("seed overwrote user rename")
	}
}

func TestNewRelayInstallTokenUnique(t *testing.T) {
	st := openTest(t)
	addRelay(t, st, "m1", "HK-01")
	if _, err := st.NewRelayInstallToken("HK-01", time.Hour); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("taken by machine: %v", err)
	}
	tok, err := st.NewRelayInstallToken("  新线路  ", time.Hour)
	if err != nil || tok.Name != "新线路" {
		t.Fatal(err, tok)
	}
	if _, err := st.NewRelayInstallToken("新线路", time.Hour); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("taken by token: %v", err)
	}
	if _, err := st.NewRelayInstallToken("", time.Hour); !errors.Is(err, ErrNameEmpty) {
		t.Fatal(err)
	}
	if _, err := st.NewRelayInstallToken(strings.Repeat("线", 33), time.Hour); !errors.Is(err, ErrNameTooLong) {
		t.Fatal(err)
	}
}

func TestOpenPreservesLandingNames(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	addRelay(t, st, "m1", "HK-01")
	if err := st.SetLandingName("m1", "relay-out-20001", "Landing-A"); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st2.LandingName("m1", "relay-out-20001") != "Landing-A" || st2.RelayDisplayName("m1") != "HK-01" {
		t.Fatal("not persisted")
	}
}
