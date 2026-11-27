package store

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"sbrelay/internal/relaycfg"
)

func TestMachineAndCommandDeepCopy(t *testing.T) {
	st := openTest(t)
	defer st.Close()
	if err := st.With(func(s *State) error {
		s.Machines["m1"] = &Machine{
			ID:          "m1",
			Name:        "HK-01",
			Role:        RoleRelay,
			LastJSON:    json.RawMessage(`{"ok":true}`),
			RelayNode:   &relaycfg.NodeInfo{Server: "1.1.1.1", Port: 443},
			LandingNode: &relaycfg.NodeInfo{Server: "2.2.2.2", Port: 8443},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	m := st.Machine("m1")
	m.Name = "mutated"
	m.LastJSON[0] = 'X'
	m.RelayNode.Server = "9.9.9.9"
	m.LandingNode.Port = 1

	again := st.Machine("m1")
	if again.Name != "HK-01" || string(again.LastJSON) != `{"ok":true}` || again.RelayNode.Server != "1.1.1.1" || again.LandingNode.Port != 8443 {
		t.Fatalf("internal machine mutated: %+v", again)
	}

	relays := st.Relays()
	relays[0].Name = "mutated-slice"
	if st.Machine("m1").Name != "HK-01" {
		t.Fatal("Relays() returned alias to internal machine")
	}

	cmd := &PendingCmd{ID: "c1", Machine: "m1", Op: "switch", OutboundSpec: &relaycfg.OutboundSpec{Tag: "relay-out-1", Server: "3.3.3.3"}}
	if err := st.Enqueue(cmd); err != nil {
		t.Fatal(err)
	}
	gotCmd := st.Command("c1")
	gotCmd.OutboundSpec.Server = "8.8.8.8"
	if st.Command("c1").OutboundSpec.Server != "3.3.3.3" {
		t.Fatal("Command() returned alias to internal command")
	}

	// 并发 Touch 与 Machine 读写不应触发 data race
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			st.Touch("m1", true, json.RawMessage(`{"ok":true}`), &relaycfg.NodeInfo{Server: "1.1.1.1", Port: int64(443 + i)}, nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if cur := st.Machine("m1"); cur != nil {
				_ = len(cur.LastJSON)
				if cur.RelayNode != nil {
					_ = cur.RelayNode.Port
				}
			}
		}
	}()
	wg.Wait()
}

func TestFlockPreventsConcurrentOpen(t *testing.T) {
	dir := t.TempDir()
	st1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "锁被占用") {
		t.Fatalf("expected flock error on second Open, got %v", err)
	}
	if err := st1.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen after Close failed: %v", err)
	}
	_ = st2.Close()
}

func TestFinishRejectsEmptyMachineID(t *testing.T) {
	st := openTest(t)
	defer st.Close()
	if err := st.Enqueue(&PendingCmd{ID: "c1", Machine: "m1", Op: "status"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Finish("", "c1", json.RawMessage(`{"ok":true}`)); err == nil {
		t.Fatal("expected error for empty machineID")
	}
}

func TestCancelMarksDoneAndSkipsTakeCommands(t *testing.T) {
	st := openTest(t)
	defer st.Close()
	if err := st.Enqueue(&PendingCmd{ID: "c1", Machine: "m1", Op: "switch"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Cancel("c1"); err != nil {
		t.Fatal(err)
	}
	c := st.Command("c1")
	if c == nil || !c.Done || !strings.Contains(string(c.Result), "timeout") {
		t.Fatalf("unexpected command after cancel: %+v", c)
	}
	if cmds := st.TakeCommands("m1"); len(cmds) != 0 {
		t.Fatalf("cancelled command should not be dispatched: %+v", cmds)
	}
}
