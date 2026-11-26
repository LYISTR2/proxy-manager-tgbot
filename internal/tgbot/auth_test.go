package tgbot

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"sbrelay/internal/store"
)

// 仅测试用假 token，不得使用真实凭据。
const fakeBotToken = "123456789:AAFakeToken_forUnitTestsOnly012345"

type recTransport struct {
	mu    sync.Mutex
	calls []string
}

func (r *recTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, req.URL.Path) // path 仍可能含假 token，下面断言时只看 method 尾巴
	body := `{"ok":true,"result":{"message_id":1}}`
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (r *recTransport) methods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.calls))
	for _, p := range r.calls {
		if i := strings.LastIndex(p, "/"); i >= 0 {
			out = append(out, p[i+1:])
		}
	}
	return out
}

func testBotWithOwner(t *testing.T, owner int64) (*Bot, *recTransport) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if owner != 0 {
		if err := st.SetOwner(owner); err != nil {
			t.Fatal(err)
		}
	}
	rt := &recTransport{}
	b := &Bot{
		cfg:    Config{Token: fakeBotToken},
		st:     st,
		http:   &http.Client{Transport: rt, Timeout: 5 * time.Second},
		pend:   map[string]string{},
		wait:   map[string]chan json.RawMessage{},
		expect: map[int64]expect{},
	}
	return b, rt
}

func TestUnauthorizedUserGetsNoReply(t *testing.T) {
	b, rt := testBotWithOwner(t, 1001)
	// 未在白名单的 chat/user，发 /start /status /add 以及点按钮，都不应触发发消息
	stranger := &User{ID: 2002}
	chat := &Chat{ID: 2002}
	b.handleMsg(&Message{ID: 1, Text: "/start", Chat: chat, From: stranger})
	b.handleMsg(&Message{ID: 2, Text: "/status", Chat: chat, From: stranger})
	b.handleMsg(&Message{ID: 3, Text: "/add 偷渡", Chat: chat, From: stranger})
	b.handleCB(&CBQ{ID: "cb1", From: stranger, Data: "home", Message: &Message{ID: 9, Chat: chat}})
	if calls := rt.methods(); len(calls) != 0 {
		t.Fatalf("unauthorized user triggered API calls: %v", calls)
	}
	if b.st.Owner() != 1001 {
		t.Fatalf("owner changed to %d", b.st.Owner())
	}
}

func TestOwnerCommandsReachAPI(t *testing.T) {
	b, rt := testBotWithOwner(t, 1001)
	owner := &User{ID: 1001}
	chat := &Chat{ID: 1001}
	b.handleMsg(&Message{ID: 1, Text: "/start", Chat: chat, From: owner})
	meth := rt.methods()
	if len(meth) == 0 || meth[0] != "sendMessage" {
		t.Fatalf("owner /start should sendMessage, got %v", meth)
	}
}

func TestRegisterTokenIsOneTime(t *testing.T) {
	b, _ := testBotWithOwner(t, 1001)
	tok, err := b.st.NewRelayInstallToken("测试甲", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux := b.AgentMux()
	body := []byte(`{"token":"` + tok.Token + `"}`)
	req := httptest.NewRequest("POST", "/v1/register", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("first register: %d %s", rec.Code, rec.Body.String())
	}
	req2 := httptest.NewRequest("POST", "/v1/register", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != 403 {
		t.Fatalf("second register should be 403, got %d %s", rec2.Code, rec2.Body.String())
	}
}

func sign(secret, ts, nonce, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + nonce + "\n" + body))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestAgentAuthHMACAndReplayWindow(t *testing.T) {
	b, _ := testBotWithOwner(t, 1001)
	secret := "unit-test-hmac-secret-not-real-0001"
	if err := b.st.With(func(s *store.State) error {
		s.Machines["m1"] = &store.Machine{ID: "m1", Name: "测试甲", Role: store.RoleRelay, Secret: secret, Online: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mux := b.AgentMux()
	body := []byte(`{"status":{}}`)
	post := func(ts, nonce, sig string) int {
		req := httptest.NewRequest("POST", "/v1/poll", bytes.NewReader(body))
		req.Header.Set("X-Machine-Id", "m1")
		req.Header.Set("X-Ts", ts)
		req.Header.Set("X-Nonce", nonce)
		req.Header.Set("X-Sig", sig)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "n-one"
	sig := sign(secret, ts, nonce, string(body))
	if code := post(ts, nonce, sig); code != 200 {
		t.Fatalf("valid: %d", code)
	}
	// 错签名
	if code := post(ts, nonce+"x", sig); code != 401 {
		t.Fatalf("bad nonce/sig: %d", code)
	}
	// 过期时间窗
	old := strconv.FormatInt(time.Now().Unix()-300, 10)
	oldSig := sign(secret, old, "n-old", string(body))
	if code := post(old, "n-old", oldSig); code != 401 {
		t.Fatalf("stale ts: %d", code)
	}
	// 同一 nonce 重放（在时间窗内）应拒绝
	if code := post(ts, nonce, sig); code != 401 {
		t.Fatalf("replay nonce should be 401, got %d", code)
	}
}
