package tgbot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 取出 install-agent.sh 里真正用于注册的 python 片段，在本地 TLS 服务上跑：成功 / 令牌被拒 / 指纹不符。
func registerSnippet(t *testing.T) string {
	src, err := os.ReadFile(filepath.Join(findRepoRoot(t), "deploy", "install-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, `SBRELAY_REG_TOKEN="$TOKEN" python3 -`)
	if i < 0 {
		t.Fatal("register snippet not found")
	}
	s = s[i:]
	s = s[strings.Index(s, "\n")+1:]
	return s[:strings.Index(s, "\nPY\n")+1]
}

func TestInstallAgentRegisterSnippet(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	py := registerSnippet(t)
	if strings.Contains(py, "sys.argv[3]") && strings.Contains(py, "token = sys.argv") {
		t.Fatal("token must not come from argv")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Token string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/v1/register" || req.Token != fakeInstallToken {
			http.Error(w, "invalid token "+req.Token, 403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"machine_id": "m1", "secret": "s1", "role": "landing", "name": "测试"})
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	pin := hex.EncodeToString(sum[:])
	dir := t.TempDir()

	run := func(token, pin string) (string, error) {
		out := filepath.Join(dir, "reg.json")
		_ = os.Remove(out)
		cmd := exec.Command("python3", "-", srv.URL, pin, out)
		cmd.Stdin = strings.NewReader(py)
		cmd.Env = append(os.Environ(), "SBRELAY_REG_TOKEN="+token)
		b, err := cmd.CombinedOutput()
		return string(b), err
	}

	if out, err := run(fakeInstallToken, pin); err != nil {
		t.Fatalf("valid token: %v %s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "reg.json"))
	if !strings.Contains(string(b), `"role": "landing"`) {
		t.Fatalf("reg.json: %s", b)
	}

	out, err := run("revoked-"+fakeInstallToken, pin)
	if err == nil || !strings.Contains(out, "令牌无效") {
		t.Fatalf("bad token should be rejected: %v %s", err, out)
	}
	if strings.Contains(out, fakeInstallToken) {
		t.Fatal("rejection echoed token")
	}

	out, err = run(fakeInstallToken, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(out, "指纹") {
		t.Fatalf("wrong pin should be rejected: %v %s", err, out)
	}
}
