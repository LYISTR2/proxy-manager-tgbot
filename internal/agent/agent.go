// Package agent 非 root 进程：主动连回控制端，只通过 sudo 调用固定 helper。
package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sbrelay/internal/redact"
	"sbrelay/internal/relaycfg"
)

type Config struct {
	URL      string // https://host:8443
	Token    string // 仅注册用；成功后丢弃
	ID       string
	Secret   string
	TLSPin   string // hex SHA-256 of raw cert
	Helper   string // /usr/local/lib/sbrelay/sbrelay-helper
	StateDir string
	Role     string
}

func (c *Config) client() *http.Client {
	// 自签证书：跳过系统 CA，在 TLS 握手阶段用 VerifyPeerCertificate 强制校验指纹，
	// 确保在发送任何 HTTP 请求头/令牌前即拒绝不匹配的证书。
	pin := strings.ToLower(strings.TrimSpace(c.TLSPin))
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if pin == "" {
				return nil
			}
			if len(rawCerts) == 0 {
				return fmt.Errorf("对端未提供 TLS 证书")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !strings.EqualFold(hex.EncodeToString(sum[:]), pin) {
				return fmt.Errorf("TLS 证书与 pin 不符，已拒绝")
			}
			return nil
		},
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func (c *Config) do(cli *http.Client, path string, body []byte) ([]byte, error) {
	if body == nil {
		body = []byte("{}")
	}
	req, err := http.NewRequest("POST", strings.TrimRight(c.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := fmt.Sprintf("%d", time.Now().UnixNano())
		mac := hmac.New(sha256.New, []byte(c.Secret))
		mac.Write([]byte(ts + "\n" + nonce + "\n" + string(body)))
		req.Header.Set("X-Machine-Id", c.ID)
		req.Header.Set("X-Ts", ts)
		req.Header.Set("X-Nonce", nonce)
		req.Header.Set("X-Sig", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func loadState(dir string) (id, secret string) {
	b, err := os.ReadFile(dir + "/agent.json")
	if err != nil {
		return "", ""
	}
	var s struct{ ID, Secret string }
	json.Unmarshal(b, &s)
	return s.ID, s.Secret
}

func saveState(dir, id, secret string) error {
	os.MkdirAll(dir, 0700)
	b, _ := json.Marshal(map[string]string{"id": id, "secret": secret})
	return os.WriteFile(dir+"/agent.json", b, 0600)
}

func (c *Config) register(cli *http.Client) error {
	if c.ID != "" && c.Secret != "" {
		return nil
	}
	id, sec := loadState(c.StateDir)
	if id != "" && sec != "" {
		c.ID, c.Secret = id, sec
		return nil
	}
	if c.Token == "" {
		return fmt.Errorf("没有注册令牌，也没有本地已注册状态")
	}
	reqBody, _ := json.Marshal(map[string]string{"token": c.Token})
	raw, err := c.do(cli, "/v1/register", reqBody)
	if err != nil {
		return err
	}
	var r struct {
		MachineID string `json:"machine_id"`
		Secret    string `json:"secret"`
		Name      string `json:"name"`
		Role      string `json:"role"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return err
	}
	c.ID, c.Secret = r.MachineID, r.Secret
	return saveState(c.StateDir, c.ID, c.Secret)
}

func (c *Config) helper(op string, stdin []byte) ([]byte, error) {
	cmd := exec.Command("sudo", "-n", "--", c.Helper, op)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	// helper 失败也返回 JSON，尽量交给控制端展示
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("调用 helper 失败: %v", err)
	}
	return out, nil
}

func (c *Config) status() []byte {
	out, err := c.helper("status", nil)
	if err != nil {
		j, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
		return j
	}
	return out
}

func Run(c Config) error {
	if c.Helper == "" {
		c.Helper = "/usr/local/lib/sbrelay/sbrelay-helper"
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/sbrelay-agent"
	}
	cli := c.client()
	if err := c.register(cli); err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}
	log.Printf("已连上控制端，machine_id=%s", c.ID)
	type cmd struct {
		ID           string                 `json:"id"`
		Op           string                 `json:"op"`
		Inbound      string                 `json:"inbound,omitempty"`
		Outbound     string                 `json:"outbound,omitempty"`
		OutboundSpec *relaycfg.OutboundSpec `json:"outbound_spec,omitempty"`
	}
	for {
		payload, _ := json.Marshal(map[string]any{"status": json.RawMessage(c.status())})
		raw, err := c.do(cli, "/v1/poll", payload)
		if err != nil {
			log.Printf("poll: %s", redact.Error(err))
			time.Sleep(5 * time.Second)
			continue
		}
		var wr struct {
			Commands []cmd `json:"commands"`
		}
		json.Unmarshal(raw, &wr)
		for _, cm := range wr.Commands {
			var out []byte
			var herr error
			switch cm.Op {
			case "status":
				out, herr = c.helper("status", nil)
			case "switch":
				req := map[string]any{"inbound": cm.Inbound, "outbound": cm.Outbound}
				if cm.OutboundSpec != nil {
					req["outbound_spec"] = cm.OutboundSpec
				}
				in, _ := json.Marshal(req)
				out, herr = c.helper("switch", in)
			case "rollback":
				out, herr = c.helper("rollback", nil)
			default:
				out, _ = json.Marshal(map[string]any{"ok": false, "error": "未知操作"})
			}
			if herr != nil && len(out) == 0 {
				out, _ = json.Marshal(map[string]any{"ok": false, "error": herr.Error()})
			}
			res, _ := json.Marshal(map[string]any{"id": cm.ID, "result": json.RawMessage(out)})
			if _, err := c.do(cli, "/v1/result", res); err != nil {
				log.Printf("result: %s", redact.Error(err))
			}
		}
		if len(wr.Commands) == 0 {
			time.Sleep(3 * time.Second)
		}
	}
}
