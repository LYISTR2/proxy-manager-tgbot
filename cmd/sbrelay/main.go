// sbrelay 单一二进制：control / agent 两个子命令。helper 是另一个 root 二进制。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"sbrelay/internal/agent"
	"sbrelay/internal/redact"
	"sbrelay/internal/store"
	"sbrelay/internal/tgbot"
	"sbrelay/internal/tlspin"
)

func main() {
	log.SetOutput(redact.Writer(os.Stderr))
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "用法: sbrelay control|agent|gen-cert|issue-token\n")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "control":
		runControl()
	case "agent":
		runAgent()
	case "issue-token":
		if err := issueToken(); err != nil {
			log.Fatal(err)
		}
	case "gen-cert":
		if err := genCert(env("SBRELAY_CERT", "/etc/sbrelay/tls.crt"), env("SBRELAY_KEY", "/etc/sbrelay/tls.key"), env("SBRELAY_CERT_HOST", "localhost")); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %s\n", os.Args[1])
		os.Exit(2)
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func runControl() {
	token := os.Getenv("SBRELAY_TG_TOKEN")
	if token == "" {
		log.Fatal("缺少环境变量 SBRELAY_TG_TOKEN")
	}
	var hint int64
	if s := os.Getenv("SBRELAY_OWNER_ID"); s != "" {
		hint, _ = strconv.ParseInt(s, 10, 64)
	}
	cfg := tgbot.Config{
		Token:     token,
		DataDir:   env("SBRELAY_DATA_DIR", "/var/lib/sbrelay"),
		Listen:    env("SBRELAY_LISTEN", "0.0.0.0:8443"),
		CertFile:  env("SBRELAY_CERT", "/etc/sbrelay/tls.crt"),
		KeyFile:   env("SBRELAY_KEY", "/etc/sbrelay/tls.key"),
		PublicURL: env("SBRELAY_PUBLIC_URL", "https://127.0.0.1:8443"),
		OwnerHint: hint,
		PkgDir:    env("SBRELAY_PKG_DIR", "/usr/local/lib/sbrelay"),
	}
	b, err := tgbot.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if pin, spki, err := tlspin.FromKeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
		log.Fatalf("加载 TLS 证书失败: %v", err)
	} else {
		b.SetPins(pin, spki)
		log.Printf("TLS pin=%s listen=%s", pin, cfg.Listen)
	}
	if id := b.PeekOwner(); id != 0 {
		log.Printf("已绑定管理员 user id=%d", id)
	} else {
		log.Printf("尚未绑定管理员：请先在 Telegram 里向 Bot 发送 /start")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := b.RunControl(ctx); err != nil && err != context.Canceled {
		log.Fatal(err)
	}
}

func runAgent() {
	cfg := agent.Config{
		URL:      os.Getenv("SBRELAY_URL"),
		Token:    os.Getenv("SBRELAY_TOKEN"),
		ID:       os.Getenv("SBRELAY_MACHINE_ID"),
		Secret:   os.Getenv("SBRELAY_SECRET"),
		TLSPin:   os.Getenv("SBRELAY_TLS_PIN"),
		Helper:   env("SBRELAY_HELPER", "/usr/local/lib/sbrelay/sbrelay-helper"),
		StateDir: env("SBRELAY_AGENT_STATE", "/var/lib/sbrelay-agent"),
		Role:     env("SBRELAY_ROLE", "relay"),
	}
	if cfg.URL == "" {
		log.Fatal("缺少 SBRELAY_URL")
	}
	if err := agent.Run(cfg); err != nil {
		log.Fatal(err)
	}
}

func genCert(certPath, keyPath, host string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"sbrelay"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	dir := certPath
	if i := lastSlash(dir); i >= 0 {
		dir = dir[:i]
	} else {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		cf.Close()
		return err
	}
	cf.Close()
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}); err != nil {
		kf.Close()
		return err
	}
	kf.Close()
	fmt.Printf("wrote %s %s\n", certPath, keyPath)
	return nil
}

func issueToken() error {
	name := env("SBRELAY_ISSUE_NAME", "relay-1")
	role := store.Role(env("SBRELAY_ISSUE_ROLE", "relay"))
	st, err := store.Open(env("SBRELAY_DATA_DIR", "/var/lib/sbrelay"))
	if err != nil {
		return err
	}
	tok, err := st.NewInstallToken(name, role, 2*time.Hour)
	if err != nil {
		return err
	}
	out := env("SBRELAY_ISSUE_OUT", "")
	if out == "" {
		fmt.Printf("TOKEN_LEN=%d expires=%s\n", len(tok.Token), tok.Expires.UTC().Format(time.RFC3339))
		return fmt.Errorf("未设置 SBRELAY_ISSUE_OUT，拒绝把令牌打到 stdout")
	}
	if err := os.WriteFile(out, []byte("SBRELAY_TOKEN="+tok.Token+"\n"), 0600); err != nil {
		return err
	}
	fmt.Printf("TOKEN_WRITTEN file=%s len=%d expires=%s\n", out, len(tok.Token), tok.Expires.UTC().Format(time.RFC3339))
	return nil
}

func lastSlash(p string) int {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return i
		}
	}
	return -1
}
