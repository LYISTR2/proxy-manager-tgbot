package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPinsFromGeneratedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	if err := writeTestCert(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	certHex, spki, err := FromKeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(certHex) != 64 || strings.ContainsAny(certHex, "ABCDEF:") {
		// hex.EncodeToString 输出小写
		if len(certHex) != 64 {
			t.Fatalf("cert hex length: %d", len(certHex))
		}
	}
	if !strings.HasPrefix(spki, "sha256//") || len(spki) < len("sha256//")+40 {
		t.Fatalf("bad spki pin: %s", spki)
	}
	// 与 openssl 计算的 SPKI pin 对齐，保证 curl --pinnedpubkey 能用
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	out, err := exec.Command("bash", "-c",
		`openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64`,
		"openssl", certPath,
	).Output()
	if err != nil {
		t.Fatalf("openssl: %v", err)
	}
	want := "sha256//" + strings.TrimSpace(string(out))
	if spki != want {
		t.Fatalf("spki mismatch got %s want %s", spki, want)
	}
}

func writeTestCert(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "sbrelay-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cf, err := os.Create(certPath)
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
	return kf.Close()
}
