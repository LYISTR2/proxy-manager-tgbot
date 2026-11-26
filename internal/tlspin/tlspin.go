// Package tlspin 计算控制端自签证书的两种指纹：
// 证书 DER 的 SHA-256（agent 校验用，十六进制），以及公钥 SPKI 的
// sha256//Base64（curl --pinnedpubkey 用）。
package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// FromKeyPair 读取证书和私钥，返回证书指纹（hex）和 curl 用的 SPKI pin。
func FromKeyPair(certFile, keyFile string) (certHex, spkiPin string, err error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", "", err
	}
	if len(c.Certificate) == 0 {
		return "", "", fmt.Errorf("证书为空")
	}
	return FromDER(c.Certificate[0])
}

// FromDER 由证书 DER 计算两种指纹。
func FromDER(certDER []byte) (certHex, spkiPin string, err error) {
	certHex = CertHex(certDER)
	spkiPin, err = SPKIPin(certDER)
	return certHex, spkiPin, err
}

// CertHex 是证书原始 DER 的 SHA-256 十六进制，供 agent 的 TLS pin 使用。
func CertHex(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return hex.EncodeToString(sum[:])
}

// SPKIPin 返回 curl --pinnedpubkey 所需的 sha256// + Base64(SHA-256(SPKI))。
func SPKIPin(certDER []byte) (string, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:]), nil
}
