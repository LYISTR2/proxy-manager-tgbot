use std::fs;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Once};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::config::{validate_pin, write_atomic};

static INIT_CRYPTO: Once = Once::new();

pub fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = default_provider().install_default();
    });
}

/// 生成 10 年有效期 ECDSA P-256 自签证书，并返回证书 DER 的 SHA-256 指纹（小写 64 位 hex）。
pub fn generate_self_signed(cert_path: &Path, key_path: &Path, host: &str) -> Result<String> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    dn.push(DnType::OrganizationName, "sbrelay");
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2036, 12, 31);

    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![SanType::DnsName(
            host.try_into()
                .with_context(|| format!("证书主机名不合法: {host}"))?,
        )];
    }

    let key_pair = KeyPair::generate().context("生成 ECDSA 私钥失败")?;
    let cert = params.self_signed(&key_pair).context("生成自签证书失败")?;

    let pin = hex::encode(Sha256::digest(cert.der().as_ref()));
    write_atomic(cert_path, cert.pem().as_bytes(), 0o644)?;
    write_atomic(key_path, key_pair.serialize_pem().as_bytes(), 0o600)?;
    Ok(pin)
}

/// 读取 PEM 证书并计算其 DER SHA-256 指纹（小写 64 位 hex）。
pub fn cert_pin_from_file(cert_path: &Path) -> Result<String> {
    let certs = load_certs(cert_path)?;
    let first = certs.first().ok_or_else(|| anyhow!("证书文件为空"))?;
    Ok(hex::encode(Sha256::digest(first.as_ref())))
}

pub fn build_server_tls(cert_path: &Path, key_path: &Path) -> Result<RustlsConfig> {
    ensure_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .context("初始化 TLS 协议版本失败")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("加载服务端证书与私钥失败")?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(cfg)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let raw = fs::read(path).with_context(|| format!("读取证书失败: {}", path.display()))?;
    let mut reader = BufReader::new(raw.as_slice());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .context("解析 PEM 证书失败")?;
    if certs.is_empty() {
        bail!("证书文件中没有有效证书: {}", path.display());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let raw = fs::read(path).with_context(|| format!("读取私钥失败: {}", path.display()))?;
    let mut reader = BufReader::new(raw.as_slice());
    rustls_pemfile::private_key(&mut reader)
        .context("解析 PEM 私钥失败")?
        .ok_or_else(|| anyhow!("私钥文件中没有有效私钥: {}", path.display()))
}

#[derive(Debug)]
struct PinCertVerifier {
    expected_sha256: [u8; 32],
}

impl ServerCertVerifier for PinCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let got = Sha256::digest(end_entity.as_ref());
        // 常量时间比对
        let mut diff = 0u8;
        for (a, b) in got.iter().zip(self.expected_sha256.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(Error::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(std::io::Error::other(
                    "TLS 证书指纹与配置的 --pin 不符",
                ))),
            )));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 构造只信任指定 DER SHA-256 指纹证书的 HTTPS 客户端。
pub fn build_pinned_client(pin_hex: &str, timeout: Duration) -> Result<reqwest::Client> {
    ensure_crypto_provider();
    let pin = validate_pin(pin_hex)?;
    let bytes = hex::decode(&pin)?;
    let mut expected_sha256 = [0u8; 32];
    expected_sha256.copy_from_slice(&bytes);

    let tls_cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .context("初始化客户端 TLS 版本失败")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinCertVerifier { expected_sha256 }))
        .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_cfg)
        .timeout(timeout)
        .build()
        .context("构造 TLS Pinning HTTP 客户端失败")
}

/// 构造普通 HTTPS 客户端（走 webpki 根证书，用于访问 Telegram API / GitHub）。
pub fn build_public_client(timeout: Duration) -> Result<reqwest::Client> {
    ensure_crypto_provider();
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("sbrelay/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("构造 HTTPS 客户端失败")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};

    #[tokio::test]
    async fn self_signed_and_pin_verification() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        let pin = generate_self_signed(&cert, &key, "127.0.0.1").unwrap();
        assert_eq!(pin.len(), 64);
        assert_eq!(cert_pin_from_file(&cert).unwrap(), pin);

        let tls = build_server_tls(&cert, &key).unwrap();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();

        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        let handle = axum_server::Handle::new();
        let srv_handle = handle.clone();
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(std_listener, tls)
                .handle(srv_handle)
                .serve(app.into_make_service())
                .await;
        });

        let ok_cli = build_pinned_client(&pin, Duration::from_secs(5)).unwrap();
        let resp = ok_cli
            .get(format!("https://{addr}/healthz"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.text().await.unwrap(), "ok");

        let bad_pin = "0".repeat(64);
        let bad_cli = build_pinned_client(&bad_pin, Duration::from_secs(5)).unwrap();
        let err = bad_cli
            .get(format!("https://{addr}/healthz"))
            .send()
            .await;
        assert!(err.is_err(), "错误指纹必须被拒绝");

        handle.shutdown();
    }
}
