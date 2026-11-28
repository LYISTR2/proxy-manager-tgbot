use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tar::{Archive, Builder, Header};

use crate::config::{ControlConfig, TlsMode};

const MAGIC: &[u8; 6] = b"SBRB01";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;
const PBKDF2_ITERS: u32 = 200_000;
const MAX_UNPACK_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub format_version: u32,
    pub sbrelay_version: String,
    pub created_at: DateTime<Utc>,
    pub public_url: String,
    #[serde(default)]
    pub tls_mode: TlsMode,
    #[serde(default = "default_true")]
    pub listen_tls: bool,
    #[serde(default)]
    pub machine_count: usize,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct BackupPayload {
    pub manifest: Option<BackupManifest>,
    pub control_toml: Vec<u8>,
    pub state_json: Option<Vec<u8>>,
    pub tls_crt: Option<Vec<u8>>,
    pub tls_key: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct StateCounts {
    #[serde(default)]
    machines: HashMap<String, MachineRevoked>,
}

#[derive(Deserialize)]
struct MachineRevoked {
    #[serde(default)]
    revoked: bool,
}

/// 生成 24 位随机高强度备份口令（去除易混淆字符）。
pub fn gen_backup_passphrase() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut raw = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect()
}

/// 将控制端配置、状态库与 TLS 证书打包并使用口令加密为 `.sbr` 字节流。
pub fn create_backup(
    control_cfg_path: &Path,
    state_override: Option<&[u8]>,
    passphrase: &str,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        bail!("备份口令不能为空");
    }

    let control_toml = fs::read(control_cfg_path)
        .with_context(|| format!("读取控制端配置失败: {}", control_cfg_path.display()))?;
    let control_str = std::str::from_utf8(&control_toml).context("control.toml 不是有效 UTF-8")?;
    let cfg = ControlConfig::from_toml_str(control_str)?;

    let state_json = match state_override {
        Some(bytes) => Some(bytes.to_vec()),
        None => {
            let p = cfg.data_dir.join("state.json");
            if p.exists() {
                Some(fs::read(&p).with_context(|| format!("读取状态文件失败: {}", p.display()))?)
            } else {
                None
            }
        }
    };

    let machine_count = state_json
        .as_deref()
        .and_then(|b| serde_json::from_slice::<StateCounts>(b).ok())
        .map(|s| s.machines.values().filter(|m| !m.revoked).count())
        .unwrap_or(0);

    let tls_crt = if cfg.cert_file.exists() {
        Some(
            fs::read(&cfg.cert_file)
                .with_context(|| format!("读取证书失败: {}", cfg.cert_file.display()))?,
        )
    } else {
        None
    };

    let tls_key = if cfg.key_file.exists() {
        Some(
            fs::read(&cfg.key_file)
                .with_context(|| format!("读取私钥失败: {}", cfg.key_file.display()))?,
        )
    } else {
        None
    };

    let manifest = BackupManifest {
        format_version: 1,
        sbrelay_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: Utc::now(),
        public_url: cfg.public_url,
        tls_mode: cfg.tls_mode,
        listen_tls: cfg.listen_tls,
        machine_count,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    let tar_gz = {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(encoder);
        append_tar_bytes(&mut tar, "manifest.json", &manifest_bytes, 0o600)?;
        append_tar_bytes(&mut tar, "control.toml", &control_toml, 0o600)?;
        if let Some(ref st) = state_json {
            append_tar_bytes(&mut tar, "state.json", st, 0o600)?;
        }
        if let Some(ref crt) = tls_crt {
            append_tar_bytes(&mut tar, "tls.crt", crt, 0o644)?;
        }
        if let Some(ref key) = tls_key {
            append_tar_bytes(&mut tar, "tls.key", key, 0o600)?;
        }
        let encoder = tar.into_inner()?;
        encoder.finish()?
    };

    encrypt_bytes(&tar_gz, passphrase)
}

/// 解密并解包 `.sbr` 备份字节流。
pub fn decrypt_backup(data: &[u8], passphrase: &str) -> Result<BackupPayload> {
    if passphrase.is_empty() {
        bail!("备份口令不能为空");
    }
    let tar_gz = decrypt_bytes(data, passphrase)?;

    let mut archive = Archive::new(GzDecoder::new(Cursor::new(tar_gz)));
    let mut total_read = 0u64;
    let mut manifest = None;
    let mut control_toml = None;
    let mut state_json = None;
    let mut tls_crt = None;
    let mut tls_key = None;

    for entry in archive.entries().context("备份归档格式损坏")? {
        let mut entry = entry.context("读取备份归档条目失败")?;
        let size = entry.header().size().unwrap_or(0);
        total_read = total_read
            .checked_add(size)
            .filter(|&s| s <= MAX_UNPACK_BYTES)
            .ok_or_else(|| anyhow!("备份解压体积超出安全限制"))?;

        let path = entry
            .path()
            .context("读取备份条目路径失败")?
            .to_string_lossy()
            .into_owned();
        let mut buf = Vec::with_capacity(size.min(1024 * 1024) as usize);
        entry.read_to_end(&mut buf)?;

        match path.as_str() {
            "manifest.json" => {
                manifest = serde_json::from_slice(&buf).ok();
            }
            "control.toml" => control_toml = Some(buf),
            "state.json" => state_json = Some(buf),
            "tls.crt" => tls_crt = Some(buf),
            "tls.key" => tls_key = Some(buf),
            other => bail!("备份包含未识别条目: {other}"),
        }
    }

    let control_toml = control_toml.ok_or_else(|| anyhow!("备份中缺少 control.toml"))?;
    Ok(BackupPayload {
        manifest,
        control_toml,
        state_json,
        tls_crt,
        tls_key,
    })
}

fn append_tar_bytes<W: std::io::Write>(
    tar: &mut Builder<W>,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_mtime(Utc::now().timestamp().max(0) as u64);
    header.set_cksum();
    tar.append_data(&mut header, name, Cursor::new(bytes))?;
    Ok(())
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");

    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &out[..HEADER_LEN],
            },
        )
        .map_err(|_| anyhow!("加密备份失败"))?;
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_bytes(data: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + 16 || &data[..MAGIC.len()] != MAGIC {
        bail!("备份文件格式无效或版本不受支持");
    }
    let header = &data[..HEADER_LEN];
    let salt = &data[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce_bytes = &data[MAGIC.len() + SALT_LEN..HEADER_LEN];
    let ct = &data[HEADER_LEN..];

    let key = derive_key(passphrase, salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ct,
                aad: header,
            },
        )
        .map_err(|_| anyhow!("解密失败：口令错误或备份文件已损坏"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::write_atomic;

    #[test]
    fn backup_roundtrip_wrong_pass_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("var");
        let crt = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        let ctl = dir.path().join("control.toml");

        write_atomic(&crt, b"CERTDATA", 0o644).unwrap();
        write_atomic(&key, b"KEYDATA", 0o600).unwrap();
        let state_bytes = br#"{"owner_id":42,"machines":{"m1":{"revoked":false},"m2":{"revoked":true}}}"#;
        write_atomic(&data_dir.join("state.json"), state_bytes, 0o600).unwrap();

        let cfg = ControlConfig {
            tg_token: "123456:secret".into(),
            listen: "127.0.0.1:8443".into(),
            public_url: "https://ctl.example.com".into(),
            tls_mode: TlsMode::Webpki,
            listen_tls: false,
            trust_proxy: true,
            data_dir: data_dir.clone(),
            cert_file: crt.clone(),
            key_file: key.clone(),
            owner_hint: Some(42),
            repo: "LYISTR2/proxy-manager-tgbot".into(),
        };
        cfg.save(&ctl).unwrap();

        let pass = gen_backup_passphrase();
        assert_eq!(pass.len(), 24);
        let enc = create_backup(&ctl, None, &pass).unwrap();
        assert!(!enc.windows(6).any(|w| w == b"secret"));

        let dec = decrypt_backup(&enc, &pass).unwrap();
        let manifest = dec.manifest.unwrap();
        assert_eq!(manifest.public_url, "https://ctl.example.com");
        assert_eq!(manifest.tls_mode, TlsMode::Webpki);
        assert!(!manifest.listen_tls);
        assert_eq!(manifest.machine_count, 1);
        assert_eq!(dec.state_json.as_deref(), Some(state_bytes.as_slice()));
        assert_eq!(dec.tls_crt.as_deref(), Some(b"CERTDATA".as_slice()));
        assert_eq!(dec.tls_key.as_deref(), Some(b"KEYDATA".as_slice()));

        assert!(decrypt_backup(&enc, "wrong-pass").is_err());

        let mut tampered = enc.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(decrypt_backup(&tampered, &pass).is_err());
    }

    #[test]
    fn backup_without_certs_works() {
        let dir = tempfile::tempdir().unwrap();
        let ctl = dir.path().join("control.toml");
        let cfg = ControlConfig {
            tg_token: "123456:secret".into(),
            listen: "127.0.0.1:8443".into(),
            public_url: "https://ctl.example.com".into(),
            tls_mode: TlsMode::Webpki,
            listen_tls: false,
            trust_proxy: true,
            data_dir: dir.path().join("var"),
            cert_file: dir.path().join("missing.crt"),
            key_file: dir.path().join("missing.key"),
            owner_hint: None,
            repo: "LYISTR2/proxy-manager-tgbot".into(),
        };
        cfg.save(&ctl).unwrap();

        let enc = create_backup(&ctl, Some(br#"{"owner_id":9}"#), "pass123").unwrap();
        let dec = decrypt_backup(&enc, "pass123").unwrap();
        assert!(dec.tls_crt.is_none());
        assert!(dec.tls_key.is_none());
        assert_eq!(dec.state_json.as_deref(), Some(br#"{"owner_id":9}"#.as_slice()));
    }
}
