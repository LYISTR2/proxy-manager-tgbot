use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::protocol::Role;

pub const ETC_DIR: &str = "/etc/sbrelay";
pub const VAR_DIR: &str = "/var/lib/sbrelay";
pub const CONTROL_CONFIG: &str = "/etc/sbrelay/control.toml";
pub const AGENT_CONFIG: &str = "/etc/sbrelay/agent.toml";
pub const TLS_CERT: &str = "/etc/sbrelay/tls.crt";
pub const TLS_KEY: &str = "/etc/sbrelay/tls.key";
pub const SINGBOX_BIN: &str = "/usr/local/bin/sing-box";
pub const SINGBOX_CONFIG: &str = "/usr/local/etc/sing-box/config.json";
pub const SBRELAY_BIN: &str = "/usr/local/bin/sbrelay";
pub const PM_LINK: &str = "/usr/local/bin/pm";
pub const CONTROL_SERVICE: &str = "/etc/systemd/system/sbrelay-control.service";
pub const AGENT_SERVICE: &str = "/etc/systemd/system/sbrelay-agent.service";
pub const SINGBOX_SERVICE: &str = "/etc/systemd/system/sing-box.service";
pub const DEFAULT_REPO: &str = "LYISTR2/proxy-manager-tgbot";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    pub tg_token: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub public_url: String,
    #[serde(default = "default_var_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "default_cert_file")]
    pub cert_file: PathBuf,
    #[serde(default = "default_key_file")]
    pub key_file: PathBuf,
    #[serde(default)]
    pub owner_hint: Option<i64>,
    #[serde(default = "default_repo")]
    pub repo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub url: String,
    pub tls_pin: String,
    pub role: Role,
    #[serde(default)]
    pub machine_id: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default = "default_var_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_singbox_bin")]
    pub singbox_bin: PathBuf,
    #[serde(default = "default_singbox_config")]
    pub singbox_config: PathBuf,
    #[serde(default = "default_service")]
    pub service: String,
}

fn default_listen() -> String {
    "0.0.0.0:8443".to_string()
}
fn default_var_dir() -> PathBuf {
    PathBuf::from(VAR_DIR)
}
fn default_cert_file() -> PathBuf {
    PathBuf::from(TLS_CERT)
}
fn default_key_file() -> PathBuf {
    PathBuf::from(TLS_KEY)
}
fn default_repo() -> String {
    DEFAULT_REPO.to_string()
}
fn default_singbox_bin() -> PathBuf {
    PathBuf::from(SINGBOX_BIN)
}
fn default_singbox_config() -> PathBuf {
    PathBuf::from(SINGBOX_CONFIG)
}
fn default_service() -> String {
    "sing-box".to_string()
}

impl ControlConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("读取控制端配置失败: {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&raw).context("解析 control.toml 失败")?;
        cfg.public_url = validate_public_url(&cfg.public_url)?;
        if cfg.tg_token.trim().is_empty() {
            bail!("control.toml 缺少 tg_token");
        }
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self).context("序列化 control.toml 失败")?;
        write_atomic(path, body.as_bytes(), 0o600)
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("读取 agent 配置失败: {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&raw).context("解析 agent.toml 失败")?;
        cfg.url = validate_public_url(&cfg.url)?;
        cfg.tls_pin = validate_pin(&cfg.tls_pin)?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self).context("序列化 agent.toml 失败")?;
        write_atomic(path, body.as_bytes(), 0o600)
    }
}

/// 原子写文件：同目录临时文件 + 权限 + fsync + rename。
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).with_context(|| format!("创建目录失败: {}", dir.display()))?;

    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("sbrelay"),
        crate::protocol::rand_hex(6)
    );
    let tmp_path = dir.join(tmp_name);

    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp_path)
            .with_context(|| format!("创建临时文件失败: {}", tmp_path.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp_path, path)
            .with_context(|| format!("原子替换文件失败: {}", path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

pub fn validate_public_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = Url::parse(trimmed).with_context(|| format!("控制端地址不合法: {raw}"))?;
    if parsed.scheme() != "https" {
        bail!("控制端地址必须使用 https://: {raw}");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("控制端地址不能包含用户信息");
    }
    if parsed.host_str().is_none() {
        bail!("控制端地址缺少主机名");
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        bail!("控制端地址不能包含路径");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("控制端地址不能包含查询参数或锚点");
    }
    Ok(trimmed.to_string())
}

pub fn validate_pin(raw: &str) -> Result<String> {
    let pin = raw.trim().to_ascii_lowercase();
    if pin.len() != 64 || !pin.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("证书指纹（--pin）必须是 64 位十六进制 SHA-256");
    }
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation() {
        assert_eq!(
            validate_public_url("https://1.2.3.4:8443/").unwrap(),
            "https://1.2.3.4:8443"
        );
        assert_eq!(
            validate_public_url("https://[2001:db8::1]:8443").unwrap(),
            "https://[2001:db8::1]:8443"
        );
        assert!(validate_public_url("http://1.2.3.4:8443").is_err());
        assert!(validate_public_url("https://1.2.3.4:8443/path").is_err());
        assert!(validate_public_url("https://user:pass@1.2.3.4:8443").is_err());
    }

    #[test]
    fn pin_validation() {
        let good = "a".repeat(64);
        assert_eq!(validate_pin(&good.to_uppercase()).unwrap(), good);
        assert!(validate_pin("abcd").is_err());
        assert!(validate_pin(&"z".repeat(64)).is_err());
    }
}
