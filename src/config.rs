use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::protocol::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Pin,
    Webpki,
}

impl TlsMode {
    pub fn cn(self) -> &'static str {
        match self {
            TlsMode::Pin => "自签指纹固定",
            TlsMode::Webpki => "公信 CA（反代/域名）",
        }
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsMode::Pin => write!(f, "pin"),
            TlsMode::Webpki => write!(f, "webpki"),
        }
    }
}

pub const ETC_DIR: &str = "/etc/sbrelay";
pub const VAR_DIR: &str = "/var/lib/sbrelay";
pub const CONTROL_CONFIG: &str = "/etc/sbrelay/control.toml";
pub const AGENT_CONFIG: &str = "/etc/sbrelay/agent.toml";
pub const TLS_CERT: &str = "/etc/sbrelay/tls.crt";
pub const TLS_KEY: &str = "/etc/sbrelay/tls.key";
pub const SINGBOX_BIN: &str = "/usr/local/bin/sing-box";
pub const SINGBOX_CONFIG: &str = "/etc/sbrelay/sing-box.json";
pub const SINGBOX_SERVICE_NAME: &str = "sbrelay-sing-box";
pub const SBRELAY_BIN: &str = "/usr/local/bin/sbrelay";
pub const PM_LINK: &str = "/usr/local/bin/pm";
pub const CONTROL_SERVICE: &str = "/etc/systemd/system/sbrelay-control.service";
pub const AGENT_SERVICE: &str = "/etc/systemd/system/sbrelay-agent.service";
pub const SINGBOX_SERVICE: &str = "/etc/systemd/system/sbrelay-sing-box.service";
pub const DEFAULT_REPO: &str = "LYISTR2/proxy-manager-tgbot";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    pub tg_token: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub public_url: String,
    #[serde(default)]
    pub tls_mode: TlsMode,
    #[serde(default = "default_true")]
    pub listen_tls: bool,
    #[serde(default)]
    pub trust_proxy: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pin: Option<String>,
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

fn default_true() -> bool {
    true
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
    SINGBOX_SERVICE_NAME.to_string()
}

impl ControlConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("读取控制端配置失败: {}", path.display()))?;
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let mut cfg: Self = toml::from_str(raw).context("解析 control.toml 失败")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&mut self) -> Result<()> {
        self.public_url = validate_public_url(&self.public_url)?;
        if self.tg_token.trim().is_empty() {
            bail!("control.toml 缺少 tg_token");
        }
        let addr: SocketAddr = self
            .listen
            .parse()
            .with_context(|| format!("监听地址不合法: {}", self.listen))?;
        if !self.listen_tls && !addr.ip().is_loopback() {
            bail!("listen_tls = false 仅允许监听回环地址（如 127.0.0.1:8443）");
        }
        let host = public_url_host(&self.public_url)?;
        if self.tls_mode == TlsMode::Webpki && is_ip_host(&host) {
            bail!("tls_mode = webpki 要求 public_url 使用域名，不能使用裸 IP");
        }
        Ok(())
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
        Self::from_toml_str(&raw)
    }

    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let mut cfg: Self = toml::from_str(raw).context("解析 agent.toml 失败")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&mut self) -> Result<()> {
        self.url = validate_public_url(&self.url)?;
        self.tls_pin = match self.tls_pin.take() {
            Some(p) if !p.trim().is_empty() => Some(validate_pin(&p)?),
            _ => None,
        };
        if self.tls_pin.is_none() && is_ip_host(&public_url_host(&self.url)?) {
            bail!("控制端地址为 IP 时必须提供证书指纹（--pin）");
        }
        Ok(())
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

pub fn public_url_host(url: &str) -> Result<String> {
    let parsed = Url::parse(url.trim()).with_context(|| format!("控制端地址不合法: {url}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("控制端地址缺少主机名"))?;
    Ok(host.trim_matches(['[', ']']).to_string())
}

pub fn is_ip_host(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
}

/// 解析用户输入的域名 / URL / IP，返回标准化 `https://...` URL 以及是否显式携带了端口。
pub fn parse_public_url_input(raw: &str, default_ip_port: &str) -> Result<(String, bool)> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("控制端地址不能为空");
    }
    if trimmed.to_ascii_lowercase().starts_with("http://") {
        bail!("控制端地址必须使用 https://: {raw}");
    }
    let (candidate, explicit_port) = if trimmed.contains("://") {
        let validated = validate_public_url(trimmed)?;
        let parsed = Url::parse(&validated)?;
        return Ok((validated, parsed.port().is_some()));
    } else if let Ok(ip) = trimmed.trim_matches(['[', ']']).parse::<IpAddr>() {
        let formatted = if ip.is_ipv6() {
            format!("https://[{ip}]:{default_ip_port}")
        } else {
            format!("https://{ip}:{default_ip_port}")
        };
        (formatted, false)
    } else {
        let with_scheme = format!("https://{trimmed}");
        let validated = validate_public_url(&with_scheme)?;
        let parsed = Url::parse(&validated)?;
        return Ok((validated, parsed.port().is_some()));
    };
    let validated = validate_public_url(&candidate)?;
    Ok((validated, explicit_port))
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
    fn public_url_input_parsing() {
        assert_eq!(
            parse_public_url_input("ctl.example.com", "8443").unwrap(),
            ("https://ctl.example.com".into(), false)
        );
        assert_eq!(
            parse_public_url_input("https://ctl.example.com:8443/", "8443").unwrap(),
            ("https://ctl.example.com:8443".into(), true)
        );
        assert_eq!(
            parse_public_url_input("ctl.example.com:9443", "8443").unwrap(),
            ("https://ctl.example.com:9443".into(), true)
        );
        assert_eq!(
            parse_public_url_input("1.2.3.4", "8443").unwrap(),
            ("https://1.2.3.4:8443".into(), false)
        );
        assert_eq!(
            parse_public_url_input("2001:db8::1", "8443").unwrap(),
            ("https://[2001:db8::1]:8443".into(), false)
        );
        assert!(parse_public_url_input("http://ctl.example.com", "8443").is_err());
    }

    #[test]
    fn config_validation_and_legacy_compat() {
        let legacy_ctl = r#"
tg_token = "123:abc"
listen = "0.0.0.0:8443"
public_url = "https://1.2.3.4:8443"
"#;
        let ctl = ControlConfig::from_toml_str(legacy_ctl).unwrap();
        assert_eq!(ctl.tls_mode, TlsMode::Pin);
        assert!(ctl.listen_tls);
        assert!(!ctl.trust_proxy);

        let bad_plain = r#"
tg_token = "123:abc"
listen = "0.0.0.0:8443"
public_url = "https://ctl.example.com"
tls_mode = "webpki"
listen_tls = false
"#;
        assert!(ControlConfig::from_toml_str(bad_plain).is_err());

        let bad_webpki_ip = r#"
tg_token = "123:abc"
listen = "127.0.0.1:8443"
public_url = "https://1.2.3.4:8443"
tls_mode = "webpki"
listen_tls = false
"#;
        assert!(ControlConfig::from_toml_str(bad_webpki_ip).is_err());

        let ok_webpki = r#"
tg_token = "123:abc"
listen = "127.0.0.1:8443"
public_url = "https://ctl.example.com"
tls_mode = "webpki"
listen_tls = false
trust_proxy = true
"#;
        assert!(ControlConfig::from_toml_str(ok_webpki).is_ok());

        let legacy_agent = format!(
            "url = \"https://1.2.3.4:8443\"\ntls_pin = \"{}\"\nrole = \"relay\"\n",
            "a".repeat(64)
        );
        let ag = AgentConfig::from_toml_str(&legacy_agent).unwrap();
        assert_eq!(ag.tls_pin.as_deref(), Some("a".repeat(64).as_str()));

        let domain_agent = "url = \"https://ctl.example.com\"\nrole = \"landing\"\n";
        let ag2 = AgentConfig::from_toml_str(domain_agent).unwrap();
        assert!(ag2.tls_pin.is_none());

        let bad_ip_agent = "url = \"https://1.2.3.4:8443\"\nrole = \"relay\"\n";
        assert!(AgentConfig::from_toml_str(bad_ip_agent).is_err());
    }

    #[test]
    fn pin_validation() {
        let good = "a".repeat(64);
        assert_eq!(validate_pin(&good.to_uppercase()).unwrap(), good);
        assert!(validate_pin("abcd").is_err());
        assert!(validate_pin(&"z".repeat(64)).is_err());
    }
}
