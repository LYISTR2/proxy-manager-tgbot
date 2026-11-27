use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;

use anyhow::{bail, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const SS2022_METHOD: &str = "2022-blake3-aes-128-gcm";
pub const TIME_WINDOW_SECS: i64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Relay,
    Landing,
}

impl Role {
    pub fn cn(self) -> &'static str {
        match self {
            Role::Relay => "线路机",
            Role::Landing => "落地机",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Relay => write!(f, "relay"),
            Role::Landing => write!(f, "landing"),
        }
    }
}

impl FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "relay" => Ok(Role::Relay),
            "landing" => Ok(Role::Landing),
            other => bail!("未知角色: {other}（应为 relay 或 landing）"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(default)]
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

impl NodeInfo {
    pub fn is_ready(&self) -> bool {
        !self.server.is_empty()
            && self.port > 0
            && !self.method.is_empty()
            && !self.password.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundSpec {
    pub landing_id: String,
    pub server: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

impl OutboundSpec {
    pub fn validate(&self) -> Result<()> {
        if !is_safe_id(&self.landing_id) {
            bail!("落地机 ID 不合法");
        }
        if self.server.is_empty()
            || self.server.len() > 128
            || self
                .server
                .chars()
                .any(|c| c.is_whitespace() || c == '/' || c == '\\')
        {
            bail!("落地地址不合法");
        }
        if self.port == 0 {
            bail!("落地端口不合法");
        }
        if self.method.trim().is_empty() || self.password.trim().is_empty() {
            bail!("缺少加密方式或密码");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Egress {
    Direct,
    Landing {
        landing_id: String,
        server: String,
        port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub role: Role,
    #[serde(default)]
    pub node: Option<NodeInfo>,
    #[serde(default)]
    pub egress: Option<Egress>,
    pub service: String,
    #[serde(default)]
    pub can_rollback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CommandOp {
    Status,
    SwitchLanding { spec: OutboundSpec },
    SwitchDirect,
    Rollback,
}

impl CommandOp {
    pub fn name(&self) -> &'static str {
        match self {
            CommandOp::Status => "status",
            CommandOp::SwitchLanding { .. } | CommandOp::SwitchDirect => "switch",
            CommandOp::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEnvelope {
    pub id: String,
    #[serde(flatten)]
    pub op: CommandOp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub ok: bool,
    pub op: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<NodeStatus>,
}

impl CommandResult {
    pub fn err(op: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            op: op.into(),
            error: Some(msg.into()),
            from: None,
            to: None,
            backup: None,
            status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub machine_id: String,
    pub secret: String,
    pub name: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRequest {
    #[serde(default)]
    pub status: Option<NodeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub commands: Vec<CommandEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultRequest {
    pub id: String,
    pub result: CommandResult,
}

pub fn is_safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn gen_ss2022_password() -> String {
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

pub fn sign_request(secret: &str, ts: i64, nonce: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(ts.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_request(
    secret: &str,
    ts: i64,
    nonce: &str,
    body: &[u8],
    sig_hex: &str,
    now: i64,
) -> bool {
    if secret.is_empty() || nonce.is_empty() || (now - ts).abs() > TIME_WINDOW_SECS {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(ts.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(nonce.as_bytes());
    mac.update(b"\n");
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

/// 按 SIP002 生成 SS2022 分享链接。
pub fn format_ss_link(node: &NodeInfo, display_name: &str) -> Option<String> {
    if !node.is_ready() {
        return None;
    }
    let userinfo = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", node.method, node.password));
    let host_port = if node.server.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6())
        || (node.server.contains(':') && !node.server.starts_with('['))
    {
        format!("[{}]:{}", node.server, node.port)
    } else {
        format!("{}:{}", node.server, node.port)
    };
    let encoded_tag = pct_encode_fragment(display_name);
    Some(format!("ss://{userinfo}@{host_port}#{encoded_tag}"))
}

fn pct_encode_fragment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 把日志/错误信息里的 Bot token、密码、私钥打码。
pub fn redact(input: &str) -> String {
    static RE_PEM: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
            .unwrap()
    });
    static RE_BOT_API: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)((?:https?://)?(?:api\.)?telegram\.org/bot)[^\s/'\\]+").unwrap()
    });
    static RE_BOT_TOKEN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{6,16}:[A-Za-z0-9_-]{20,}\b").unwrap());
    static RE_PASS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)((?:ssh[_-])?pass(?:word|wd|phrase)?\s*[=:]\s*)[^\s]+").unwrap()
    });

    if input.is_empty() {
        return String::new();
    }
    let s = RE_PEM.replace_all(input, "[redacted private key]");
    let s = RE_BOT_API.replace_all(&s, "${1}***");
    let s = RE_BOT_TOKEN.replace_all(&s, "***");
    let s = RE_PASS.replace_all(&s, "${1}***");
    s.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_roundtrip_and_window() {
        let secret = "0123456789abcdef";
        let now = 1_700_000_000;
        let body = br#"{"status":null}"#;
        let sig = sign_request(secret, now, "nonce1", body);

        assert!(verify_request(secret, now, "nonce1", body, &sig, now + 10));
        assert!(!verify_request(secret, now, "nonce1", body, &sig, now + 200));
        assert!(!verify_request(secret, now, "nonce2", body, &sig, now));
        assert!(!verify_request(secret, now, "nonce1", b"{}", &sig, now));
    }

    #[test]
    fn ss_link_formats_ipv4_and_ipv6() {
        let n4 = NodeInfo {
            server: "1.2.3.4".into(),
            port: 30000,
            method: SS2022_METHOD.into(),
            password: "secret".into(),
        };
        let link = format_ss_link(&n4, "香港节点").unwrap();
        assert!(link.starts_with("ss://"));
        assert!(link.contains("@1.2.3.4:30000#"));

        let n6 = NodeInfo {
            server: "2001:db8::1".into(),
            ..n4
        };
        let link6 = format_ss_link(&n6, "v6").unwrap();
        assert!(link6.contains("@[2001:db8::1]:30000#v6"));
    }

    #[test]
    fn redact_hides_secrets() {
        let s = "err https://api.telegram.org/bot123456789:ABCDEFghijklmnopQRSTUV123/getUpdates password=mysecret";
        let r = redact(s);
        assert!(!r.contains("ABCDEFghijklmnopQRSTUV123"));
        assert!(!r.contains("mysecret"));
        assert!(r.contains("api.telegram.org/bot***"));
    }
}
