use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::write_atomic;
use crate::protocol::{
    gen_ss2022_password, rand_hex, CommandResult, Egress, NodeInfo, NodeStatus, OutboundSpec, Role,
    SS2022_METHOD,
};

pub const INBOUND_TAG: &str = "sbrelay-in";
pub const DIRECT_TAG: &str = "direct";
pub const LANDING_TAG_PREFIX: &str = "landing-";
const MAX_BACKUPS: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EgressTarget {
    Direct,
    Landing { spec: OutboundSpec },
}

impl EgressTarget {
    pub fn key(&self) -> String {
        match self {
            EgressTarget::Direct => "direct".to_string(),
            EgressTarget::Landing { spec } => format!("landing:{}", spec.landing_id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSwitch {
    pub from: EgressTarget,
    pub to_key: String,
    pub after_sha256: String,
    pub backup: String,
    pub at: String,
    #[serde(default)]
    pub rolled_back: bool,
}

pub trait ServiceRunner: Send + Sync {
    fn check(&self, singbox_bin: &Path, config: &Path) -> Result<()>;
    fn restart(&self, service: &str) -> Result<()>;
    fn is_active(&self, service: &str) -> bool;
}

pub struct SystemdRunner;

impl ServiceRunner for SystemdRunner {
    fn check(&self, singbox_bin: &Path, config: &Path) -> Result<()> {
        let out = Command::new(singbox_bin)
            .args(["check", "-c"])
            .arg(config)
            .output()
            .with_context(|| format!("执行 {} check 失败", singbox_bin.display()))?;
        if !out.status.success() {
            let msg = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            bail!("sing-box check 未通过: {}", trim_err(&msg));
        }
        Ok(())
    }

    fn restart(&self, service: &str) -> Result<()> {
        let status = Command::new("/usr/bin/systemctl")
            .args(["restart", service])
            .status()
            .with_context(|| format!("执行 systemctl restart {service} 失败"))?;
        if !status.success() {
            bail!("systemctl restart {service} 失败");
        }
        Ok(())
    }

    fn is_active(&self, service: &str) -> bool {
        Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", service])
            .status()
            .is_ok_and(|s| s.success())
    }
}

pub struct SingboxManager<R: ServiceRunner = SystemdRunner> {
    pub config_path: PathBuf,
    pub singbox_bin: PathBuf,
    pub state_dir: PathBuf,
    pub service: String,
    pub role: Role,
    pub public_ip: Option<String>,
    pub settle_wait: Duration,
    pub runner: R,
}

impl SingboxManager<SystemdRunner> {
    pub fn system(
        config_path: PathBuf,
        singbox_bin: PathBuf,
        state_dir: PathBuf,
        service: String,
        role: Role,
        public_ip: Option<String>,
    ) -> Self {
        Self {
            config_path,
            singbox_bin,
            state_dir,
            service,
            role,
            public_ip,
            settle_wait: Duration::from_secs(2),
            runner: SystemdRunner,
        }
    }
}

impl<R: ServiceRunner> SingboxManager<R> {
    /// 初始化 sbrelay 专用 sing-box 配置；若已存在含 `sbrelay-in` 的配置则原样保留，
    /// 若文件非空但不含 `sbrelay-in` 则中止，绝不覆盖或劫持外部配置。
    pub fn init_node(
        &self,
        port_override: Option<u16>,
        password_override: Option<String>,
    ) -> Result<(NodeInfo, bool)> {
        if self.config_path.exists() {
            let raw = fs::read_to_string(&self.config_path)?;
            if !raw.trim().is_empty() {
                let doc: Value = serde_json::from_str(&raw).with_context(|| {
                    format!(
                        "已有配置 {} 无法解析为 JSON，拒绝覆盖",
                        self.config_path.display()
                    )
                })?;
                if let Some(mut existing) = extract_inbound(&doc) {
                    if existing.server.is_empty() {
                        existing.server = self.public_ip.clone().unwrap_or_default();
                    }
                    return Ok((existing, false));
                }
                bail!(
                    "检测到已有配置 {} 但不含 sbrelay 管理的入站 ({INBOUND_TAG})，已中止以避免覆盖原有配置",
                    self.config_path.display()
                );
            }
        }

        let port = match port_override {
            Some(p) if p > 0 => p,
            Some(_) => bail!("端口号必须为 1–65535"),
            None => pick_free_port(),
        };
        let password = password_override
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(gen_ss2022_password);

        let doc = json!({
            "log": { "level": "info", "timestamp": true },
            "inbounds": [{
                "type": "shadowsocks",
                "tag": INBOUND_TAG,
                "listen": "::",
                "listen_port": port,
                "method": SS2022_METHOD,
                "password": password,
            }],
            "outbounds": [{
                "type": "direct",
                "tag": DIRECT_TAG,
            }],
            "route": {
                "final": DIRECT_TAG,
            }
        });

        let bytes = serde_json::to_vec_pretty(&doc)?;
        self.check_candidate_bytes(&bytes)?;
        write_atomic(&self.config_path, &bytes, 0o600)?;

        let node = NodeInfo {
            server: self.public_ip.clone().unwrap_or_default(),
            port,
            method: SS2022_METHOD.to_string(),
            password,
        };
        Ok((node, true))
    }

    pub fn read_status(&self) -> Result<NodeStatus> {
        let raw = fs::read_to_string(&self.config_path)
            .with_context(|| format!("读取 {} 失败", self.config_path.display()))?;
        let doc: Value = serde_json::from_str(&raw).context("解析 sing-box config.json 失败")?;

        let mut node = extract_inbound(&doc);
        if let Some(ref mut n) = node {
            if n.server.is_empty() {
                n.server = self.public_ip.clone().unwrap_or_default();
            }
        }

        let egress = if self.role == Role::Relay {
            Some(extract_egress(&doc))
        } else {
            None
        };

        let can_rollback = self
            .load_last()
            .is_some_and(|l| !l.rolled_back && sha256_hex(raw.as_bytes()) == l.after_sha256);

        Ok(NodeStatus {
            role: self.role,
            node,
            egress,
            service: if self.runner.is_active(&self.service) {
                "active".into()
            } else {
                "inactive".into()
            },
            can_rollback,
        })
    }

    pub fn switch(&self, target: EgressTarget, op: &str) -> CommandResult {
        if self.role != Role::Relay {
            return CommandResult::err(op, "落地机不允许执行切换操作");
        }
        if let EgressTarget::Landing { ref spec } = target {
            if let Err(e) = spec.validate() {
                return CommandResult::err(op, e.to_string());
            }
        }

        let old_bytes = match fs::read(&self.config_path) {
            Ok(b) => b,
            Err(e) => return CommandResult::err(op, format!("读取配置失败: {e}")),
        };
        let mut doc: Value = match serde_json::from_slice(&old_bytes) {
            Ok(v) => v,
            Err(e) => return CommandResult::err(op, format!("解析配置失败: {e}")),
        };

        let cur_target = extract_egress_target(&doc);
        let from_key = cur_target.key();
        let to_key = target.key();

        if targets_equal(&cur_target, &target) {
            return CommandResult::err(op, "目标出口与当前相同，无需切换");
        }

        apply_target(&mut doc, &target);
        let mut new_bytes = match serde_json::to_vec_pretty(&doc) {
            Ok(b) => b,
            Err(e) => return CommandResult::err(op, e.to_string()),
        };
        new_bytes.push(b'\n');

        let backup = match self.backup(&old_bytes) {
            Ok(p) => p,
            Err(e) => return CommandResult::err(op, format!("备份失败，未做改动: {e}")),
        };

        if let Err(e) = self.check_candidate_bytes(&new_bytes) {
            return CommandResult::err(op, format!("配置校验未通过，未做改动: {e}"));
        }

        if let Err(e) = write_atomic(&self.config_path, &new_bytes, 0o600) {
            return CommandResult::err(op, format!("写入配置失败: {e}"));
        }

        if let Err(e) = self.restart_and_verify() {
            let restore_res = write_atomic(&self.config_path, &old_bytes, 0o600);
            let restart_res = self.restart_and_verify();
            let mut msg = format!("切换后服务异常，已自动回滚原配置: {e}");
            if let Err(re) = restore_res {
                msg.push_str(&format!("；恢复原文件失败: {re}"));
            }
            if let Err(re) = restart_res {
                msg.push_str(&format!("；回滚后重启失败: {re}（备份在 {backup}）"));
            }
            return CommandResult::err(op, msg);
        }

        let last = LastSwitch {
            from: cur_target,
            to_key: to_key.clone(),
            after_sha256: sha256_hex(&new_bytes),
            backup: backup.clone(),
            at: Utc::now().to_rfc3339(),
            rolled_back: op == "rollback",
        };
        let _ = self.save_last(&last);

        CommandResult {
            ok: true,
            op: op.to_string(),
            error: None,
            from: Some(from_key),
            to: Some(to_key),
            backup: Some(backup),
            status: self.read_status().ok(),
        }
    }

    pub fn rollback(&self) -> CommandResult {
        if self.role != Role::Relay {
            return CommandResult::err("rollback", "落地机不支持回滚");
        }
        let Some(last) = self.load_last() else {
            return CommandResult::err("rollback", "没有可回滚的切换记录");
        };
        if last.rolled_back {
            return CommandResult::err("rollback", "上次切换已回滚过");
        }
        let cur_bytes = match fs::read(&self.config_path) {
            Ok(b) => b,
            Err(e) => return CommandResult::err("rollback", format!("读取配置失败: {e}")),
        };
        if sha256_hex(&cur_bytes) != last.after_sha256 {
            return CommandResult::err(
                "rollback",
                format!(
                    "上次切换后配置已被外部修改，拒绝自动回滚（备份在 {}）",
                    last.backup
                ),
            );
        }
        self.switch(last.from, "rollback")
    }

    fn check_candidate_bytes(&self, bytes: &[u8]) -> Result<()> {
        let dir = self
            .config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("/tmp"));
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".sbrelay-check-{}.json", rand_hex(6)));
        write_atomic(&tmp, bytes, 0o600)?;
        let res = self.runner.check(&self.singbox_bin, &tmp);
        let _ = fs::remove_file(&tmp);
        res
    }

    fn restart_and_verify(&self) -> Result<()> {
        self.runner.restart(&self.service)?;
        if !self.settle_wait.is_zero() {
            std::thread::sleep(self.settle_wait);
        }
        if !self.runner.is_active(&self.service) {
            bail!("{} 重启后未处于运行状态", self.service);
        }
        Ok(())
    }

    fn backup(&self, raw: &[u8]) -> Result<String> {
        let bdir = self.state_dir.join("backups");
        fs::create_dir_all(&bdir)?;
        let name = format!(
            "{}-{}.json",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            rand_hex(3)
        );
        let path = bdir.join(name);
        write_atomic(&path, raw, 0o600)?;
        prune_backups(&bdir);
        Ok(path.display().to_string())
    }

    fn last_path(&self) -> PathBuf {
        self.state_dir.join("last_switch.json")
    }

    fn load_last(&self) -> Option<LastSwitch> {
        let raw = fs::read_to_string(self.last_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn save_last(&self, last: &LastSwitch) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(last)?;
        write_atomic(&self.last_path(), &bytes, 0o600)
    }
}

fn extract_inbound(doc: &Value) -> Option<NodeInfo> {
    let inbounds = doc.get("inbounds")?.as_array()?;
    for ib in inbounds {
        if ib.get("tag").and_then(Value::as_str) != Some(INBOUND_TAG) {
            continue;
        }
        let ty = ib.get("type").and_then(Value::as_str).unwrap_or("");
        let port = ib
            .get("listen_port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(0);
        if ty != "shadowsocks" || port == 0 {
            continue;
        }
        return Some(NodeInfo {
            server: String::new(),
            port,
            method: ib
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            password: ib
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    None
}

fn extract_egress(doc: &Value) -> Egress {
    match extract_egress_target(doc) {
        EgressTarget::Direct => Egress::Direct,
        EgressTarget::Landing { spec } => Egress::Landing {
            landing_id: spec.landing_id,
            server: spec.server,
            port: spec.port,
        },
    }
}

fn extract_egress_target(doc: &Value) -> EgressTarget {
    let final_tag = doc
        .get("route")
        .and_then(|r| r.get("final"))
        .and_then(Value::as_str)
        .unwrap_or(DIRECT_TAG);

    if let Some(lid) = final_tag.strip_prefix(LANDING_TAG_PREFIX) {
        if let Some(outs) = doc.get("outbounds").and_then(Value::as_array) {
            if let Some(o) = outs
                .iter()
                .find(|o| o.get("tag").and_then(Value::as_str) == Some(final_tag))
            {
                let server = o
                    .get("server")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let port = o
                    .get("server_port")
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(0);
                let method = o
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let password = o
                    .get("password")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if !server.is_empty() && port > 0 {
                    return EgressTarget::Landing {
                        spec: OutboundSpec {
                            landing_id: lid.to_string(),
                            server,
                            port,
                            method,
                            password,
                        },
                    };
                }
            }
        }
    }
    EgressTarget::Direct
}

fn targets_equal(a: &EgressTarget, b: &EgressTarget) -> bool {
    match (a, b) {
        (EgressTarget::Direct, EgressTarget::Direct) => true,
        (EgressTarget::Landing { spec: sa }, EgressTarget::Landing { spec: sb }) => sa == sb,
        _ => false,
    }
}

/// 只更新 outbounds 与 route.final，绝不触碰 inbounds。
fn apply_target(doc: &mut Value, target: &EgressTarget) {
    let Some(obj) = doc.as_object_mut() else {
        return;
    };
    let direct_out = json!({ "type": "direct", "tag": DIRECT_TAG });
    match target {
        EgressTarget::Direct => {
            obj.insert("outbounds".into(), Value::Array(vec![direct_out]));
            obj.insert("route".into(), json!({ "final": DIRECT_TAG }));
        }
        EgressTarget::Landing { spec } => {
            let tag = format!("{LANDING_TAG_PREFIX}{}", spec.landing_id);
            let landing_out = json!({
                "type": "shadowsocks",
                "tag": tag,
                "server": spec.server,
                "server_port": spec.port,
                "method": spec.method,
                "password": spec.password,
            });
            obj.insert(
                "outbounds".into(),
                Value::Array(vec![direct_out, landing_out]),
            );
            obj.insert("route".into(), json!({ "final": tag }));
        }
    }
}

fn prune_backups(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    if names.len() <= MAX_BACKUPS {
        return;
    }
    names.sort();
    for old in &names[..names.len() - MAX_BACKUPS] {
        let _ = fs::remove_file(dir.join(old));
    }
}

fn pick_free_port() -> u16 {
    let mut rng = rand::thread_rng();
    for _ in 0..64 {
        let p: u16 = rng.gen_range(20000..=59999);
        if TcpListener::bind(("0.0.0.0", p)).is_ok() && UdpSocket::bind(("0.0.0.0", p)).is_ok() {
            return p;
        }
    }
    rng.gen_range(20000..=59999)
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn trim_err(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() > 300 {
        format!("{}…", t.chars().take(300).collect::<String>())
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockRunner {
        check_ok: AtomicBool,
        active: AtomicBool,
        fail_next_restart: AtomicBool,
    }

    impl MockRunner {
        fn ok() -> Self {
            Self {
                check_ok: AtomicBool::new(true),
                active: AtomicBool::new(true),
                fail_next_restart: AtomicBool::new(false),
            }
        }
    }

    impl ServiceRunner for MockRunner {
        fn check(&self, _: &Path, _: &Path) -> Result<()> {
            if self.check_ok.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(anyhow!("mock check failed"))
            }
        }
        fn restart(&self, _: &str) -> Result<()> {
            if self.fail_next_restart.swap(false, Ordering::SeqCst) {
                return Err(anyhow!("mock restart failed"));
            }
            Ok(())
        }
        fn is_active(&self, _: &str) -> bool {
            self.active.load(Ordering::SeqCst)
        }
    }

    fn mgr(dir: &Path, role: Role, runner: MockRunner) -> SingboxManager<MockRunner> {
        SingboxManager {
            config_path: dir.join("config.json"),
            singbox_bin: PathBuf::from("/usr/local/bin/sing-box"),
            state_dir: dir.join("state"),
            service: "sing-box".into(),
            role,
            public_ip: Some("1.2.3.4".into()),
            settle_wait: Duration::ZERO,
            runner,
        }
    }

    #[test]
    fn init_switch_direct_and_rollback_preserve_inbound() {
        let dir = tempfile::tempdir().unwrap();
        let m = mgr(dir.path(), Role::Relay, MockRunner::ok());
        let (node, created) = m.init_node(Some(23456), Some("pass123".into())).unwrap();
        assert!(created);
        assert_eq!(node.port, 23456);
        assert_eq!(node.password, "pass123");

        // 再次 init 不覆盖已有入站
        let (node2, created2) = m.init_node(Some(34567), Some("other".into())).unwrap();
        assert!(!created2);
        assert_eq!(node2.port, 23456);
        assert_eq!(node2.password, "pass123");

        let spec = OutboundSpec {
            landing_id: "jp1".into(),
            server: "5.6.7.8".into(),
            port: 44333,
            method: SS2022_METHOD.into(),
            password: "lpass".into(),
        };

        // 切到落地
        let r1 = m.switch(EgressTarget::Landing { spec: spec.clone() }, "switch");
        assert!(r1.ok, "{:?}", r1.error);
        let st = m.read_status().unwrap();
        assert_eq!(st.node.as_ref().unwrap().password, "pass123");
        assert!(matches!(st.egress, Some(Egress::Landing { ref landing_id, .. }) if landing_id == "jp1"));
        assert!(st.can_rollback);

        // 重复切换同落地拒绝 noop
        let noop = m.switch(EgressTarget::Landing { spec }, "switch");
        assert!(!noop.ok);

        // 回滚到本机直出
        let rb = m.rollback();
        assert!(rb.ok, "{:?}", rb.error);
        assert_eq!(m.read_status().unwrap().egress, Some(Egress::Direct));
        assert!(!m.read_status().unwrap().can_rollback);
    }

    #[test]
    fn check_failure_and_restart_failure_do_not_corrupt_config() {
        let dir = tempfile::tempdir().unwrap();
        let m = mgr(dir.path(), Role::Relay, MockRunner::ok());
        m.init_node(Some(23456), Some("pass123".into())).unwrap();
        let before = fs::read(&m.config_path).unwrap();

        let spec = OutboundSpec {
            landing_id: "us1".into(),
            server: "9.9.9.9".into(),
            port: 30000,
            method: SS2022_METHOD.into(),
            password: "p".into(),
        };

        m.runner.check_ok.store(false, Ordering::SeqCst);
        let r_chk = m.switch(EgressTarget::Landing { spec: spec.clone() }, "switch");
        assert!(!r_chk.ok);
        assert_eq!(fs::read(&m.config_path).unwrap(), before);

        // 重启失败自动回滚到原文件
        m.runner.check_ok.store(true, Ordering::SeqCst);
        m.runner.fail_next_restart.store(true, Ordering::SeqCst);
        let r_rst = m.switch(EgressTarget::Landing { spec }, "switch");
        assert!(!r_rst.ok);
        assert_eq!(fs::read(&m.config_path).unwrap(), before);
    }

    #[test]
    fn refuses_foreign_config_without_sbrelay_tag() {
        let dir = tempfile::tempdir().unwrap();
        let m = mgr(dir.path(), Role::Relay, MockRunner::ok());

        // 已有其他 shadowsocks 入站（tag 不是 sbrelay-in）：绝不劫持也不覆盖
        let foreign = br#"{"inbounds":[{"type":"shadowsocks","tag":"user-ss","listen_port":8888,"method":"2022-blake3-aes-128-gcm","password":"abc"}]}"#;
        fs::write(&m.config_path, foreign).unwrap();
        assert!(m.init_node(Some(23456), Some("newpass".into())).is_err());
        assert_eq!(fs::read(&m.config_path).unwrap(), foreign);

        // 已有其他协议配置（如 vless）：绝不覆盖
        let foreign_vless = br#"{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":443}]}"#;
        fs::write(&m.config_path, foreign_vless).unwrap();
        assert!(m.init_node(Some(23456), Some("newpass".into())).is_err());
        assert_eq!(fs::read(&m.config_path).unwrap(), foreign_vless);
    }
}
