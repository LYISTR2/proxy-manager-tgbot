use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::Serialize;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::protocol::{
    rand_hex, redact, sign_request, CommandOp, CommandResult, PollRequest, PollResponse,
    RegisterRequest, RegisterResponse, ResultRequest,
};
use crate::singbox::{EgressTarget, ServiceRunner, SingboxManager, SystemdRunner};
use crate::tls::build_agent_client;

fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = cur {
        let s = e.to_string().trim().to_string();
        if !s.is_empty() && parts.last() != Some(&s) {
            parts.push(s);
        }
        cur = e.source();
    }
    redact(&parts.join(": "))
}

/// 使用一次性令牌向控制端注册（有指纹则强校验指纹，否则走公信 CA 校验）。
pub async fn register_with_token(
    url: &str,
    tls_pin: Option<&str>,
    token: &str,
) -> Result<RegisterResponse> {
    let cli = build_agent_client(tls_pin, Duration::from_secs(20))?;
    let endpoint = format!("{}/v1/register", url.trim_end_matches('/'));
    let resp = cli
        .post(&endpoint)
        .json(&RegisterRequest {
            token: token.trim().to_string(),
        })
        .send()
        .await
        .map_err(|e| {
            let msg = format_error_chain(&e);
            let lower = msg.to_ascii_lowercase();
            if tls_pin.is_none()
                && (lower.contains("certificate")
                    || msg.contains("UnknownIssuer")
                    || lower.contains("tls"))
            {
                anyhow!("连接控制端失败: {msg}（若控制端使用自签证书直连，请传入 --pin <指纹>）")
            } else {
                anyhow!("连接控制端失败: {msg}")
            }
        })?;

    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        bail!("注册令牌无效、已过期或已使用");
    }
    if status.as_u16() == 429 {
        bail!("注册失败次数过多，请 1 分钟后重试");
    }
    if !status.is_success() {
        bail!("注册失败，HTTP {}", status.as_u16());
    }
    let reg: RegisterResponse = resp.json().await.context("解析控制端注册响应失败")?;
    if reg.machine_id.is_empty() || reg.secret.is_empty() {
        bail!("控制端返回不完整");
    }
    Ok(reg)
}

pub struct AgentRunner<R: ServiceRunner = SystemdRunner> {
    pub url: String,
    pub machine_id: String,
    pub secret: String,
    pub client: reqwest::Client,
    pub singbox: Arc<SingboxManager<R>>,
}

impl AgentRunner<SystemdRunner> {
    pub fn from_config(cfg: &AgentConfig) -> Result<Self> {
        let machine_id = cfg
            .machine_id
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("agent.toml 缺少 machine_id，请先运行 sbrelay setup agent"))?;
        let secret = cfg
            .secret
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("agent.toml 缺少 secret，请先运行 sbrelay setup agent"))?;
        // 长轮询服务端挂起 25 秒，客户端超时设 45 秒留足余量
        let client = build_agent_client(cfg.tls_pin.as_deref(), Duration::from_secs(45))?;
        let singbox = Arc::new(SingboxManager::system(
            cfg.singbox_config.clone(),
            cfg.singbox_bin.clone(),
            cfg.state_dir.clone(),
            cfg.service.clone(),
            cfg.role,
            cfg.public_ip.clone(),
        ));
        Ok(Self {
            url: cfg.url.trim_end_matches('/').to_string(),
            machine_id,
            secret,
            client,
            singbox,
        })
    }
}

impl<R: ServiceRunner + 'static> AgentRunner<R> {
    async fn post_signed<T: Serialize>(&self, path: &str, payload: &T) -> Result<Vec<u8>> {
        let body = serde_json::to_vec(payload)?;
        let ts = Utc::now().timestamp();
        let nonce = rand_hex(8);
        let sig = sign_request(&self.secret, ts, &nonce, &body);

        let resp = self
            .client
            .post(format!("{}{}", self.url, path))
            .header("Content-Type", "application/json")
            .header("X-Machine-Id", &self.machine_id)
            .header("X-Ts", ts.to_string())
            .header("X-Nonce", nonce)
            .header("X-Sig", sig)
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!("{}", format_error_chain(&e)))?;

        let status = resp.status();
        let bytes = resp.bytes().await.unwrap_or_default();
        if !status.is_success() {
            let txt = String::from_utf8_lossy(&bytes);
            bail!("HTTP {} {}", status.as_u16(), redact(txt.trim()));
        }
        Ok(bytes.to_vec())
    }

    pub async fn execute_op(&self, op: CommandOp) -> CommandResult {
        let sb = self.singbox.clone();
        tokio::task::spawn_blocking(move || match op {
            CommandOp::Status => match sb.read_status() {
                Ok(st) => CommandResult {
                    ok: true,
                    op: "status".into(),
                    error: None,
                    from: None,
                    to: None,
                    backup: None,
                    status: Some(st),
                },
                Err(e) => CommandResult::err("status", e.to_string()),
            },
            CommandOp::SwitchLanding { spec } => {
                sb.switch(EgressTarget::Landing { spec }, "switch")
            }
            CommandOp::SwitchDirect => sb.switch(EgressTarget::Direct, "switch"),
            CommandOp::Rollback => sb.rollback(),
        })
        .await
        .unwrap_or_else(|e| CommandResult::err("internal", format!("任务执行异常: {e}")))
    }

    pub async fn poll_once(&self) -> Result<usize> {
        let sb = self.singbox.clone();
        let status = tokio::task::spawn_blocking(move || sb.read_status().ok())
            .await
            .ok()
            .flatten();

        let raw = self
            .post_signed("/v1/poll", &PollRequest { status })
            .await?;
        let pr: PollResponse = serde_json::from_slice(&raw).context("解析 poll 响应失败")?;
        let count = pr.commands.len();

        for cmd in pr.commands {
            let result = self.execute_op(cmd.op).await;
            if let Err(e) = self
                .post_signed(
                    "/v1/result",
                    &ResultRequest {
                        id: cmd.id,
                        result,
                    },
                )
                .await
            {
                warn!("上报命令结果失败: {}", redact(&e.to_string()));
            }
        }
        Ok(count)
    }

    pub async fn run_loop(&self, mut shutdown: watch::Receiver<bool>) {
        info!(
            "agent 已启动，machine_id={} role={} control={}",
            self.machine_id, self.singbox.role, self.url
        );
        loop {
            if *shutdown.borrow() {
                return;
            }
            let res = tokio::select! {
                _ = shutdown.changed() => return,
                r = self.poll_once() => r,
            };
            if let Err(e) = res {
                warn!("poll 失败: {}", redact(&e.to_string()));
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }
}

pub async fn run_agent_cmd(config_path: &Path) -> Result<()> {
    let cfg = AgentConfig::load(config_path)?;
    let runner = AgentRunner::from_config(&cfg)?;
    let (tx, rx) = watch::channel(false);

    tokio::spawn(async move {
        let _ = crate::ops::wait_shutdown_signal().await;
        let _ = tx.send(true);
    });

    runner.run_loop(rx).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::path::PathBuf;

    use crate::control::{router, ControlState};
    use crate::protocol::{Egress, OutboundSpec, Role, SS2022_METHOD};
    use crate::store::Store;
    use crate::tls::{build_pinned_client, build_server_tls, generate_self_signed};

    struct OkRunner;
    impl ServiceRunner for OkRunner {
        fn check(&self, _: &Path, _: &Path) -> Result<()> {
            Ok(())
        }
        fn restart(&self, _: &str) -> Result<()> {
            Ok(())
        }
        fn is_active(&self, _: &str) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn agent_registers_switches_landing_and_rolls_back_over_tls() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("ctl")).unwrap());
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        let pin = generate_self_signed(&cert, &key, "127.0.0.1").unwrap();
        let tls = build_server_tls(&cert, &key).unwrap();

        let state = ControlState::new(store.clone(), None);
        let app = router(state);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = axum_server::Handle::new();
        let h2 = handle.clone();
        tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls)
                .handle(h2)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await;
        });

        let url = format!("https://{addr}");
        let tok = store
            .new_install_token("香港测试", Role::Relay, Duration::from_secs(300))
            .unwrap();
        let reg = register_with_token(&url, Some(&pin), &tok.token)
            .await
            .unwrap();

        let sb = Arc::new(SingboxManager {
            config_path: dir.path().join("config.json"),
            singbox_bin: PathBuf::from("/usr/local/bin/sing-box"),
            state_dir: dir.path().join("agent-state"),
            service: "sing-box".into(),
            role: Role::Relay,
            public_ip: Some("2.2.2.2".into()),
            settle_wait: Duration::ZERO,
            runner: OkRunner,
        });
        sb.init_node(Some(33333), Some("fixed-pass".into())).unwrap();

        let runner = AgentRunner {
            url,
            machine_id: reg.machine_id.clone(),
            secret: reg.secret,
            client: build_pinned_client(&pin, Duration::from_secs(10)).unwrap(),
            singbox: sb,
        };

        // 下发切换落地命令 -> Agent 长轮询拉取执行并回传结果
        let spec = OutboundSpec {
            landing_id: "jp1".into(),
            server: "8.8.8.8".into(),
            port: 44444,
            method: SS2022_METHOD.into(),
            password: "lpass".into(),
        };
        let (_cid, rx) = store
            .enqueue_cmd(&reg.machine_id, CommandOp::SwitchLanding { spec })
            .unwrap();
        assert_eq!(runner.poll_once().await.unwrap(), 1);
        let res = rx.await.unwrap();
        assert!(res.ok, "{:?}", res.error);
        assert!(matches!(
            res.status.as_ref().and_then(|s| s.egress.as_ref()),
            Some(Egress::Landing { landing_id, .. }) if landing_id == "jp1"
        ));

        // 下发回滚命令 -> 恢复本机直出且入站密码保持不变
        let (_cid2, rx2) = store
            .enqueue_cmd(&reg.machine_id, CommandOp::Rollback)
            .unwrap();
        assert_eq!(runner.poll_once().await.unwrap(), 1);
        let res2 = rx2.await.unwrap();
        assert!(res2.ok, "{:?}", res2.error);
        let st2 = res2.status.unwrap();
        assert_eq!(st2.egress, Some(Egress::Direct));
        assert_eq!(st2.node.unwrap().password, "fixed-pass");

        handle.shutdown();
    }

    #[test]
    fn error_chain_preserves_root_cause_and_redacts() {
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "error sending request")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let err = Outer(std::io::Error::other("tls handshake failed password=topsecret"));
        let msg = format_error_chain(&err);
        assert!(msg.contains("error sending request"));
        assert!(msg.contains("tls handshake failed"));
        assert!(!msg.contains("topsecret"));
    }
}
