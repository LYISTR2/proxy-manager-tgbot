use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::sync::watch;
use tracing::info;

use crate::agent::register_with_token;
use crate::backup::{create_backup, decrypt_backup, gen_backup_passphrase};
use crate::bot::Bot;
use crate::config::{
    is_ip_host, parse_public_url_input, public_url_host, validate_pin, write_atomic, AgentConfig,
    ControlConfig, TlsMode, AGENT_CONFIG, AGENT_SERVICE, CONTROL_CONFIG, CONTROL_SERVICE,
    DEFAULT_REPO, ETC_DIR, PM_LINK, SBRELAY_BIN, SINGBOX_BIN, SINGBOX_CONFIG, SINGBOX_SERVICE,
    SINGBOX_SERVICE_NAME, TLS_CERT, TLS_KEY, VAR_DIR,
};
use crate::control::{router, ControlState};
use crate::singbox::SingboxManager;
use crate::store::Store;
use crate::tls::{build_public_client, build_server_tls, cert_pin_from_file, generate_self_signed};
use crate::TlsModeArg;

pub async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub async fn run_control_cmd(config_path: &Path) -> Result<()> {
    let cfg = ControlConfig::load(config_path)?;
    let store = std::sync::Arc::new(Store::open(&cfg.data_dir)?);
    let addr: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("监听地址不合法: {}", cfg.listen))?;

    let pin = if cfg.listen_tls {
        Some(cert_pin_from_file(&cfg.cert_file)?)
    } else {
        None
    };

    let bot = Bot::new(cfg.clone(), config_path.to_path_buf(), store.clone(), pin.clone())?;
    let bot_hook = bot.clone();
    let ready_hook = std::sync::Arc::new(move |mid: String| {
        let b = bot_hook.clone();
        tokio::spawn(async move { b.notify_node_ready(&mid).await });
    });

    let state = ControlState::new_with_proxy(store, Some(ready_hook), cfg.trust_proxy);
    let app = router(state);

    let (tx, rx) = watch::channel(false);
    let handle = axum_server::Handle::new();
    let srv_handle = handle.clone();

    tokio::spawn(async move {
        wait_shutdown_signal().await;
        let _ = tx.send(true);
        srv_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });

    let bot_task = tokio::spawn(bot.run_polling(rx));

    if cfg.listen_tls {
        let tls_cfg = build_server_tls(&cfg.cert_file, &cfg.key_file)?;
        info!(
            "控制端启动成功 (HTTPS) listen={} public_url={} tls_mode={} tls_pin={}",
            addr,
            cfg.public_url,
            cfg.tls_mode,
            pin.as_deref().unwrap_or("-")
        );
        axum_server::bind_rustls(addr, tls_cfg)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .context("HTTPS 控制端服务异常退出")?;
    } else {
        if !addr.ip().is_loopback() {
            bail!("listen_tls = false 仅允许监听回环地址");
        }
        info!(
            "控制端启动成功 (HTTP/反代后端) listen={} public_url={} tls_mode={}",
            addr, cfg.public_url, cfg.tls_mode
        );
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .context("HTTP 控制端服务异常退出")?;
    }

    let _ = bot_task.await;
    Ok(())
}

pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("请以 root 运行（例如先 sudo -i 或加 sudo）");
    }
    Ok(())
}

struct HttpsProbe {
    webpki_ok: bool,
    is_cloudflare: bool,
    healthz_ok: bool,
}

fn detect_local_proxy() -> Option<String> {
    for svc in ["caddy", "nginx", "openresty", "traefik", "haproxy"] {
        if systemctl_active(&format!("{svc}.service")) {
            return Some(format!("{svc}.service"));
        }
    }
    if TcpListener::bind("0.0.0.0:443")
        .is_err_and(|e| e.kind() == io::ErrorKind::AddrInUse)
    {
        return Some("443 端口已被占用".to_string());
    }
    None
}

async fn dns_matches_local_ip(host: &str, local_ip: Option<&str>) -> Option<bool> {
    let local = local_ip?.parse::<IpAddr>().ok()?;
    let addrs = tokio::net::lookup_host((host, 443)).await.ok()?;
    let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
    if ips.is_empty() {
        return None;
    }
    Some(ips.contains(&local))
}

async fn probe_public_https(public_url: &str) -> HttpsProbe {
    let Ok(cli) = build_public_client(Duration::from_secs(5)) else {
        return HttpsProbe {
            webpki_ok: false,
            is_cloudflare: false,
            healthz_ok: false,
        };
    };
    let url = format!("{}/healthz", public_url.trim_end_matches('/'));
    match cli.get(url).send().await {
        Ok(resp) => {
            let server_cf = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.to_ascii_lowercase().contains("cloudflare"));
            let is_cloudflare = server_cf || resp.headers().contains_key("cf-ray");
            let status_ok = resp.status().is_success();
            let body = resp.text().await.unwrap_or_default();
            HttpsProbe {
                webpki_ok: true,
                is_cloudflare,
                healthz_ok: status_ok && body.trim() == "ok",
            }
        }
        Err(_) => HttpsProbe {
            webpki_ok: false,
            is_cloudflare: false,
            healthz_ok: false,
        },
    }
}

fn ensure_url_port(url: &str, port: &str) -> Result<String> {
    let mut parsed = url::Url::parse(url)?;
    if parsed.port().is_none() {
        let port_num: u16 = port.parse().context("端口不合法")?;
        if port_num != 443 {
            parsed
                .set_port(Some(port_num))
                .map_err(|_| anyhow!("设置端口失败"))?;
        }
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn resolve_listen_with_tls(
    listen_override: Option<&str>,
    existing: Option<&ControlConfig>,
    preferred_mode: TlsMode,
    default_listen: &str,
    plain_http: bool,
) -> Result<(String, bool)> {
    let raw = listen_override
        .or_else(|| {
            existing
                .filter(|c| c.tls_mode == preferred_mode)
                .map(|c| c.listen.as_str())
        })
        .unwrap_or(default_listen);
    let listen = normalize_listen(raw)?;
    let addr: SocketAddr = listen.parse()?;
    let listen_tls = if preferred_mode == TlsMode::Webpki {
        !plain_http && !addr.ip().is_loopback()
    } else {
        true
    };
    Ok((listen, listen_tls))
}

fn print_reverse_proxy_snippets(public_url: &str, listen: &str, listen_tls: bool) {
    let host = public_url_host(public_url).unwrap_or_else(|_| "ctl.example.com".into());
    let upstream = if listen_tls {
        format!("https://{listen}")
    } else {
        format!("http://{listen}")
    };
    println!();
    println!("请确保反代已将 {public_url} 转发到 {upstream}（以下配置二选一）：");
    println!();
    println!("  [Caddyfile 示例]");
    println!("  {host} {{");
    if listen_tls {
        println!("      reverse_proxy {upstream} {{");
        println!("          transport http {{");
        println!("              tls_insecure_skip_verify");
        println!("          }}");
        println!("      }}");
    } else {
        println!("      reverse_proxy {upstream}");
    }
    println!("  }}");
    println!();
    println!("  [Nginx 示例（443 server 块内）]");
    println!("  location / {{");
    println!("      proxy_pass {upstream};");
    println!("      proxy_http_version 1.1;");
    println!("      proxy_set_header Host $host;");
    println!("      proxy_set_header X-Real-IP $remote_addr;");
    println!("      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
    println!("      proxy_set_header X-Forwarded-Proto $scheme;");
    println!("      proxy_read_timeout 60s;");
    println!("  }}");
}

async fn write_and_start_control_service() -> Result<()> {
    let unit = format!(
        "[Unit]\n\
         Description=sbrelay Telegram control plane\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={SBRELAY_BIN} control\n\
         WorkingDirectory={VAR_DIR}\n\
         Restart=on-failure\n\
         RestartSec=3s\n\
         LimitNOFILE=4096\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         ReadWritePaths={VAR_DIR}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    write_atomic(Path::new(CONTROL_SERVICE), unit.as_bytes(), 0o644)?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", "--now", "sbrelay-control.service"])?;
    run_systemctl(&["restart", "sbrelay-control.service"])?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    if !systemctl_active("sbrelay-control.service") {
        bail!("控制端服务启动失败，请排查: journalctl -u sbrelay-control -n 40");
    }
    Ok(())
}

pub async fn setup_control(
    listen_arg: Option<String>,
    public_url_arg: Option<String>,
    tls_mode_arg: TlsModeArg,
    plain_http: bool,
    regen_cert: bool,
) -> Result<()> {
    require_root()?;
    println!("======== sbrelay 控制端安装 / 更新 ========");

    let existing = ControlConfig::load(Path::new(CONTROL_CONFIG)).ok();
    let listen_override = listen_arg
        .or_else(|| std::env::var("SBRELAY_LISTEN").ok())
        .filter(|s| !s.trim().is_empty());
    let default_ip_port = listen_override
        .as_deref()
        .or_else(|| existing.as_ref().map(|c| c.listen.as_str()))
        .and_then(|l| normalize_listen(l).ok())
        .and_then(|l| l.rsplit_once(':').map(|(_, p)| p.to_string()))
        .unwrap_or_else(|| "8443".to_string());

    let detected_ip = detect_public_ip().await;
    let fallback_ip_host = detected_ip.as_deref().unwrap_or("127.0.0.1");
    let default_pub = existing
        .as_ref()
        .map(|c| c.public_url.clone())
        .unwrap_or_else(|| format!("https://{}:{default_ip_port}", format_url_host(fallback_ip_host)));

    let raw_pub = match public_url_arg
        .or_else(|| std::env::var("SBRELAY_PUBLIC_URL").ok())
        .filter(|s| !s.trim().is_empty())
    {
        Some(v) => v,
        None if is_tty() => {
            let line = prompt_line(&format!(
                "请输入控制端域名或公网地址（如 ctl.example.com，直接回车使用 {default_pub}）："
            ))?;
            if line.is_empty() {
                default_pub
            } else {
                line
            }
        }
        None => default_pub,
    };

    let (mut public_url, had_explicit_port) = parse_public_url_input(&raw_pub, &default_ip_port)?;
    let host = public_url_host(&public_url)?;
    let is_ip = is_ip_host(&host);

    let (tls_mode, listen, listen_tls, trust_proxy) = if is_ip {
        if tls_mode_arg == TlsModeArg::Webpki {
            bail!("使用公信 CA 模式（--tls-mode webpki）时必须输入域名，不能使用裸 IP");
        }
        let (l, _) = resolve_listen_with_tls(
            listen_override.as_deref(),
            existing.as_ref(),
            TlsMode::Pin,
            "0.0.0.0:8443",
            false,
        )?;
        (TlsMode::Pin, l, true, false)
    } else {
        match tls_mode_arg {
            TlsModeArg::Pin => {
                let (l, _) = resolve_listen_with_tls(
                    listen_override.as_deref(),
                    existing.as_ref(),
                    TlsMode::Pin,
                    "0.0.0.0:8443",
                    false,
                )?;
                if !had_explicit_port {
                    let lport = l.rsplit_once(':').map(|(_, p)| p).unwrap_or("8443");
                    public_url = ensure_url_port(&public_url, lport)?;
                }
                (TlsMode::Pin, l, true, false)
            }
            TlsModeArg::Webpki => {
                let (l, ltls) = resolve_listen_with_tls(
                    listen_override.as_deref(),
                    existing.as_ref(),
                    TlsMode::Webpki,
                    "127.0.0.1:8443",
                    plain_http,
                )?;
                (TlsMode::Webpki, l, ltls, true)
            }
            TlsModeArg::Auto => {
                println!("正在检测 {host} 的网络与反代环境...");
                let local_proxy = detect_local_proxy();
                let dns_local = dns_matches_local_ip(&host, detected_ip.as_deref()).await;
                let probe = probe_public_https(&public_url).await;

                if dns_local == Some(false) && !probe.is_cloudflare {
                    println!(
                        "提示：当前域名 {host} 解析 IP 与本机公网 IP 不一致（若尚未切换解析或刚改完 DNS 可忽略）。"
                    );
                }

                if probe.is_cloudflare {
                    println!("检测到 Cloudflare 代理，已自动启用公信 CA 模式（免 --pin）。");
                    let def_listen = if local_proxy.is_some() && !had_explicit_port {
                        "127.0.0.1:8443"
                    } else {
                        "0.0.0.0:8443"
                    };
                    let (l, ltls) = resolve_listen_with_tls(
                        listen_override.as_deref(),
                        existing.as_ref(),
                        TlsMode::Webpki,
                        def_listen,
                        plain_http,
                    )?;
                    (TlsMode::Webpki, l, ltls, true)
                } else if local_proxy.is_some() || probe.webpki_ok {
                    if let Some(ref p) = local_proxy {
                        println!(
                            "检测到本机反代/443占用（{p}），已自动切换为公信 CA 反代模式（免 --pin）。"
                        );
                    } else {
                        println!(
                            "检测到 {public_url} 已提供有效公信 HTTPS，已自动启用公信 CA 模式（免 --pin）。"
                        );
                    }
                    let (l, ltls) = resolve_listen_with_tls(
                        listen_override.as_deref(),
                        existing.as_ref(),
                        TlsMode::Webpki,
                        "127.0.0.1:8443",
                        plain_http,
                    )?;
                    (TlsMode::Webpki, l, ltls, true)
                } else if !had_explicit_port && is_tty() {
                    println!("未检测到本机反代（Nginx/Caddy）或 Cloudflare 代理，请选择部署模式：");
                    println!("  [1] 反代 + 公信 HTTPS（推荐，免 --pin、方便后续迁移）");
                    println!("  [2] sbrelay 自签 HTTPS 直连（8443 端口 + 指纹固定）");
                    let ans = prompt_line("请选择 [1/2]（默认 1）：")?;
                    if ans.trim() == "2" {
                        let (l, _) = resolve_listen_with_tls(
                            listen_override.as_deref(),
                            existing.as_ref(),
                            TlsMode::Pin,
                            "0.0.0.0:8443",
                            false,
                        )?;
                        let lport = l.rsplit_once(':').map(|(_, p)| p).unwrap_or("8443");
                        public_url = ensure_url_port(&public_url, lport)?;
                        (TlsMode::Pin, l, true, false)
                    } else {
                        let (l, ltls) = resolve_listen_with_tls(
                            listen_override.as_deref(),
                            existing.as_ref(),
                            TlsMode::Webpki,
                            "127.0.0.1:8443",
                            plain_http,
                        )?;
                        (TlsMode::Webpki, l, ltls, true)
                    }
                } else if had_explicit_port {
                    let (l, _) = resolve_listen_with_tls(
                        listen_override.as_deref(),
                        existing.as_ref(),
                        TlsMode::Pin,
                        "0.0.0.0:8443",
                        false,
                    )?;
                    (TlsMode::Pin, l, true, false)
                } else {
                    let (l, ltls) = resolve_listen_with_tls(
                        listen_override.as_deref(),
                        existing.as_ref(),
                        TlsMode::Webpki,
                        "127.0.0.1:8443",
                        plain_http,
                    )?;
                    (TlsMode::Webpki, l, ltls, true)
                }
            }
        }
    };

    let tg_token = match std::env::var("SBRELAY_TG_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => match existing.as_ref().map(|c| c.tg_token.clone()) {
            Some(old) if !old.is_empty() => {
                println!("检测到已有 Bot token，已保留（如需更换请执行 sbrelay set-token）。");
                old
            }
            _ => prompt_secret("请输入 Telegram Bot token（不回显）：")?,
        },
    };
    validate_bot_token(&tg_token)?;

    let cert_path = PathBuf::from(TLS_CERT);
    let key_path = PathBuf::from(TLS_KEY);
    let pin = if listen_tls {
        let p = if regen_cert || !cert_path.exists() || !key_path.exists() {
            println!("正在生成自签 TLS 证书（主机：{host}）...");
            generate_self_signed(&cert_path, &key_path, &host)?
        } else {
            println!("使用已有 TLS 证书，未覆盖。");
            cert_pin_from_file(&cert_path)?
        };
        Some(p)
    } else {
        None
    };

    let owner_hint = std::env::var("SBRELAY_OWNER_ID")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| existing.as_ref().and_then(|c| c.owner_hint));
    let repo = std::env::var("SBRELAY_REPO")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| existing.as_ref().map(|c| c.repo.clone()))
        .unwrap_or_else(|| DEFAULT_REPO.to_string());

    let mut cfg = ControlConfig {
        tg_token,
        listen: listen.clone(),
        public_url: public_url.clone(),
        tls_mode,
        listen_tls,
        trust_proxy,
        data_dir: PathBuf::from(VAR_DIR),
        cert_file: cert_path,
        key_file: key_path,
        owner_hint,
        repo,
    };
    cfg.validate()?;
    fs::create_dir_all(VAR_DIR)?;
    fs::set_permissions(VAR_DIR, fs::Permissions::from_mode(0o700))?;
    cfg.save(Path::new(CONTROL_CONFIG))?;

    ensure_pm_symlink();
    write_and_start_control_service().await?;

    println!();
    println!("控制端已就绪（active）");
    println!("版本：{}", env!("CARGO_PKG_VERSION"));
    println!("模式：{}    监听：{listen}    对外地址：{public_url}", tls_mode.cn());
    if let (TlsMode::Pin, Some(p)) = (tls_mode, pin.as_deref()) {
        println!("证书指纹（--pin）：{p}");
    }
    if tls_mode == TlsMode::Webpki {
        let post_probe = probe_public_https(&public_url).await;
        if post_probe.healthz_ok {
            println!("公网反代连通检查通过（{public_url}/healthz -> ok）。");
        } else {
            print_reverse_proxy_snippets(&public_url, &listen, listen_tls);
        }
    }
    println!();
    println!("下一步：");
    println!("  1. 在 Telegram 向 Bot 发送 /start 绑定管理员。");
    println!("  2. 在面板点「添加线路机 / 添加落地机」，在目标机执行给出的一行命令。");
    println!("  3. 可在 Bot 发 /backup 导出加密备份，方便以后零重装迁移到新控制机。");
    println!("  4. 随时运行 sbrelay menu（或 pm）打开管理菜单。");
    Ok(())
}

pub async fn setup_agent(
    url_arg: Option<String>,
    pin_arg: Option<String>,
    clear_pin: bool,
    force_register: bool,
) -> Result<()> {
    require_root()?;
    println!("======== sbrelay Agent 安装 / 更新 ========");

    let existing = AgentConfig::load(Path::new(AGENT_CONFIG)).ok();
    let raw_url = url_arg
        .or_else(|| std::env::var("SBRELAY_URL").ok())
        .or_else(|| existing.as_ref().map(|c| c.url.clone()))
        .ok_or_else(|| anyhow!("缺少 --url（控制端地址）"))?;
    let (url, _) = parse_public_url_input(&raw_url, "8443")?;

    let tls_pin = if clear_pin {
        None
    } else if let Some(p) = pin_arg
        .or_else(|| std::env::var("SBRELAY_TLS_PIN").ok())
        .filter(|s| !s.trim().is_empty())
    {
        Some(validate_pin(&p)?)
    } else {
        existing.as_ref().and_then(|c| c.tls_pin.clone())
    };

    if tls_pin.is_none() && is_ip_host(&public_url_host(&url)?) {
        bail!("控制端地址为 IP 时必须提供证书指纹（--pin）");
    }

    // 1. 先确保 sing-box 可用，避免环境失败白白消耗一次性令牌
    ensure_singbox_installed().await?;

    // 2. 已有注册凭据直接原地更新；否则用一次性令牌注册并拿到角色
    let already_registered = !force_register
        && existing
            .as_ref()
            .is_some_and(|c| c.machine_id.is_some() && c.secret.is_some());

    let (machine_id, secret, role) = if already_registered {
        let ex = existing.as_ref().unwrap();
        println!("检测到已注册凭据，执行原地更新，不重复注册（角色：{}）。", ex.role);
        (
            ex.machine_id.clone().unwrap(),
            ex.secret.clone().unwrap(),
            ex.role,
        )
    } else {
        let token = match std::env::var("SBRELAY_TOKEN") {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => prompt_secret("请输入面板提供的一次性安装令牌（不回显）：")?,
        };
        let reg = register_with_token(&url, tls_pin.as_deref(), &token).await?;
        println!("注册成功：{}（角色：{}）", reg.name, reg.role.cn());
        (reg.machine_id, reg.secret, reg.role)
    };

    let public_ip = std::env::var("SBRELAY_PUBLIC_IP")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| existing.as_ref().and_then(|c| c.public_ip.clone()))
        .or(detect_public_ip().await);

    // 3. 立刻落盘 agent.toml，防止后续异常导致令牌浪费
    let mut cfg = AgentConfig {
        url,
        tls_pin,
        role,
        machine_id: Some(machine_id),
        secret: Some(secret),
        public_ip: public_ip.clone(),
        state_dir: PathBuf::from(VAR_DIR),
        singbox_bin: PathBuf::from(SINGBOX_BIN),
        singbox_config: PathBuf::from(SINGBOX_CONFIG),
        service: SINGBOX_SERVICE_NAME.into(),
    };
    cfg.validate()?;
    fs::create_dir_all(VAR_DIR)?;
    fs::set_permissions(VAR_DIR, fs::Permissions::from_mode(0o700))?;
    cfg.save(Path::new(AGENT_CONFIG))?;

    // 4. 初始化 sbrelay 专用 sing-box 配置与独立服务（不碰宿主机已有 sing-box.service）
    let sb = SingboxManager::system(
        cfg.singbox_config.clone(),
        cfg.singbox_bin.clone(),
        cfg.state_dir.clone(),
        cfg.service.clone(),
        cfg.role,
        cfg.public_ip.clone(),
    );
    let port_override = std::env::var("SBRELAY_SS_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());
    let pass_override = std::env::var("SBRELAY_SS_PASSWORD").ok();
    let (node, created) = sb.init_node(port_override, pass_override)?;
    if created {
        println!(
            "已自动生成 SS2022 入站（端口 {}，{}，配置位于 {SINGBOX_CONFIG}）。",
            node.port, node.method
        );
    } else {
        println!("检测到已有 sbrelay SS2022 入站（端口 {}），已原样保留。", node.port);
    }

    ensure_singbox_service(created)?;
    ensure_pm_symlink();

    // 5. 写入带路径沙箱的 sbrelay-agent.service
    let unit = format!(
        "[Unit]\n\
         Description=sbrelay agent (connects out to control plane)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={SBRELAY_BIN} agent\n\
         WorkingDirectory={VAR_DIR}\n\
         Restart=on-failure\n\
         RestartSec=3s\n\
         ProtectSystem=strict\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         ReadWritePaths={ETC_DIR} {VAR_DIR}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    write_atomic(Path::new(AGENT_SERVICE), unit.as_bytes(), 0o644)?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", "--now", "sbrelay-agent.service"])?;
    run_systemctl(&["restart", "sbrelay-agent.service"])?;
    tokio::time::sleep(Duration::from_secs(1)).await;

    if !systemctl_active("sbrelay-agent.service") {
        bail!("agent 启动失败，请排查: journalctl -u sbrelay-agent -n 40");
    }

    println!();
    println!("Agent 已就绪（角色：{}，active）。", role.cn());
    println!("回到 Telegram 面板即可查看节点信息与切换落地。");
    Ok(())
}

async fn ensure_singbox_installed() -> Result<()> {
    if Path::new(SINGBOX_BIN).exists() {
        return Ok(());
    }
    println!("未检测到 sing-box，正在从 GitHub Release 下载官方稳定版（校验 SHA-256）...");
    let sb_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("不支持的 CPU 架构: {other}，请手动安装 {SINGBOX_BIN}"),
    };
    let cli = build_public_client(Duration::from_secs(180))?;

    let ver = match std::env::var("SBRELAY_SINGBOX_VERSION") {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v').to_string(),
        _ => {
            let meta: Value = cli
                .get("https://api.github.com/repos/SagerNet/sing-box/releases/latest")
                .send()
                .await
                .context("获取 sing-box 最新版本失败")?
                .error_for_status()?
                .json()
                .await?;
            meta.get("tag_name")
                .and_then(Value::as_str)
                .map(|s| s.trim_start_matches('v').to_string())
                .ok_or_else(|| anyhow!("无法解析 sing-box 最新版本号"))?
        }
    };

    let asset_name = format!("sing-box-{ver}-linux-{sb_arch}.tar.gz");
    let want_sha = match std::env::var("SBRELAY_SINGBOX_SHA256") {
        Ok(s) if !s.trim().is_empty() => validate_pin(&s)?,
        _ => {
            let meta: Value = cli
                .get(format!(
                    "https://api.github.com/repos/SagerNet/sing-box/releases/tags/v{ver}"
                ))
                .send()
                .await
                .context("获取 sing-box 发布摘要失败")?
                .error_for_status()?
                .json()
                .await?;
            let found = meta
                .get("assets")
                .and_then(Value::as_array)
                .and_then(|arr| {
                    arr.iter().find(|a| {
                        a.get("name").and_then(Value::as_str) == Some(asset_name.as_str())
                    })
                })
                .and_then(|a| a.get("digest"))
                .and_then(Value::as_str)
                .and_then(|d| d.strip_prefix("sha256:"));
            let Some(sha) = found else {
                bail!("无法取得 sing-box {ver} 的 SHA-256 摘要，请设置 SBRELAY_SINGBOX_SHA256 后重试");
            };
            validate_pin(sha)?
        }
    };

    let mirror = std::env::var("SBRELAY_MIRROR").unwrap_or_default();
    let dl_url = format!(
        "{}https://github.com/SagerNet/sing-box/releases/download/v{ver}/{asset_name}",
        mirror.trim()
    );
    let tgz = cli
        .get(&dl_url)
        .send()
        .await
        .with_context(|| format!("下载 sing-box 失败: {dl_url}"))?
        .error_for_status()?
        .bytes()
        .await?;

    let got_sha = hex::encode(Sha256::digest(&tgz));
    if got_sha != want_sha {
        bail!("sing-box SHA-256 校验失败（期望 {want_sha}，实际 {got_sha}）");
    }

    let mut archive = Archive::new(GzDecoder::new(tgz.as_ref()));
    let mut bin_bytes = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.file_name().and_then(|s| s.to_str()) == Some("sing-box") {
            entry.read_to_end(&mut bin_bytes)?;
            break;
        }
    }
    if bin_bytes.is_empty() {
        bail!("压缩包中未找到 sing-box 可执行文件");
    }
    write_atomic(Path::new(SINGBOX_BIN), &bin_bytes, 0o755)?;
    println!("已安装 sing-box v{ver} 到 {SINGBOX_BIN}");
    Ok(())
}

fn ensure_singbox_service(force_restart: bool) -> Result<()> {
    let unit_path = Path::new(SINGBOX_SERVICE);
    let svc_unit = format!("{SINGBOX_SERVICE_NAME}.service");
    let unit = format!(
        "[Unit]\n\
         Description=sbrelay dedicated sing-box service\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={SINGBOX_BIN} run -c {SINGBOX_CONFIG}\n\
         Restart=on-failure\n\
         RestartSec=3s\n\
         LimitNOFILE=65535\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    );
    let need_write = fs::read_to_string(unit_path).ok().as_deref() != Some(unit.as_str());
    if need_write {
        write_atomic(unit_path, unit.as_bytes(), 0o644)?;
        run_systemctl(&["daemon-reload"])?;
        run_systemctl(&["enable", &svc_unit])?;
    }
    if force_restart || need_write || !systemctl_active(&svc_unit) {
        run_systemctl(&["restart", &svc_unit])?;
    }
    Ok(())
}

pub fn set_token() -> Result<()> {
    require_root()?;
    let path = Path::new(CONTROL_CONFIG);
    let mut cfg = ControlConfig::load(path)?;
    let new_tok = match std::env::var("SBRELAY_TG_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => prompt_secret("请输入新的 Telegram Bot token（不回显）：")?,
    };
    validate_bot_token(&new_tok)?;
    cfg.tg_token = new_tok;
    cfg.save(path)?;
    run_systemctl(&["restart", "sbrelay-control.service"])?;
    println!("Bot token 已更新，控制端已重启。");
    Ok(())
}

pub fn restart_services() -> Result<()> {
    require_root()?;
    let mut any = false;
    if Path::new(CONTROL_SERVICE).exists() {
        run_systemctl(&["restart", "sbrelay-control.service"])?;
        println!("已重启 sbrelay-control");
        any = true;
    }
    if Path::new(AGENT_SERVICE).exists() {
        run_systemctl(&["restart", "sbrelay-agent.service"])?;
        println!("已重启 sbrelay-agent");
        any = true;
    }
    if Path::new(SINGBOX_SERVICE).exists() {
        let svc_unit = format!("{SINGBOX_SERVICE_NAME}.service");
        run_systemctl(&["restart", &svc_unit])?;
        println!("已重启 {SINGBOX_SERVICE_NAME}");
        any = true;
    }
    if !any {
        println!("本机未安装 sbrelay 服务。");
    }
    Ok(())
}

pub fn show_status() {
    println!("======== sbrelay 状态 (v{}) ========", env!("CARGO_PKG_VERSION"));
    if Path::new(CONTROL_SERVICE).exists() {
        let st = svc_state_str("sbrelay-control.service");
        println!("控制端：{st}");
        if let Ok(cfg) = ControlConfig::load(Path::new(CONTROL_CONFIG)) {
            println!(
                "  模式：{}    监听：{}    对外：{}",
                cfg.tls_mode.cn(),
                cfg.listen,
                cfg.public_url
            );
            if let Some(pin) = cfg
                .listen_tls
                .then(|| cert_pin_from_file(&cfg.cert_file).ok())
                .flatten()
            {
                println!("  指纹（--pin）：{pin}");
            }
        }
    } else {
        println!("控制端：未安装");
    }

    if Path::new(AGENT_SERVICE).exists() {
        let st = svc_state_str("sbrelay-agent.service");
        if let Ok(cfg) = AgentConfig::load(Path::new(AGENT_CONFIG)) {
            let verify = if cfg.tls_pin.is_some() {
                "指纹固定"
            } else {
                "公信 CA"
            };
            println!(
                "Agent ：{st}（角色：{}，校验：{verify}，控制端：{}）",
                cfg.role.cn(),
                cfg.url
            );
        } else {
            println!("Agent ：{st}");
        }
    } else {
        println!("Agent ：未安装");
    }

    if Path::new(SINGBOX_SERVICE).exists() {
        let svc_unit = format!("{SINGBOX_SERVICE_NAME}.service");
        println!("sing-box ({SINGBOX_SERVICE_NAME})：{}", svc_state_str(&svc_unit));
    }
}

pub fn backup_control(output: Option<PathBuf>, auto_pass: bool) -> Result<()> {
    require_root()?;
    let passphrase = match std::env::var("SBRELAY_BACKUP_PASS") {
        Ok(p) if !p.is_empty() => p,
        _ if auto_pass => {
            let p = gen_backup_passphrase();
            println!("已生成随机备份口令（请妥善保存）：{p}");
            p
        }
        _ => {
            let p1 = prompt_secret("请设置备份加密口令（不回显）：")?;
            let p2 = prompt_secret("请再次输入确认口令（不回显）：")?;
            if p1 != p2 {
                bail!("两次输入的口令不一致");
            }
            p1
        }
    };

    let bytes = create_backup(Path::new(CONTROL_CONFIG), None, &passphrase)?;
    let out_path = output.unwrap_or_else(|| {
        PathBuf::from(format!(
            "sbrelay-backup-{}.sbr",
            Utc::now().format("%Y%m%d-%H%M%S")
        ))
    });
    write_atomic(&out_path, &bytes, 0o600)?;
    println!("控制端加密备份已生成：{}", out_path.display());
    println!("迁移到新服务器后执行：sbrelay restore {}", out_path.display());
    Ok(())
}

pub async fn restore_control(
    file: &Path,
    public_url_override: Option<String>,
    listen_override: Option<String>,
    tls_mode_override: Option<TlsModeArg>,
) -> Result<()> {
    require_root()?;
    if !file.exists() {
        bail!("找不到备份文件: {}", file.display());
    }
    let data =
        fs::read(file).with_context(|| format!("读取备份文件失败: {}", file.display()))?;
    let passphrase = match std::env::var("SBRELAY_BACKUP_PASS") {
        Ok(p) if !p.is_empty() => p,
        _ => prompt_secret("请输入备份解密口令（不回显）：")?,
    };

    let payload = decrypt_backup(&data, &passphrase)?;
    let cfg_str =
        std::str::from_utf8(&payload.control_toml).context("备份中 control.toml 不是有效 UTF-8")?;
    let mut cfg = ControlConfig::from_toml_str(cfg_str)?;

    if let Some(ref raw_url) = public_url_override {
        let (u, _) = parse_public_url_input(raw_url, "8443")?;
        cfg.public_url = u;
    }
    if let Some(ref raw_listen) = listen_override {
        cfg.listen = normalize_listen(raw_listen)?;
    }
    if let Some(mode_arg) = tls_mode_override {
        match mode_arg {
            TlsModeArg::Pin => {
                cfg.tls_mode = TlsMode::Pin;
                cfg.listen_tls = true;
                cfg.trust_proxy = false;
            }
            TlsModeArg::Webpki => {
                cfg.tls_mode = TlsMode::Webpki;
                cfg.trust_proxy = true;
                if listen_override.is_none() && !cfg.listen.parse::<SocketAddr>()?.ip().is_loopback()
                {
                    cfg.listen = "127.0.0.1:8443".to_string();
                }
                cfg.listen_tls = !cfg.listen.parse::<SocketAddr>()?.ip().is_loopback();
            }
            TlsModeArg::Auto => {}
        }
    }
    cfg.validate()?;

    if systemctl_active("sbrelay-control.service") {
        let _ = run_systemctl(&["stop", "sbrelay-control.service"]);
    }

    fs::create_dir_all(VAR_DIR)?;
    fs::set_permissions(VAR_DIR, fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all(&cfg.data_dir)?;
    fs::set_permissions(&cfg.data_dir, fs::Permissions::from_mode(0o700))?;

    cfg.save(Path::new(CONTROL_CONFIG))?;
    if let Some(ref st) = payload.state_json {
        write_atomic(&cfg.data_dir.join("state.json"), st, 0o600)?;
    }
    if let Some(ref crt) = payload.tls_crt {
        write_atomic(&cfg.cert_file, crt, 0o644)?;
    }
    if let Some(ref key) = payload.tls_key {
        write_atomic(&cfg.key_file, key, 0o600)?;
    }
    if cfg.listen_tls && (!cfg.cert_file.exists() || !cfg.key_file.exists()) {
        let host = public_url_host(&cfg.public_url)?;
        generate_self_signed(&cfg.cert_file, &cfg.key_file, &host)?;
    }

    ensure_pm_symlink();
    write_and_start_control_service().await?;

    let restored_count = payload.manifest.as_ref().map(|m| m.machine_count).unwrap_or(0);
    println!();
    println!("控制端已从备份恢复并启动（active）");
    println!(
        "模式：{}    监听：{}    对外地址：{}",
        cfg.tls_mode.cn(),
        cfg.listen,
        cfg.public_url
    );
    println!("已恢复机器记录：{restored_count} 台");
    if cfg.tls_mode == TlsMode::Webpki {
        let post_probe = probe_public_https(&cfg.public_url).await;
        if post_probe.healthz_ok {
            println!("公网反代连通检查通过（{}/healthz -> ok）。", cfg.public_url);
        } else {
            print_reverse_proxy_snippets(&cfg.public_url, &cfg.listen, cfg.listen_tls);
        }
    }
    println!();
    println!("将域名解析或反代切到本机后，所有已安装的 Agent 会自动重连并上报节点状态，无需重新对接。");
    Ok(())
}

pub fn rebind_agent(url: &str, pin: Option<String>, webpki: bool) -> Result<()> {
    require_root()?;
    let path = Path::new(AGENT_CONFIG);
    let mut cfg = AgentConfig::load(path)?;
    let (new_url, _) = parse_public_url_input(url, "8443")?;
    cfg.url = new_url;
    if webpki {
        cfg.tls_pin = None;
    } else if let Some(p) = pin.filter(|s| !s.trim().is_empty()) {
        cfg.tls_pin = Some(validate_pin(&p)?);
    }
    cfg.validate()?;
    cfg.save(path)?;
    if Path::new(AGENT_SERVICE).exists() {
        run_systemctl(&["restart", "sbrelay-agent.service"])?;
    }
    let verify = if cfg.tls_pin.is_some() {
        "指纹固定"
    } else {
        "公信 CA"
    };
    println!(
        "Agent 控制端地址已更新为 {}（校验：{verify}），现有节点与凭据保持不变。",
        cfg.url
    );
    Ok(())
}

pub fn uninstall(purge: bool) -> Result<()> {
    require_root()?;
    let mut removed_any_unit = false;
    for (unit_path, svc) in [
        (CONTROL_SERVICE, "sbrelay-control.service"),
        (AGENT_SERVICE, "sbrelay-agent.service"),
    ] {
        if Path::new(unit_path).exists() {
            let _ = run_systemctl(&["disable", "--now", svc]);
            let _ = fs::remove_file(unit_path);
            removed_any_unit = true;
        }
    }
    if removed_any_unit {
        let _ = run_systemctl(&["daemon-reload"]);
    }

    if purge {
        println!(
            "即将彻底删除 {ETC_DIR}（含 Bot token、证书与 sbrelay 专用 sing-box 配置）、{VAR_DIR}（状态与备份）以及 {SINGBOX_SERVICE_NAME} 服务。"
        );
        let ans = prompt_line("确认彻底清除？输入 yes 继续：")?;
        if ans.trim() == "yes" {
            if Path::new(SINGBOX_SERVICE).exists() {
                let svc_unit = format!("{SINGBOX_SERVICE_NAME}.service");
                let _ = run_systemctl(&["disable", "--now", &svc_unit]);
                let _ = fs::remove_file(SINGBOX_SERVICE);
                let _ = run_systemctl(&["daemon-reload"]);
            }
            let _ = fs::remove_dir_all(ETC_DIR);
            let _ = fs::remove_dir_all(VAR_DIR);
            let _ = fs::remove_file(PM_LINK);
            let _ = fs::remove_file(SBRELAY_BIN);
            println!("已彻底清除 sbrelay 服务与数据（未改动宿主机原有的 sing-box 服务或配置）。");
        } else {
            println!("已取消删除数据；控制端/Agent 服务已停止卸载，数据与 {SINGBOX_SERVICE_NAME} 已保留。");
        }
    } else {
        println!(
            "控制端/Agent 服务已卸载，配置与数据（{ETC_DIR}、{VAR_DIR}）及 {SINGBOX_SERVICE_NAME} 已保留，重新安装可免令牌恢复。"
        );
        println!("说明：未改动宿主机原有的 sing-box 配置与服务。");
    }
    Ok(())
}

pub async fn interactive_menu() -> Result<()> {
    require_root()?;
    loop {
        println!();
        show_status();
        println!("----------------------------------------");
        println!("  1. 安装 / 更新控制端（支持域名与自动识别反代）");
        println!("  2. 安装 / 更新 Agent（线路机 / 落地机）");
        println!("  3. 修改 Bot token");
        println!("  4. 重启服务");
        println!("  5. 卸载（保留数据）");
        println!("  6. 彻底清除（删除数据）");
        println!("  7. 备份控制端（生成加密 .sbr 文件）");
        println!("  8. 从备份恢复控制端");
        println!("  9. 灾备重绑 Agent 控制端地址");
        println!("  0. 退出");
        println!("----------------------------------------");
        let choice = prompt_line("请选择数字：")?;
        let res = match choice.trim() {
            "1" => setup_control(None, None, TlsModeArg::Auto, false, false).await,
            "2" => {
                let url = prompt_line("控制端地址（如 https://ctl.example.com，留空复用已有）：")?;
                let pin = prompt_line(
                    "证书指纹（64 位 hex，反代/公信 CA 模式直接留空，已有配置留空复用）：",
                )?;
                setup_agent(
                    (!url.trim().is_empty()).then_some(url),
                    (!pin.trim().is_empty()).then_some(pin),
                    false,
                    false,
                )
                .await
            }
            "3" => set_token(),
            "4" => restart_services(),
            "5" => uninstall(false),
            "6" => uninstall(true),
            "7" => backup_control(None, false),
            "8" => {
                let file = prompt_line("请输入备份文件路径（.sbr）：")?;
                if file.trim().is_empty() {
                    Ok(())
                } else {
                    restore_control(Path::new(file.trim()), None, None, None).await
                }
            }
            "9" => {
                let url = prompt_line("请输入新控制端地址（域名或 https://IP:端口）：")?;
                let pin = prompt_line("新证书指纹（公信 CA / 反代模式留空）：")?;
                if url.trim().is_empty() {
                    Ok(())
                } else {
                    let webpki = pin.trim().is_empty();
                    rebind_agent(
                        url.trim(),
                        (!webpki).then_some(pin.trim().to_string()),
                        webpki,
                    )
                }
            }
            "0" | "" => break,
            _ => {
                println!("无效选项。");
                Ok(())
            }
        };
        if let Err(e) = res {
            eprintln!("操作失败：{e}");
        }
    }
    Ok(())
}

async fn detect_public_ip() -> Option<String> {
    if let Ok(cli) = build_public_client(Duration::from_secs(6)) {
        for url in [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://ipv4.icanhazip.com",
        ] {
            if let Ok(resp) = cli.get(url).send().await {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        let ip = text.trim();
                        if ip.parse::<IpAddr>().is_ok() {
                            return Some(ip.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn is_tty() -> bool {
    unsafe { libc::isatty(0) != 0 }
}

fn ensure_pm_symlink() {
    if Path::new(SBRELAY_BIN).exists() && !Path::new(PM_LINK).exists() {
        let _ = symlink(SBRELAY_BIN, PM_LINK);
    }
}

fn normalize_listen(raw: &str) -> Result<String> {
    let s = raw.trim();
    let normalized = if s.starts_with(':') {
        format!("0.0.0.0{s}")
    } else if s.chars().all(|c| c.is_ascii_digit()) {
        format!("0.0.0.0:{s}")
    } else {
        s.to_string()
    };
    let _: SocketAddr = normalized
        .parse()
        .with_context(|| format!("监听地址不合法: {raw}（应为 0.0.0.0:8443）"))?;
    Ok(normalized)
}

fn format_url_host(host: &str) -> String {
    if host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn validate_bot_token(tok: &str) -> Result<()> {
    if tok.is_empty() || tok.len() > 256 || tok.chars().any(char::is_whitespace) || !tok.contains(':') {
        bail!("Telegram Bot token 格式不合法");
    }
    Ok(())
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_secret(prompt: &str) -> Result<String> {
    let val = rpassword::prompt_password(prompt).context("读取不回显输入失败（非交互终端请使用环境变量）")?;
    let trimmed = val.trim().to_string();
    if trimmed.is_empty() {
        bail!("输入为空，已取消");
    }
    Ok(trimmed)
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("/usr/bin/systemctl")
        .args(args)
        .status()
        .with_context(|| format!("执行 systemctl {} 失败", args.join(" ")))?;
    if !status.success() {
        bail!("systemctl {} 返回非零退出码", args.join(" "));
    }
    Ok(())
}

fn systemctl_active(svc: &str) -> bool {
    Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", svc])
        .status()
        .is_ok_and(|s| s.success())
}

fn svc_state_str(svc: &str) -> String {
    Command::new("/usr/bin/systemctl")
        .args(["is-active", svc])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_normalization() {
        assert_eq!(normalize_listen(":8443").unwrap(), "0.0.0.0:8443");
        assert_eq!(normalize_listen("8443").unwrap(), "0.0.0.0:8443");
        assert_eq!(normalize_listen("127.0.0.1:9443").unwrap(), "127.0.0.1:9443");
        assert!(normalize_listen("not-an-addr").is_err());
    }
}
