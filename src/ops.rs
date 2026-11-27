use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::sync::watch;
use tracing::info;

use crate::agent::register_with_token;
use crate::bot::Bot;
use crate::config::{
    validate_pin, validate_public_url, write_atomic, AgentConfig, ControlConfig, AGENT_CONFIG,
    AGENT_SERVICE, CONTROL_CONFIG, CONTROL_SERVICE, DEFAULT_REPO, ETC_DIR, PM_LINK, SBRELAY_BIN,
    SINGBOX_BIN, SINGBOX_CONFIG, SINGBOX_SERVICE, TLS_CERT, TLS_KEY, VAR_DIR,
};
use crate::control::{router, ControlState};
use crate::singbox::SingboxManager;
use crate::store::Store;
use crate::tls::{build_public_client, build_server_tls, cert_pin_from_file, generate_self_signed};

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
    let pin = cert_pin_from_file(&cfg.cert_file)?;
    let tls_cfg = build_server_tls(&cfg.cert_file, &cfg.key_file)?;
    let addr: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("监听地址不合法: {}", cfg.listen))?;

    let bot = Bot::new(cfg.clone(), store.clone(), pin.clone())?;
    let bot_hook = bot.clone();
    let ready_hook = std::sync::Arc::new(move |mid: String| {
        let b = bot_hook.clone();
        tokio::spawn(async move { b.notify_node_ready(&mid).await });
    });

    let state = ControlState::new(store, Some(ready_hook));
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

    info!(
        "控制端启动成功 listen={} public_url={} tls_pin={}",
        addr, cfg.public_url, pin
    );
    axum_server::bind_rustls(addr, tls_cfg)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("HTTPS 控制端服务异常退出")?;

    let _ = bot_task.await;
    Ok(())
}

pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("请以 root 运行（例如先 sudo -i 或加 sudo）");
    }
    Ok(())
}

pub async fn setup_control(
    listen_arg: Option<String>,
    public_url_arg: Option<String>,
    regen_cert: bool,
) -> Result<()> {
    require_root()?;
    println!("======== sbrelay 控制端安装 / 更新 ========");

    let existing = ControlConfig::load(Path::new(CONTROL_CONFIG)).ok();

    let listen = normalize_listen(
        &listen_arg
            .or_else(|| std::env::var("SBRELAY_LISTEN").ok())
            .or_else(|| existing.as_ref().map(|c| c.listen.clone()))
            .unwrap_or_else(|| "0.0.0.0:8443".to_string()),
    )?;
    let port = listen
        .rsplit_once(':')
        .map(|(_, p)| p)
        .unwrap_or("8443");

    let detected_ip = detect_public_ip().await;
    let host_for_cert = detected_ip
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let default_pub = format!("https://{}:{port}", format_url_host(&host_for_cert));

    let raw_pub = public_url_arg
        .or_else(|| std::env::var("SBRELAY_PUBLIC_URL").ok())
        .or_else(|| existing.as_ref().map(|c| c.public_url.clone()))
        .unwrap_or(default_pub);
    let public_url = validate_public_url(&raw_pub)?;

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
    let pin = if regen_cert || !cert_path.exists() || !key_path.exists() {
        println!("正在生成自签 TLS 证书（主机：{host_for_cert}）...");
        generate_self_signed(&cert_path, &key_path, &host_for_cert)?
    } else {
        println!("使用已有 TLS 证书，未覆盖。");
        cert_pin_from_file(&cert_path)?
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

    let cfg = ControlConfig {
        tg_token,
        listen: listen.clone(),
        public_url: public_url.clone(),
        data_dir: PathBuf::from(VAR_DIR),
        cert_file: cert_path,
        key_file: key_path,
        owner_hint,
        repo,
    };
    fs::create_dir_all(VAR_DIR)?;
    fs::set_permissions(VAR_DIR, fs::Permissions::from_mode(0o700))?;
    cfg.save(Path::new(CONTROL_CONFIG))?;

    ensure_pm_symlink();

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

    println!();
    println!("控制端已就绪（active）");
    println!("版本：{}", env!("CARGO_PKG_VERSION"));
    println!("监听：{listen}    对外地址：{public_url}");
    println!("证书指纹（--pin）：{pin}");
    println!();
    println!("下一步：");
    println!("  1. 在 Telegram 向 Bot 发送 /start 绑定管理员。");
    println!("  2. 在面板点「添加线路机 / 添加落地机」，在目标机执行给出的一行命令。");
    println!("  3. 随时运行 sbrelay menu（或 pm）打开管理菜单。");
    Ok(())
}

pub async fn setup_agent(
    url_arg: Option<String>,
    pin_arg: Option<String>,
    force_register: bool,
) -> Result<()> {
    require_root()?;
    println!("======== sbrelay Agent 安装 / 更新 ========");

    let existing = AgentConfig::load(Path::new(AGENT_CONFIG)).ok();
    let url = validate_public_url(
        &url_arg
            .or_else(|| std::env::var("SBRELAY_URL").ok())
            .or_else(|| existing.as_ref().map(|c| c.url.clone()))
            .ok_or_else(|| anyhow!("缺少 --url（控制端地址）"))?,
    )?;
    let tls_pin = validate_pin(
        &pin_arg
            .or_else(|| std::env::var("SBRELAY_TLS_PIN").ok())
            .or_else(|| existing.as_ref().map(|c| c.tls_pin.clone()))
            .ok_or_else(|| anyhow!("缺少 --pin（控制端证书指纹）"))?,
    )?;

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
        let reg = register_with_token(&url, &tls_pin, &token).await?;
        println!("注册成功：{}（角色：{}）", reg.name, reg.role.cn());
        (reg.machine_id, reg.secret, reg.role)
    };

    let public_ip = std::env::var("SBRELAY_PUBLIC_IP")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| existing.as_ref().and_then(|c| c.public_ip.clone()))
        .or(detect_public_ip().await);

    // 3. 立刻落盘 agent.toml，防止后续异常导致令牌浪费
    let cfg = AgentConfig {
        url,
        tls_pin,
        role,
        machine_id: Some(machine_id),
        secret: Some(secret),
        public_ip: public_ip.clone(),
        state_dir: PathBuf::from(VAR_DIR),
        singbox_bin: PathBuf::from(SINGBOX_BIN),
        singbox_config: PathBuf::from(SINGBOX_CONFIG),
        service: "sing-box".into(),
    };
    fs::create_dir_all(VAR_DIR)?;
    fs::set_permissions(VAR_DIR, fs::Permissions::from_mode(0o700))?;
    cfg.save(Path::new(AGENT_CONFIG))?;

    // 4. 初始化 sing-box 单文件配置与服务
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
            "已自动生成 SS2022 入站（端口 {}，{}）。",
            node.port, node.method
        );
    } else {
        println!("检测到已有 SS2022 入站（端口 {}），已原样保留。", node.port);
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
         ReadWritePaths={ETC_DIR} {VAR_DIR} /usr/local/etc/sing-box\n\
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
    let mut need_reload = false;
    if !unit_path.exists() {
        let unit = format!(
            "[Unit]\n\
             Description=sing-box service\n\
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
        write_atomic(unit_path, unit.as_bytes(), 0o644)?;
        need_reload = true;
    }
    if need_reload {
        run_systemctl(&["daemon-reload"])?;
        run_systemctl(&["enable", "sing-box.service"])?;
    }
    if force_restart || !systemctl_active("sing-box.service") {
        run_systemctl(&["restart", "sing-box.service"])?;
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
            println!("  监听：{}    对外：{}", cfg.listen, cfg.public_url);
            if let Ok(pin) = cert_pin_from_file(&cfg.cert_file) {
                println!("  指纹（--pin）：{pin}");
            }
        }
    } else {
        println!("控制端：未安装");
    }

    if Path::new(AGENT_SERVICE).exists() {
        let st = svc_state_str("sbrelay-agent.service");
        if let Ok(cfg) = AgentConfig::load(Path::new(AGENT_CONFIG)) {
            println!("Agent ：{st}（角色：{}，控制端：{}）", cfg.role.cn(), cfg.url);
        } else {
            println!("Agent ：{st}");
        }
    } else {
        println!("Agent ：未安装");
    }

    if Path::new(SINGBOX_SERVICE).exists() {
        println!("sing-box：{}", svc_state_str("sing-box.service"));
    }
}

pub fn uninstall(purge: bool) -> Result<()> {
    require_root()?;
    for svc in ["sbrelay-control.service", "sbrelay-agent.service"] {
        let _ = run_systemctl(&["disable", "--now", svc]);
    }
    let _ = fs::remove_file(CONTROL_SERVICE);
    let _ = fs::remove_file(AGENT_SERVICE);
    let _ = run_systemctl(&["daemon-reload"]);

    if purge {
        println!("即将彻底删除 {ETC_DIR} 与 {VAR_DIR}（含 Bot token、证书、状态与切换备份）。");
        let ans = prompt_line("确认彻底清除？输入 yes 继续：")?;
        if ans.trim() == "yes" {
            let _ = fs::remove_dir_all(ETC_DIR);
            let _ = fs::remove_dir_all(VAR_DIR);
            let _ = fs::remove_file(PM_LINK);
            let _ = fs::remove_file(SBRELAY_BIN);
            println!("已彻底清除 sbrelay 服务与数据（未改动 sing-box 配置）。");
        } else {
            println!("已取消删除数据；服务已停止卸载，数据已保留。");
        }
    } else {
        println!("服务已卸载，配置与数据（{ETC_DIR}、{VAR_DIR}）已保留，重新安装可免令牌恢复。");
        println!("说明：未改动 sing-box 配置与服务。");
    }
    Ok(())
}

pub async fn interactive_menu() -> Result<()> {
    require_root()?;
    loop {
        println!();
        show_status();
        println!("----------------------------------------");
        println!("  1. 安装 / 更新控制端");
        println!("  2. 安装 / 更新 Agent（线路机 / 落地机）");
        println!("  3. 修改 Bot token");
        println!("  4. 重启服务");
        println!("  5. 卸载（保留数据）");
        println!("  6. 彻底清除（删除数据）");
        println!("  0. 退出");
        println!("----------------------------------------");
        let choice = prompt_line("请选择数字：")?;
        let res = match choice.trim() {
            "1" => setup_control(None, None, false).await,
            "2" => {
                let url = prompt_line("控制端地址（如 https://1.2.3.4:8443，留空复用已有）：")?;
                let pin = prompt_line("证书指纹（64 位 hex，留空复用已有）：")?;
                setup_agent(
                    (!url.trim().is_empty()).then_some(url),
                    (!pin.trim().is_empty()).then_some(pin),
                    false,
                )
                .await
            }
            "3" => set_token(),
            "4" => restart_services(),
            "5" => uninstall(false),
            "6" => uninstall(true),
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
