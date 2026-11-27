mod agent;
mod bot;
mod config;
mod control;
mod ops;
mod protocol;
mod singbox;
mod store;
mod tls;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::config::{AGENT_CONFIG, CONTROL_CONFIG};

#[derive(Parser)]
#[command(
    name = "sbrelay",
    version,
    about = "单二进制 Telegram Bot + sing-box SS2022 线路/落地管理工具"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// 启动控制端（Telegram Bot + HTTPS API）
    Control {
        #[arg(long, default_value = CONTROL_CONFIG)]
        config: PathBuf,
    },
    /// 启动 Agent（主动长轮询控制端）
    Agent {
        #[arg(long, default_value = AGENT_CONFIG)]
        config: PathBuf,
    },
    /// 安装 / 更新本机角色与 systemd 服务
    Setup {
        #[command(subcommand)]
        role: SetupRole,
    },
    /// 打开交互管理菜单（也可通过 pm 软链直接启动）
    Menu,
    /// 查看控制端 / Agent / sing-box 运行状态
    Status,
    /// 修改 Telegram Bot token 并重启控制端
    SetToken,
    /// 重启本机已安装的 sbrelay 服务
    Restart,
    /// 卸载服务（默认保留配置与数据；加 --purge 彻底清除）
    Uninstall {
        #[arg(long)]
        purge: bool,
    },
    /// 显示版本号
    Version,
}

#[derive(Subcommand)]
enum SetupRole {
    /// 安装 / 更新控制端
    Control {
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long)]
        regen_cert: bool,
    },
    /// 安装 / 更新 Agent（线路机或落地机，角色由控制端令牌决定）
    Agent {
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        pin: Option<String>,
        #[arg(long)]
        force_register: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::ensure_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let invoked_as_pm = std::env::args()
        .next()
        .and_then(|p| PathBuf::from(p).file_name().map(|s| s == "pm"))
        .unwrap_or(false);

    let cli = Cli::parse();
    let cmd = match cli.cmd {
        Some(c) => c,
        None if invoked_as_pm => Cmd::Menu,
        None => {
            ops::show_status();
            println!("\n用法提示：sbrelay --help  或  sbrelay menu");
            return Ok(());
        }
    };

    match cmd {
        Cmd::Control { config } => ops::run_control_cmd(&config).await,
        Cmd::Agent { config } => agent::run_agent_cmd(&config).await,
        Cmd::Setup { role } => match role {
            SetupRole::Control {
                listen,
                public_url,
                regen_cert,
            } => ops::setup_control(listen, public_url, regen_cert).await,
            SetupRole::Agent {
                url,
                pin,
                force_register,
            } => ops::setup_agent(url, pin, force_register).await,
        },
        Cmd::Menu => ops::interactive_menu().await,
        Cmd::Status => {
            ops::show_status();
            Ok(())
        }
        Cmd::SetToken => ops::set_token(),
        Cmd::Restart => ops::restart_services(),
        Cmd::Uninstall { purge } => ops::uninstall(purge),
        Cmd::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
