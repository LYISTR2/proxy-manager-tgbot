use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::backup::{create_backup, gen_backup_passphrase};
use crate::config::{ControlConfig, TlsMode};
use crate::protocol::{
    format_ss_link, redact, CommandOp, CommandResult, Egress, OutboundSpec, Role,
};
use crate::store::{Machine, Store, NAME_HINT};
use crate::tls::build_public_client;

#[derive(Debug, Clone)]
enum Expect {
    AddMachine(Role),
    RenameMachine(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallbackAction {
    Noop,
    Home,
    Add(Role),
    Machine(String),
    NodeLink(String),
    Refresh(String),
    PickLanding(String),
    ConfirmDirect(String),
    ConfirmLanding(String, String),
    ExecDirect(String),
    ExecLanding(String, String),
    Rollback(String),
    Rename(String),
    DeleteAsk(String),
    DeleteExec(String),
    Backup,
}

impl CallbackAction {
    fn parse(data: &str) -> Option<Self> {
        if data == "noop" {
            return Some(Self::Noop);
        }
        if data == "home" {
            return Some(Self::Home);
        }
        if data == "bk" {
            return Some(Self::Backup);
        }
        let parts: Vec<&str> = data.split(':').collect();
        match parts.as_slice() {
            ["add", "r"] => Some(Self::Add(Role::Relay)),
            ["add", "l"] => Some(Self::Add(Role::Landing)),
            ["m", id] => Some(Self::Machine((*id).into())),
            ["node", id] => Some(Self::NodeLink((*id).into())),
            ["rs", id] => Some(Self::Refresh((*id).into())),
            ["pk", id] => Some(Self::PickLanding((*id).into())),
            ["cf", mid, "d"] => Some(Self::ConfirmDirect((*mid).into())),
            ["cf", mid, lid] => Some(Self::ConfirmLanding((*mid).into(), (*lid).into())),
            ["go", mid, "d"] => Some(Self::ExecDirect((*mid).into())),
            ["go", mid, lid] => Some(Self::ExecLanding((*mid).into(), (*lid).into())),
            ["rb", id] => Some(Self::Rollback((*id).into())),
            ["rn", id] => Some(Self::Rename((*id).into())),
            ["del", id] => Some(Self::DeleteAsk((*id).into())),
            ["delx", id] => Some(Self::DeleteExec((*id).into())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Btn {
    pub text: String,
    pub callback_data: String,
}

impl Btn {
    fn new(text: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            callback_data: data.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Keyboard {
    pub inline_keyboard: Vec<Vec<Btn>>,
}

impl Keyboard {
    fn new(rows: Vec<Vec<Btn>>) -> Self {
        Self {
            inline_keyboard: rows,
        }
    }
}

#[derive(Debug, Deserialize)]
struct TgResp {
    ok: bool,
    #[serde(default)]
    description: String,
    #[serde(default)]
    result: Value,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id: i64,
    #[serde(default)]
    message: Option<TgMessage>,
    #[serde(default)]
    callback_query: Option<TgCallback>,
}

#[derive(Debug, Deserialize)]
struct TgMessage {
    message_id: i64,
    #[serde(default)]
    text: String,
    chat: Option<TgChat>,
    from: Option<TgUser>,
}

#[derive(Debug, Deserialize)]
struct TgChat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TgUser {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct TgCallback {
    id: String,
    from: Option<TgUser>,
    #[serde(default)]
    data: String,
    message: Option<TgMessage>,
}

pub struct Bot {
    cfg: ControlConfig,
    config_path: PathBuf,
    store: Arc<Store>,
    pin: Option<String>,
    http: reqwest::Client,
    expect: Mutex<HashMap<i64, Expect>>,
    in_flight: Mutex<HashSet<String>>,
    notified: Mutex<HashSet<String>>,
}

impl Bot {
    pub fn new(
        cfg: ControlConfig,
        config_path: PathBuf,
        store: Arc<Store>,
        pin: Option<String>,
    ) -> Result<Arc<Self>> {
        if let Some(hint) = cfg.owner_hint {
            if hint != 0 && store.owner() == 0 {
                let _ = store.set_owner(hint);
            }
        }
        let http = build_public_client(Duration::from_secs(45))?;
        Ok(Arc::new(Self {
            cfg,
            config_path,
            store,
            pin,
            http,
            expect: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashSet::new()),
            notified: Mutex::new(HashSet::new()),
        }))
    }

    async fn api(&self, method: &str, payload: Value) -> Result<Value> {
        let url = format!("https://api.telegram.org/bot{}/{}", self.cfg.tg_token, method);
        let resp = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", redact(&e.to_string())))?;
        let tr: TgResp = resp.json().await?;
        if !tr.ok {
            bail!("telegram: {}", tr.description);
        }
        Ok(tr.result)
    }

    async fn send(&self, chat: i64, text: &str, kb: Option<&Keyboard>) {
        let mut body = json!({
            "chat_id": chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        if let Some(k) = kb {
            body["reply_markup"] = serde_json::to_value(k).unwrap_or(Value::Null);
        }
        if let Err(e) = self.api("sendMessage", body).await {
            warn!("sendMessage 失败: {}", redact(&e.to_string()));
        }
    }

    async fn edit(&self, chat: i64, mid: i64, text: &str, kb: Option<&Keyboard>) {
        let markup = match kb {
            Some(k) => serde_json::to_value(k).unwrap_or(json!({"inline_keyboard": []})),
            None => json!({"inline_keyboard": []}),
        };
        let body = json!({
            "chat_id": chat,
            "message_id": mid,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": markup,
        });
        if let Err(e) = self.api("editMessageText", body).await {
            let msg = e.to_string();
            if !msg.contains("message is not modified") {
                warn!("editMessageText 失败: {}", redact(&msg));
            }
        }
    }

    async fn answer(&self, cb_id: &str, text: &str) {
        let _ = self
            .api(
                "answerCallbackQuery",
                json!({ "callback_query_id": cb_id, "text": text }),
            )
            .await;
    }

    async fn send_document(
        &self,
        chat: i64,
        filename: &str,
        bytes: Vec<u8>,
        caption: &str,
    ) -> Result<()> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendDocument",
            self.cfg.tg_token
        );
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(filename.to_string())
            .mime_str("application/octet-stream")?;
        let form = reqwest::multipart::Form::new()
            .text("chat_id", chat.to_string())
            .text("caption", caption.to_string())
            .text("parse_mode", "HTML")
            .part("document", part);
        let resp = self
            .http
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{}", redact(&e.to_string())))?;
        let tr: TgResp = resp.json().await?;
        if !tr.ok {
            bail!("telegram: {}", tr.description);
        }
        Ok(())
    }

    async fn send_backup(&self, chat: i64) {
        let pass = gen_backup_passphrase();
        let state_json = match self.store.snapshot_json() {
            Ok(b) => b,
            Err(e) => {
                self.send(
                    chat,
                    &format!("导出状态失败：{}", escape(&e.to_string())),
                    None,
                )
                .await;
                return;
            }
        };
        let cfg_path = self.config_path.clone();
        let pass_clone = pass.clone();
        let bytes = match tokio::task::spawn_blocking(move || {
            create_backup(&cfg_path, Some(&state_json), &pass_clone)
        })
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                self.send(
                    chat,
                    &format!("生成加密备份失败：{}", escape(&e.to_string())),
                    None,
                )
                .await;
                return;
            }
            Err(e) => {
                self.send(
                    chat,
                    &format!("生成备份任务异常：{}", escape(&e.to_string())),
                    None,
                )
                .await;
                return;
            }
        };

        let (relays, landings) = self.store.active_machine_counts();
        let filename = format!(
            "sbrelay-backup-{}.sbr",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );
        let caption = format!(
            "控制端加密备份（线路机 {relays} 台 / 落地机 {landings} 台）\n\
             对外地址：<code>{}</code>（{}）\n\
             解密口令：<tg-spoiler><code>{}</code></tg-spoiler>\n\n\
             迁移到新服务器后执行：\n\
             <pre>sbrelay restore {}</pre>\n\
             再将域名解析或反代切到新机，现有 Agent 无需重新对接，会自动重连上报。",
            escape(&self.cfg.public_url),
            self.cfg.tls_mode.cn(),
            escape(&pass),
            escape(&filename),
        );
        if let Err(e) = self.send_document(chat, &filename, bytes, &caption).await {
            self.send(
                chat,
                &format!("发送备份文件失败：{}", escape(&e.to_string())),
                None,
            )
            .await;
        }
    }

    fn allowed(&self, uid: i64) -> bool {
        let owner = self.store.owner();
        owner != 0 && owner == uid
    }

    fn try_lock_machine(&self, id: &str) -> bool {
        self.in_flight.lock().unwrap().insert(id.to_string())
    }

    fn unlock_machine(&self, id: &str) {
        self.in_flight.lock().unwrap().remove(id);
    }

    async fn ask(&self, machine_id: &str, op: CommandOp, timeout: Duration) -> Result<CommandResult> {
        let (cmd_id, rx) = self.store.enqueue_cmd(machine_id, op)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(res)) => Ok(res),
            Ok(Err(_)) => {
                self.store.cancel_cmd(&cmd_id);
                bail!("等待结果通道关闭");
            }
            Err(_) => {
                self.store.cancel_cmd(&cmd_id);
                bail!("agent 未在 {} 秒内响应（可能离线）", timeout.as_secs());
            }
        }
    }

    pub async fn notify_node_ready(&self, machine_id: &str) {
        let owner = self.store.owner();
        if owner == 0 {
            return;
        }
        {
            let mut set = self.notified.lock().unwrap();
            if !set.insert(machine_id.to_string()) {
                return;
            }
        }
        let Some(m) = self.store.machine(machine_id) else {
            return;
        };
        if m.revoked {
            return;
        }
        let Some(node) = m.status.as_ref().and_then(|s| s.node.as_ref()) else {
            return;
        };
        if !node.is_ready() {
            return;
        }
        match m.role {
            Role::Relay => {
                let (text, kb) = self.node_view(machine_id);
                self.send(
                    owner,
                    &format!("线路机已上线并自动搭好 SS2022 节点：\n\n{text}"),
                    Some(&kb),
                )
                .await;
            }
            Role::Landing => {
                let text = format!(
                    "落地机「{}」已上线就绪（SS2022 端口 {}）。\n现在可在线路机面板里直接切换到它。",
                    escape(&m.name),
                    node.port
                );
                self.send(
                    owner,
                    &text,
                    Some(&Keyboard::new(vec![vec![Btn::new("打开首页", "home")]])),
                )
                .await;
            }
        }
    }

    pub fn install_command(&self, token: &str) -> String {
        match (self.cfg.tls_mode, self.pin.as_deref()) {
            (TlsMode::Webpki, _) | (_, None) => format!(
                "export HISTCONTROL=ignorespace\n SBRELAY_TOKEN={} bash <(curl -fsSL https://raw.githubusercontent.com/{}/main/install.sh) agent --url '{}'",
                token, self.cfg.repo, self.cfg.public_url
            ),
            (TlsMode::Pin, Some(pin)) => format!(
                "export HISTCONTROL=ignorespace\n SBRELAY_TOKEN={} bash <(curl -fsSL https://raw.githubusercontent.com/{}/main/install.sh) agent --url '{}' --pin '{}'",
                token, self.cfg.repo, self.cfg.public_url, pin
            ),
        }
    }

    fn egress_label(&self, egress: Option<&Egress>) -> String {
        match egress {
            None => "未知".into(),
            Some(Egress::Direct) => "本机直出".into(),
            Some(Egress::Landing {
                landing_id,
                server,
                port,
            }) => {
                if let Some(lm) = self.store.machine(landing_id) {
                    if !lm.revoked {
                        return lm.name;
                    }
                }
                format!("{server}:{port}")
            }
        }
    }

    fn egress_key_label(&self, key: &str) -> String {
        if key == "direct" {
            return "本机直出".into();
        }
        if let Some(lid) = key.strip_prefix("landing:") {
            if let Some(lm) = self.store.machine(lid) {
                return lm.name;
            }
            return lid.to_string();
        }
        key.to_string()
    }

    pub fn home_view(&self) -> (String, Keyboard) {
        let relays = self.store.machines_by_role(Role::Relay);
        let landings = self.store.machines_by_role(Role::Landing);

        if relays.is_empty() && landings.is_empty() {
            let text = "线路切换面板\n\n还没有机器。\n1. 点「添加线路机」自动搭建 SS2022 客户端节点；\n2. 点「添加落地机」自动搭建 SS2022 落地；\n3. 之后可在不动客户端节点的前提下随时换落地或改本机直出。".to_string();
            let kb = Keyboard::new(vec![
                vec![
                    Btn::new("添加线路机", "add:r"),
                    Btn::new("添加落地机", "add:l"),
                ],
                vec![Btn::new("备份控制端", "bk")],
            ]);
            return (text, kb);
        }

        let mut text = String::from("线路切换面板\n");
        let mut rows = Vec::new();

        text.push_str("\n【线路机】\n");
        if relays.is_empty() {
            text.push_str("暂无，请点「添加线路机」。\n");
        } else {
            for m in &relays {
                let dot = online_dot(m);
                let egress = match m.status.as_ref() {
                    Some(st) => format!(" → {}", escape(&self.egress_label(st.egress.as_ref()))),
                    None if !m.is_online() => " · 离线".into(),
                    None => " · 等待上报".into(),
                };
                text.push_str(&format!("{dot} {}{egress}\n", escape(&m.name)));
                rows.push(vec![Btn::new(
                    format!("线路 · {}", m.name),
                    format!("m:{}", m.id),
                )]);
            }
        }

        text.push_str("\n【落地机】\n");
        if landings.is_empty() {
            text.push_str("暂无，请点「添加落地机」。\n");
        } else {
            for m in &landings {
                let dot = online_dot(m);
                let state = if m.is_landing_ready() {
                    "已就绪"
                } else {
                    "等待上报"
                };
                text.push_str(&format!("{dot} {} · {state}\n", escape(&m.name)));
                rows.push(vec![Btn::new(
                    format!("落地 · {}", m.name),
                    format!("m:{}", m.id),
                )]);
            }
        }

        rows.push(vec![
            Btn::new("刷新", "home"),
            Btn::new("添加线路机", "add:r"),
            Btn::new("添加落地机", "add:l"),
        ]);
        rows.push(vec![Btn::new("备份控制端", "bk")]);
        (text.trim_end().to_string(), Keyboard::new(rows))
    }

    pub fn machine_view(&self, id: &str) -> (String, Keyboard) {
        let Some(m) = self.store.machine(id) else {
            return (
                "找不到这台机器。".into(),
                Keyboard::new(vec![vec![Btn::new("返回", "home")]]),
            );
        };
        if m.revoked {
            return (
                "这台机器已删除。".into(),
                Keyboard::new(vec![vec![Btn::new("返回", "home")]]),
            );
        }

        let mut text = format!("{} {}\n角色：{}\n", online_dot(&m), escape(&m.name), m.role.cn());
        match m.last_seen {
            Some(t) => text.push_str(&format!("最近心跳：{}\n", t.format("%Y-%m-%d %H:%M:%S UTC"))),
            None => text.push_str("尚未连上控制端。\n"),
        }

        let mut rows = Vec::new();
        match m.role {
            Role::Relay => {
                if let Some(st) = m.status.as_ref() {
                    text.push_str(&format!("sing-box：{}\n", escape(&st.service)));
                    if let Some(n) = st.node.as_ref() {
                        text.push_str(&format!("客户端节点：SS2022（端口 {}，换落地不变）\n", n.port));
                        rows.push(vec![Btn::new(
                            "查看 SS2022 节点链接",
                            format!("node:{}", m.id),
                        )]);
                    }
                    text.push_str(&format!(
                        "当前出口：{}\n",
                        escape(&self.egress_label(st.egress.as_ref()))
                    ));
                    rows.push(vec![Btn::new("换落地 / 本机直出", format!("pk:{}", m.id))]);
                    if st.can_rollback {
                        rows.push(vec![
                            Btn::new("回滚上次切换", format!("rb:{}", m.id)),
                            Btn::new("刷新状态", format!("rs:{}", m.id)),
                        ]);
                    } else {
                        rows.push(vec![Btn::new("刷新状态", format!("rs:{}", m.id))]);
                    }
                } else {
                    text.push_str("还没有状态，可点刷新向 agent 请求一次。");
                    rows.push(vec![Btn::new("刷新状态", format!("rs:{}", m.id))]);
                }
            }
            Role::Landing => {
                if let Some(st) = m.status.as_ref() {
                    text.push_str(&format!("sing-box：{}\n", escape(&st.service)));
                    if let Some(n) = st.node.as_ref().filter(|n| n.is_ready()) {
                        text.push_str(&format!(
                            "落地节点：已就绪（{}，端口 {}）\n在线路机面板中可直接切换到这台落地机。",
                            escape(&n.method),
                            n.port
                        ));
                    } else {
                        text.push_str("落地节点：等待上报完整 SS2022 信息。");
                    }
                } else {
                    text.push_str("落地节点：等待落地机 agent 上报信息。");
                }
                rows.push(vec![Btn::new("刷新状态", format!("rs:{}", m.id))]);
            }
        }

        rows.push(vec![
            Btn::new("重命名", format!("rn:{}", m.id)),
            Btn::new("删除机器", format!("del:{}", m.id)),
        ]);
        rows.push(vec![Btn::new("返回首页", "home")]);
        (text.trim_end().to_string(), Keyboard::new(rows))
    }

    pub fn node_view(&self, id: &str) -> (String, Keyboard) {
        let Some(m) = self.store.machine(id).filter(|m| !m.revoked) else {
            return (
                "找不到这台线路机。".into(),
                Keyboard::new(vec![vec![Btn::new("返回", "home")]]),
            );
        };
        let Some(n) = m.status.as_ref().and_then(|s| s.node.as_ref()) else {
            return (
                "尚未获取到 SS2022 节点信息，请先点刷新状态。".into(),
                Keyboard::new(vec![vec![Btn::new("返回", format!("m:{id}"))]]),
            );
        };
        let server = if n.server.is_empty() {
            "待检测"
        } else {
            &n.server
        };
        let mut text = format!(
            "线路机「{}」SS2022 节点\n地址：<code>{}</code>\n端口：<code>{}</code>\n加密：<code>{}</code>\n密码：<code>{}</code>\n",
            escape(&m.name),
            escape(server),
            n.port,
            escape(&n.method),
            escape(&n.password)
        );
        if let Some(link) = format_ss_link(n, &m.name) {
            text.push_str(&format!("\n分享链接：\n<pre>{}</pre>\n", escape(&link)));
        }
        text.push_str("\n提示：切换落地或本机直出时，以上节点信息完全不变。");
        (
            text,
            Keyboard::new(vec![vec![
                Btn::new("返回线路机", format!("m:{id}")),
                Btn::new("首页", "home"),
            ]]),
        )
    }

    fn pick_view(&self, id: &str) -> (String, Keyboard) {
        let Some(m) = self.store.machine(id).filter(|m| !m.revoked) else {
            return (
                "找不到这台线路机。".into(),
                Keyboard::new(vec![vec![Btn::new("返回", "home")]]),
            );
        };
        let cur = m.status.as_ref().and_then(|s| s.egress.as_ref());
        let mut text = format!(
            "给线路机「{}」选择出口（当前：{}）\n只改出站与路由，不动入站地址、端口和密码。",
            escape(&m.name),
            escape(&self.egress_label(cur))
        );

        let mut rows = Vec::new();
        let mut ready_count = 0usize;
        for lm in self.store.machines_by_role(Role::Landing) {
            if !lm.is_landing_ready() {
                continue;
            }
            ready_count += 1;
            let is_cur = matches!(cur, Some(Egress::Landing { landing_id, .. }) if landing_id == &lm.id);
            if is_cur {
                rows.push(vec![Btn::new(
                    format!("{} {}（当前）", online_dot(&lm), lm.name),
                    "noop",
                )]);
            } else {
                rows.push(vec![Btn::new(
                    format!("{} 切到「{}」", online_dot(&lm), lm.name),
                    format!("cf:{}:{}", m.id, lm.id),
                )]);
            }
        }

        if matches!(cur, Some(Egress::Direct)) {
            rows.push(vec![Btn::new("本机直出（当前）", "noop")]);
        } else {
            rows.push(vec![Btn::new(
                "切到「本机直出」（不经落地）",
                format!("cf:{}:d", m.id),
            )]);
        }

        if ready_count == 0 {
            text.push_str("\n\n暂无已就绪的落地机，可以先用「本机直出」，或回首页添加落地机。");
        }
        rows.push(vec![Btn::new("返回", format!("m:{}", m.id))]);
        (text, Keyboard::new(rows))
    }

    fn format_switch_result(&self, op_cn: &str, machine_name: &str, res: &CommandResult) -> String {
        if !res.ok {
            let err = res.error.as_deref().unwrap_or("未知错误");
            return format!("{op_cn}失败：{}", escape(err));
        }
        let from = res
            .from
            .as_deref()
            .map(|k| self.egress_key_label(k))
            .unwrap_or_else(|| "?".into());
        let to = res
            .to
            .as_deref()
            .map(|k| self.egress_key_label(k))
            .unwrap_or_else(|| "?".into());
        let mut s = format!(
            "{op_cn}成功。\n线路机「{}」：{} → {}",
            escape(machine_name),
            escape(&from),
            escape(&to)
        );
        if let Some(ref b) = res.backup {
            s.push_str(&format!("\n备份：<code>{}</code>", escape(b)));
        }
        s
    }

    async fn send_install_for(&self, chat: i64, name: &str, role: Role) -> bool {
        let tok = match self
            .store
            .new_install_token(name, role, Duration::from_secs(2 * 3600))
        {
            Ok(t) => t,
            Err(e) => {
                self.send(chat, &escape(&e.to_string()), None).await;
                return false;
            }
        };
        let cmd = self.install_command(&tok.token);
        let extra = match role {
            Role::Relay => "安装完成后会自动搭建 SS2022 节点并推送链接给你。",
            Role::Landing => "安装完成后会自动搭建 SS2022 落地并上报，线路机可直接切到它。",
        };
        let msg = format!(
            "{}「{}」安装命令（2 小时内有效，一次性）。{}\n在目标机器以 root 执行：\n\n<pre>{}</pre>",
            role.cn(),
            escape(&tok.name),
            extra,
            escape(&cmd)
        );
        self.send(
            chat,
            &msg,
            Some(&Keyboard::new(vec![vec![Btn::new("返回首页", "home")]])),
        )
        .await;
        true
    }

    async fn handle_message(&self, msg: TgMessage) {
        let (Some(from), Some(chat)) = (msg.from, msg.chat) else {
            return;
        };
        let uid = from.id;
        let text = msg.text.trim();
        let (cmd_raw, arg) = match text.split_once(' ') {
            Some((c, a)) => (c, a.trim()),
            None => (text, ""),
        };
        let cmd = cmd_raw.to_ascii_lowercase();

        if is_start_cmd(&cmd) {
            self.expect.lock().unwrap().remove(&uid);
            if self.store.owner() == 0 {
                if self.store.set_owner(uid).is_err() {
                    self.send(chat.id, "绑定管理员失败。", None).await;
                    return;
                }
                self.send(chat.id, "已将你绑定为管理员，之后只响应你的消息。", None)
                    .await;
            } else if !self.allowed(uid) {
                return;
            }
            let (t, kb) = self.home_view();
            self.send(chat.id, &t, Some(&kb)).await;
            return;
        }

        if !self.allowed(uid) {
            return;
        }

        if cmd == "/cancel" {
            if self.expect.lock().unwrap().remove(&uid).is_some() {
                self.send(chat.id, "已取消。", None).await;
            }
            let (t, kb) = self.home_view();
            self.send(chat.id, &t, Some(&kb)).await;
            return;
        }

        if !text.starts_with('/') {
            let pending = self.expect.lock().unwrap().get(&uid).cloned();
            if let Some(exp) = pending {
                match exp {
                    Expect::AddMachine(role) => {
                        if self.send_install_for(chat.id, text, role).await {
                            self.expect.lock().unwrap().remove(&uid);
                        }
                    }
                    Expect::RenameMachine(mid) => match self.store.rename_machine(&mid, text) {
                        Ok(m) => {
                            self.expect.lock().unwrap().remove(&uid);
                            let (t, kb) = self.machine_view(&mid);
                            self.send(
                                chat.id,
                                &format!("已改名为「{}」。\n\n{t}", escape(&m.name)),
                                Some(&kb),
                            )
                            .await;
                        }
                        Err(e) => {
                            self.send(chat.id, &escape(&e.to_string()), None).await;
                        }
                    },
                }
                return;
            }
        }

        match cmd.as_str() {
            "/help" => {
                self.send(
                    chat.id,
                    &format!(
                        "命令：\n/start 首页\n/status 刷新列表\n/add 名字 添加线路机（{NAME_HINT}）\n/add-landing 名字 添加落地机\n/backup 导出控制端加密备份\n/cancel 取消输入\n/help 本说明\n\n日常操作直接点按钮即可。"
                    ),
                    None,
                )
                .await;
            }
            "/backup" => {
                self.expect.lock().unwrap().remove(&uid);
                self.send(chat.id, "正在生成加密备份…", None).await;
                self.send_backup(chat.id).await;
            }
            "/status" | "/home" => {
                self.expect.lock().unwrap().remove(&uid);
                let (t, kb) = self.home_view();
                self.send(chat.id, &t, Some(&kb)).await;
            }
            "/add" => {
                if arg.is_empty() {
                    self.expect
                        .lock()
                        .unwrap()
                        .insert(uid, Expect::AddMachine(Role::Relay));
                    self.send(
                        chat.id,
                        &format!("请发送这台线路机的名字（{NAME_HINT}）。\n发 /cancel 取消。"),
                        None,
                    )
                    .await;
                } else {
                    self.expect.lock().unwrap().remove(&uid);
                    self.send_install_for(chat.id, arg, Role::Relay).await;
                }
            }
            "/add-landing" | "/addlanding" => {
                if arg.is_empty() {
                    self.expect
                        .lock()
                        .unwrap()
                        .insert(uid, Expect::AddMachine(Role::Landing));
                    self.send(
                        chat.id,
                        &format!("请发送这台落地机的名字（{NAME_HINT}）。\n发 /cancel 取消。"),
                        None,
                    )
                    .await;
                } else {
                    self.expect.lock().unwrap().remove(&uid);
                    self.send_install_for(chat.id, arg, Role::Landing).await;
                }
            }
            _ => {
                let (t, kb) = self.home_view();
                self.send(chat.id, &t, Some(&kb)).await;
            }
        }
    }

    async fn handle_callback(&self, cb: TgCallback) {
        let (Some(from), Some(msg)) = (cb.from, cb.message) else {
            return;
        };
        let Some(chat) = msg.chat else { return };
        let uid = from.id;
        if !self.allowed(uid) {
            return;
        }
        let Some(action) = CallbackAction::parse(&cb.data) else {
            self.answer(&cb.id, "").await;
            return;
        };

        if !matches!(action, CallbackAction::Noop | CallbackAction::Add(_) | CallbackAction::Rename(_)) {
            self.expect.lock().unwrap().remove(&uid);
        }

        let chat_id = chat.id;
        let mid = msg.message_id;

        match action {
            CallbackAction::Noop => self.answer(&cb.id, "当前已在使用该出口").await,
            CallbackAction::Home => {
                let (t, kb) = self.home_view();
                self.edit(chat_id, mid, &t, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::Add(role) => {
                self.expect
                    .lock()
                    .unwrap()
                    .insert(uid, Expect::AddMachine(role));
                self.edit(
                    chat_id,
                    mid,
                    &format!(
                        "请发送这台{}的名字（{NAME_HINT}，同角色不能重名）。\n发 /cancel 取消。",
                        role.cn()
                    ),
                    Some(&Keyboard::new(vec![vec![Btn::new("取消", "home")]])),
                )
                .await;
                self.answer(&cb.id, "请发送名字").await;
            }
            CallbackAction::Machine(id) => {
                let (t, kb) = self.machine_view(&id);
                self.edit(chat_id, mid, &t, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::NodeLink(id) => {
                let (t, kb) = self.node_view(&id);
                self.edit(chat_id, mid, &t, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::PickLanding(id) => {
                let (t, kb) = self.pick_view(&id);
                self.edit(chat_id, mid, &t, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::ConfirmDirect(id) => {
                let name = self
                    .store
                    .machine(&id)
                    .map(|m| m.name)
                    .unwrap_or_else(|| "线路机".into());
                let text = format!(
                    "确认将线路机「{}」切换为「本机直出」？\n流量将直接从线路机自身 IP 发出，会短暂重启 sing-box 1–2 秒。客户端节点不变。",
                    escape(&name)
                );
                let kb = Keyboard::new(vec![vec![
                    Btn::new("确认切换", format!("go:{id}:d")),
                    Btn::new("取消", format!("m:{id}")),
                ]]);
                self.edit(chat_id, mid, &text, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::ConfirmLanding(id, lid) => {
                let rname = self
                    .store
                    .machine(&id)
                    .map(|m| m.name)
                    .unwrap_or_else(|| "线路机".into());
                let lname = self
                    .store
                    .machine(&lid)
                    .map(|m| m.name)
                    .unwrap_or_else(|| "落地机".into());
                let text = format!(
                    "确认将线路机「{}」切到落地「{}」？\n会短暂重启线路机 sing-box 1–2 秒。客户端节点地址、端口和密码完全不变。",
                    escape(&rname),
                    escape(&lname)
                );
                let kb = Keyboard::new(vec![vec![
                    Btn::new("确认切换", format!("go:{id}:{lid}")),
                    Btn::new("取消", format!("m:{id}")),
                ]]);
                self.edit(chat_id, mid, &text, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::Refresh(id) => {
                if !self.try_lock_machine(&id) {
                    self.answer(&cb.id, "该机器正在执行其他操作，请稍候").await;
                    return;
                }
                self.answer(&cb.id, "正在刷新状态…").await;
                let res = self.ask(&id, CommandOp::Status, Duration::from_secs(20)).await;
                self.unlock_machine(&id);
                match res {
                    Ok(r) => {
                        if let Some(st) = r.status {
                            self.store.touch_status(&id, Some(st));
                        }
                        let (t, kb) = self.machine_view(&id);
                        self.edit(chat_id, mid, &t, Some(&kb)).await;
                    }
                    Err(e) => {
                        self.edit(
                            chat_id,
                            mid,
                            &format!("刷新失败：{}", escape(&e.to_string())),
                            Some(&Keyboard::new(vec![vec![Btn::new("返回", format!("m:{id}"))]])),
                        )
                        .await;
                    }
                }
            }
            CallbackAction::ExecDirect(id) => {
                self.exec_switch(chat_id, mid, &cb.id, &id, CommandOp::SwitchDirect, "切换")
                    .await;
            }
            CallbackAction::ExecLanding(id, lid) => {
                let Some(lm) = self.store.machine(&lid).filter(|m| m.is_landing_ready()) else {
                    self.answer(&cb.id, "目标落地机已不可用").await;
                    return;
                };
                let node = lm.status.unwrap().node.unwrap();
                let spec = OutboundSpec {
                    landing_id: lm.id,
                    server: node.server,
                    port: node.port,
                    method: node.method,
                    password: node.password,
                };
                self.exec_switch(
                    chat_id,
                    mid,
                    &cb.id,
                    &id,
                    CommandOp::SwitchLanding { spec },
                    "切换",
                )
                .await;
            }
            CallbackAction::Rollback(id) => {
                self.exec_switch(chat_id, mid, &cb.id, &id, CommandOp::Rollback, "回滚")
                    .await;
            }
            CallbackAction::Rename(id) => {
                self.expect
                    .lock()
                    .unwrap()
                    .insert(uid, Expect::RenameMachine(id.clone()));
                self.edit(
                    chat_id,
                    mid,
                    &format!("请发送新名字（{NAME_HINT}，同角色不能重名）。\n发 /cancel 取消。"),
                    Some(&Keyboard::new(vec![vec![Btn::new("取消", format!("m:{id}"))]])),
                )
                .await;
                self.answer(&cb.id, "请发送新名字").await;
            }
            CallbackAction::DeleteAsk(id) => {
                let Some(m) = self.store.machine(&id).filter(|m| !m.revoked) else {
                    self.answer(&cb.id, "机器已不存在").await;
                    let (t, kb) = self.home_view();
                    self.edit(chat_id, mid, &t, Some(&kb)).await;
                    return;
                };
                let text = format!(
                    "确认删除{}「{}」？\n会吊销其接入凭据（不改动目标机 sing-box，如需卸载请在目标机运行 sbrelay uninstall）。",
                    m.role.cn(),
                    escape(&m.name)
                );
                let kb = Keyboard::new(vec![vec![
                    Btn::new("确认删除", format!("delx:{id}")),
                    Btn::new("取消", format!("m:{id}")),
                ]]);
                self.edit(chat_id, mid, &text, Some(&kb)).await;
                self.answer(&cb.id, "").await;
            }
            CallbackAction::DeleteExec(id) => {
                match self.store.revoke_machine(&id) {
                    Ok(()) => self.answer(&cb.id, "已删除").await,
                    Err(e) => self.answer(&cb.id, &e.to_string()).await,
                }
                let (t, kb) = self.home_view();
                self.edit(chat_id, mid, &t, Some(&kb)).await;
            }
            CallbackAction::Backup => {
                self.answer(&cb.id, "正在生成加密备份…").await;
                self.send_backup(chat_id).await;
            }
        }
    }

    async fn exec_switch(
        &self,
        chat_id: i64,
        mid: i64,
        cb_id: &str,
        machine_id: &str,
        op: CommandOp,
        op_cn: &str,
    ) {
        if !self.try_lock_machine(machine_id) {
            self.answer(cb_id, "该线路机正在执行操作，请稍候").await;
            return;
        }
        let mname = self
            .store
            .machine(machine_id)
            .map(|m| m.name)
            .unwrap_or_else(|| "线路机".into());
        self.answer(cb_id, &format!("正在{op_cn}…")).await;
        self.edit(
            chat_id,
            mid,
            &format!("正在{op_cn}，线路机 sing-box 将短暂重启…"),
            None,
        )
        .await;

        let res = self.ask(machine_id, op, Duration::from_secs(40)).await;
        self.unlock_machine(machine_id);

        let kb = Keyboard::new(vec![vec![
            Btn::new("查看线路机", format!("m:{machine_id}")),
            Btn::new("首页", "home"),
        ]]);
        match res {
            Ok(r) => {
                if let Some(ref st) = r.status {
                    self.store.touch_status(machine_id, Some(st.clone()));
                }
                let txt = self.format_switch_result(op_cn, &mname, &r);
                self.edit(chat_id, mid, &txt, Some(&kb)).await;
            }
            Err(e) => {
                self.edit(
                    chat_id,
                    mid,
                    &format!("{op_cn}失败：{}", escape(&e.to_string())),
                    Some(&kb),
                )
                .await;
            }
        }
    }

    pub async fn run_polling(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        if self.store.owner() != 0 {
            info!("已绑定管理员 user_id={}", self.store.owner());
        } else {
            info!("尚未绑定管理员：请在 Telegram 向 Bot 发送 /start");
        }

        let mut offset: i64 = self.store.tg_offset();
        loop {
            if *shutdown.borrow() {
                return;
            }
            let req = self.api(
                "getUpdates",
                json!({
                    "offset": offset,
                    "timeout": 25,
                    "allowed_updates": ["message", "callback_query"]
                }),
            );
            let res = tokio::select! {
                _ = shutdown.changed() => return,
                r = req => r,
            };
            let val = match res {
                Ok(v) => v,
                Err(e) => {
                    warn!("getUpdates 失败: {}", redact(&e.to_string()));
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        _ = tokio::time::sleep(Duration::from_secs(3)) => continue,
                    }
                }
            };
            let updates: Vec<Update> = serde_json::from_value(val).unwrap_or_default();
            let prev_offset = offset;
            for u in updates {
                offset = u.update_id + 1;
                if let Some(msg) = u.message {
                    let bot = self.clone();
                    tokio::spawn(async move { bot.handle_message(msg).await });
                }
                if let Some(cb) = u.callback_query {
                    let bot = self.clone();
                    tokio::spawn(async move { bot.handle_callback(cb).await });
                }
            }
            if offset > prev_offset {
                self.store.set_tg_offset(offset);
            }
        }
    }
}

fn online_dot(m: &Machine) -> &'static str {
    if m.is_online() {
        "●"
    } else {
        "○"
    }
}

fn is_start_cmd(cmd: &str) -> bool {
    cmd == "/start" || cmd.strip_prefix("/start@").is_some_and(|s| !s.is_empty())
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{NodeInfo, NodeStatus, SS2022_METHOD};
    use std::path::PathBuf;

    #[test]
    fn callback_parsing_covers_all_variants() {
        assert_eq!(CallbackAction::parse("home"), Some(CallbackAction::Home));
        assert_eq!(
            CallbackAction::parse("add:r"),
            Some(CallbackAction::Add(Role::Relay))
        );
        assert_eq!(
            CallbackAction::parse("cf:abc:d"),
            Some(CallbackAction::ConfirmDirect("abc".into()))
        );
        assert_eq!(
            CallbackAction::parse("go:abc:def"),
            Some(CallbackAction::ExecLanding("abc".into(), "def".into()))
        );
        assert_eq!(CallbackAction::parse("bk"), Some(CallbackAction::Backup));
        assert!(CallbackAction::parse("unknown:1").is_none());
    }

    #[test]
    fn views_render_relay_and_landing() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let cfg = ControlConfig {
            tg_token: "123456:testtoken".into(),
            listen: "0.0.0.0:8443".into(),
            public_url: "https://1.2.3.4:8443".into(),
            tls_mode: TlsMode::Pin,
            listen_tls: true,
            trust_proxy: false,
            data_dir: PathBuf::from(dir.path()),
            cert_file: dir.path().join("tls.crt"),
            key_file: dir.path().join("tls.key"),
            owner_hint: Some(42),
            repo: "LYISTR2/proxy-manager-tgbot".into(),
        };
        let pin = "a".repeat(64);
        let bot = Bot::new(
            cfg.clone(),
            dir.path().join("control.toml"),
            store.clone(),
            Some(pin.clone()),
        )
        .unwrap();
        assert_eq!(store.owner(), 42);
        assert!(bot.install_command("tok1").contains("--pin"));

        let webpki_cfg = ControlConfig {
            public_url: "https://ctl.example.com".into(),
            listen: "127.0.0.1:8443".into(),
            tls_mode: TlsMode::Webpki,
            listen_tls: false,
            trust_proxy: true,
            ..cfg
        };
        let webpki_bot = Bot::new(
            webpki_cfg,
            dir.path().join("control.toml"),
            store.clone(),
            None,
        )
        .unwrap();
        let cmd_webpki = webpki_bot.install_command("tok2");
        assert!(cmd_webpki.contains("--url 'https://ctl.example.com'"));
        assert!(!cmd_webpki.contains("--pin"));

        let rt = store
            .new_install_token("香港线路", Role::Relay, Duration::from_secs(60))
            .unwrap();
        let rm = store.consume_token(&rt.token).unwrap();
        store.touch_status(
            &rm.id,
            Some(NodeStatus {
                role: Role::Relay,
                node: Some(NodeInfo {
                    server: "1.1.1.1".into(),
                    port: 23456,
                    method: SS2022_METHOD.into(),
                    password: "secret".into(),
                }),
                egress: Some(Egress::Direct),
                service: "active".into(),
                can_rollback: false,
            }),
        );

        let (home, _) = bot.home_view();
        assert!(home.contains("香港线路"));
        assert!(home.contains("本机直出"));

        let (node_txt, _) = bot.node_view(&rm.id);
        assert!(node_txt.contains("ss://"));
        assert!(node_txt.contains("23456"));
    }
}
