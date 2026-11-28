use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Notify};

use crate::config::write_atomic;
use crate::protocol::{rand_hex, CommandEnvelope, CommandOp, CommandResult, NodeStatus, Role};

pub const MAX_NAME_CHARS: usize = 32;
pub const NAME_HINT: &str = "1–32 个字（汉字、英文均可）";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub secret: String,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
    #[serde(default)]
    pub status: Option<NodeStatus>,
    #[serde(default)]
    pub revoked: bool,
}

impl Machine {
    pub fn is_online(&self) -> bool {
        self.last_seen
            .is_some_and(|t| (Utc::now() - t).num_seconds() < 60)
    }

    pub fn is_landing_ready(&self) -> bool {
        self.role == Role::Landing
            && !self.revoked
            && self
                .status
                .as_ref()
                .and_then(|s| s.node.as_ref())
                .is_some_and(|n| n.is_ready())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallToken {
    pub token: String,
    pub name: String,
    pub role: Role,
    pub expires: DateTime<Utc>,
    #[serde(default)]
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCmd {
    pub id: String,
    pub machine_id: String,
    pub op: CommandOp,
    pub created: DateTime<Utc>,
    #[serde(default)]
    pub dispatched_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub result: Option<CommandResult>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    owner_id: i64,
    #[serde(default)]
    tg_offset: i64,
    #[serde(default)]
    machines: HashMap<String, Machine>,
    #[serde(default)]
    tokens: HashMap<String, InstallToken>,
    #[serde(default)]
    commands: HashMap<String, PendingCmd>,
}

struct Inner {
    state: State,
    last_flush: Instant,
}

pub struct Store {
    path: PathBuf,
    _lock_file: File,
    inner: Mutex<Inner>,
    notifiers: Mutex<HashMap<String, Arc<Notify>>>,
    waiters: Mutex<HashMap<String, oneshot::Sender<CommandResult>>>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)
            .with_context(|| format!("创建数据目录失败: {}", dir.display()))?;
        let path = dir.join("state.json");
        let lock_path = dir.join("state.json.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .with_context(|| format!("打开锁文件失败: {}", lock_path.display()))?;

        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            bail!(
                "状态锁被占用（{}），请确认没有其他 sbrelay 控制端正在使用同一数据目录",
                lock_path.display()
            );
        }

        let state = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("读取 state.json 失败: {}", path.display()))?;
            serde_json::from_str(&raw).context("解析 state.json 失败")?
        } else {
            State::default()
        };

        Ok(Self {
            path,
            _lock_file: lock_file,
            inner: Mutex::new(Inner {
                state,
                last_flush: Instant::now(),
            }),
            notifiers: Mutex::new(HashMap::new()),
            waiters: Mutex::new(HashMap::new()),
        })
    }

    fn save_locked(&self, inner: &mut Inner) -> Result<()> {
        let now = Utc::now();
        inner.state.commands.retain(|_, c| {
            let age = (now - c.created).num_seconds();
            if c.done {
                age < 600
            } else {
                age < 1800
            }
        });
        inner.state.tokens.retain(|_, t| {
            if t.used {
                now < t.expires
            } else {
                (now - t.expires).num_seconds() < 86_400
            }
        });
        let raw = serde_json::to_vec_pretty(&inner.state)?;
        write_atomic(&self.path, &raw, 0o600)?;
        inner.last_flush = Instant::now();
        Ok(())
    }

    pub fn snapshot_json(&self) -> Result<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        Ok(serde_json::to_vec_pretty(&inner.state)?)
    }

    pub fn active_machine_counts(&self) -> (usize, usize) {
        let inner = self.inner.lock().unwrap();
        let mut relays = 0usize;
        let mut landings = 0usize;
        for m in inner.state.machines.values() {
            if !m.revoked {
                match m.role {
                    Role::Relay => relays += 1,
                    Role::Landing => landings += 1,
                }
            }
        }
        (relays, landings)
    }

    pub fn owner(&self) -> i64 {
        self.inner.lock().unwrap().state.owner_id
    }

    pub fn tg_offset(&self) -> i64 {
        self.inner.lock().unwrap().state.tg_offset
    }

    pub fn set_tg_offset(&self, offset: i64) {
        let mut inner = self.inner.lock().unwrap();
        if offset > inner.state.tg_offset {
            inner.state.tg_offset = offset;
            let _ = self.save_locked(&mut inner);
        }
    }

    pub fn set_owner(&self, id: i64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.state.owner_id != 0 && inner.state.owner_id != id {
            bail!("已绑定其他管理员");
        }
        inner.state.owner_id = id;
        self.save_locked(&mut inner)
    }

    pub fn new_install_token(
        &self,
        name: &str,
        role: Role,
        ttl: Duration,
    ) -> Result<InstallToken> {
        let norm = normalize_name(name)?;
        let mut inner = self.inner.lock().unwrap();
        if name_taken(&inner.state, &norm, role, None) {
            bail!("已有{}叫「{}」，请换一个名字", role.cn(), norm);
        }
        let tok = InstallToken {
            token: rand_hex(16),
            name: norm,
            role,
            expires: Utc::now() + chrono::Duration::from_std(ttl).unwrap(),
            used: false,
        };
        inner.state.tokens.insert(tok.token.clone(), tok.clone());
        self.save_locked(&mut inner)?;
        Ok(tok)
    }

    pub fn consume_token(&self, token: &str) -> Result<Machine> {
        let mut inner = self.inner.lock().unwrap();
        let now = Utc::now();
        let Some(t) = inner.state.tokens.get_mut(token) else {
            bail!("注册令牌无效或已过期");
        };
        if t.used || now > t.expires {
            bail!("注册令牌无效或已过期");
        }
        t.used = true;
        let machine = Machine {
            id: rand_hex(8),
            name: t.name.clone(),
            role: t.role,
            secret: rand_hex(32),
            created: now,
            last_seen: None,
            status: None,
            revoked: false,
        };
        inner
            .state
            .machines
            .insert(machine.id.clone(), machine.clone());
        self.save_locked(&mut inner)?;
        Ok(machine)
    }

    pub fn machine(&self, id: &str) -> Option<Machine> {
        self.inner.lock().unwrap().state.machines.get(id).cloned()
    }

    pub fn machines_by_role(&self, role: Role) -> Vec<Machine> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<Machine> = inner
            .state
            .machines
            .values()
            .filter(|m| m.role == role && !m.revoked)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        out
    }

    pub fn rename_machine(&self, id: &str, new_name: &str) -> Result<Machine> {
        let norm = normalize_name(new_name)?;
        let mut inner = self.inner.lock().unwrap();
        let Some(existing) = inner.state.machines.get(id) else {
            bail!("找不到这台机器");
        };
        if existing.revoked {
            bail!("找不到这台机器");
        }
        let role = existing.role;
        if existing.name == norm {
            bail!("与当前名字相同，没有改动");
        }
        if name_taken(&inner.state, &norm, role, Some(id)) {
            bail!("已有{}叫「{}」，请换一个名字", role.cn(), norm);
        }
        let m = inner.state.machines.get_mut(id).unwrap();
        m.name = norm;
        let cloned = m.clone();
        self.save_locked(&mut inner)?;
        Ok(cloned)
    }

    pub fn revoke_machine(&self, id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let Some(m) = inner.state.machines.get_mut(id) else {
            bail!("找不到这台机器");
        };
        m.revoked = true;
        m.secret.clear();
        self.save_locked(&mut inner)
    }

    /// 更新心跳和上报状态。返回值表示该机器是否首次上报就绪节点（用于推送上线通知）。
    pub fn touch_status(&self, id: &str, status: Option<NodeStatus>) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(m) = inner.state.machines.get_mut(id) else {
            return false;
        };
        let was_ready = m
            .status
            .as_ref()
            .and_then(|s| s.node.as_ref())
            .is_some_and(|n| n.is_ready());
        let mut changed = m.last_seen.is_none();
        m.last_seen = Some(Utc::now());

        if let Some(st) = status {
            if m.status.as_ref() != Some(&st) {
                m.status = Some(st);
                changed = true;
            }
        }
        let now_ready = m
            .status
            .as_ref()
            .and_then(|s| s.node.as_ref())
            .is_some_and(|n| n.is_ready());

        if changed || inner.last_flush.elapsed() >= Duration::from_secs(15) {
            let _ = self.save_locked(&mut inner);
        }
        !was_ready && now_ready
    }

    fn notifier_for(&self, machine_id: &str) -> Arc<Notify> {
        let mut map = self.notifiers.lock().unwrap();
        map.entry(machine_id.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    /// 入队命令并立即唤醒正在长轮询的 Agent，返回等待结果的 oneshot。
    pub fn enqueue_cmd(
        &self,
        machine_id: &str,
        op: CommandOp,
    ) -> Result<(String, oneshot::Receiver<CommandResult>)> {
        let id = rand_hex(8);
        let cmd = PendingCmd {
            id: id.clone(),
            machine_id: machine_id.to_string(),
            op,
            created: Utc::now(),
            dispatched_at: None,
            done: false,
            result: None,
        };
        let (tx, rx) = oneshot::channel();
        {
            self.waiters.lock().unwrap().insert(id.clone(), tx);
            let mut inner = self.inner.lock().unwrap();
            inner.state.commands.insert(id.clone(), cmd);
            self.save_locked(&mut inner)?;
        }
        self.notifier_for(machine_id).notify_waiters();
        Ok((id, rx))
    }

    pub fn take_commands(&self, machine_id: &str) -> Vec<CommandEnvelope> {
        let mut inner = self.inner.lock().unwrap();
        let now = Utc::now();
        let mut out = Vec::new();
        for c in inner.state.commands.values_mut() {
            if c.done || c.machine_id != machine_id {
                continue;
            }
            if (now - c.created).num_seconds() >= 120 {
                continue;
            }
            if let Some(d) = c.dispatched_at {
                if (now - d).num_seconds() < 60 {
                    continue;
                }
            }
            c.dispatched_at = Some(now);
            out.push(CommandEnvelope {
                id: c.id.clone(),
                op: c.op.clone(),
            });
        }
        if !out.is_empty() {
            let _ = self.save_locked(&mut inner);
        }
        out
    }

    /// 长轮询取命令：有待执行命令立刻返回，否则最多等待 `wait` 直到被 `enqueue_cmd` 唤醒。
    pub async fn wait_for_commands(
        &self,
        machine_id: &str,
        wait: Duration,
    ) -> Vec<CommandEnvelope> {
        let notify = self.notifier_for(machine_id);
        let notified = notify.notified();
        let cmds = self.take_commands(machine_id);
        if !cmds.is_empty() {
            return cmds;
        }
        let _ = tokio::time::timeout(wait, notified).await;
        self.take_commands(machine_id)
    }

    pub fn finish_cmd(&self, machine_id: &str, cmd_id: &str, result: CommandResult) -> Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let Some(c) = inner.state.commands.get_mut(cmd_id) else {
                bail!("未知命令");
            };
            if c.machine_id != machine_id {
                bail!("无权提交该命令结果");
            }
            c.done = true;
            c.result = Some(result.clone());
            self.save_locked(&mut inner)?;
        }
        if let Some(tx) = self.waiters.lock().unwrap().remove(cmd_id) {
            let _ = tx.send(result);
        }
        Ok(())
    }

    pub fn cancel_cmd(&self, cmd_id: &str) {
        self.waiters.lock().unwrap().remove(cmd_id);
        let mut inner = self.inner.lock().unwrap();
        if let Some(c) = inner.state.commands.get_mut(cmd_id) {
            if !c.done {
                c.done = true;
                c.result = Some(CommandResult::err(c.op.name(), "timeout"));
                let _ = self.save_locked(&mut inner);
            }
        }
    }
}

pub fn normalize_name(raw: &str) -> Result<String> {
    let s = raw.trim();
    if s.is_empty() {
        bail!("名字不能为空，请输入 {NAME_HINT}");
    }
    if s.chars().any(|c| c.is_control()) {
        bail!("名字不能包含换行或控制字符，请输入 {NAME_HINT}");
    }
    let count = s.chars().count();
    if count > MAX_NAME_CHARS {
        bail!("名字太长（最多 {MAX_NAME_CHARS} 个字，当前 {count} 个）");
    }
    Ok(s.to_string())
}

fn name_taken(state: &State, name: &str, role: Role, except_id: Option<&str>) -> bool {
    let in_machines = state.machines.values().any(|m| {
        !m.revoked
            && m.role == role
            && except_id != Some(m.id.as_str())
            && m.name == name
    });
    if in_machines {
        return true;
    }
    let now = Utc::now();
    state
        .tokens
        .values()
        .any(|t| !t.used && t.role == role && now <= t.expires && t.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn token_machine_and_long_poll_flow() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());

        assert_eq!(store.owner(), 0);
        store.set_owner(1001).unwrap();
        assert!(store.set_owner(1002).is_err());

        let tok = store
            .new_install_token("香港线路", Role::Relay, Duration::from_secs(3600))
            .unwrap();
        assert!(store
            .new_install_token("香港线路", Role::Relay, Duration::from_secs(3600))
            .is_err());

        let m = store.consume_token(&tok.token).unwrap();
        assert_eq!(m.name, "香港线路");
        assert!(store.consume_token(&tok.token).is_err());

        let st_clone = store.clone();
        let mid = m.id.clone();
        let waiter = tokio::spawn(async move {
            st_clone
                .wait_for_commands(&mid, Duration::from_secs(5))
                .await
        });

        tokio::time::sleep(Duration::from_millis(40)).await;
        let (cid, rx) = store.enqueue_cmd(&m.id, CommandOp::Status).unwrap();
        let cmds = waiter.await.unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].id, cid);

        store
            .finish_cmd(
                &m.id,
                &cid,
                CommandResult {
                    ok: true,
                    op: "status".into(),
                    error: None,
                    from: None,
                    to: None,
                    backup: None,
                    status: None,
                },
            )
            .unwrap();
        let res = rx.await.unwrap();
        assert!(res.ok);
    }

    #[test]
    fn flock_blocks_second_open() {
        let dir = tempfile::tempdir().unwrap();
        let _s1 = Store::open(dir.path()).unwrap();
        assert!(Store::open(dir.path()).is_err());
    }

    #[test]
    fn tg_offset_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Store::open(dir.path()).unwrap();
            assert_eq!(s.tg_offset(), 0);
            s.set_tg_offset(12345);
            s.set_tg_offset(100); // 不允许倒退
            assert_eq!(s.tg_offset(), 12345);
        }
        let s2 = Store::open(dir.path()).unwrap();
        assert_eq!(s2.tg_offset(), 12345);
    }
}
