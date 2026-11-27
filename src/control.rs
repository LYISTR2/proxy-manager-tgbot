use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;

use crate::protocol::{
    verify_request, PollRequest, PollResponse, RegisterRequest, RegisterResponse, ResultRequest,
    TIME_WINDOW_SECS,
};
use crate::store::{Machine, Store};

const REG_FAIL_LIMIT: usize = 5;
const REG_FAIL_WINDOW: Duration = Duration::from_secs(60);

pub type NodeReadyHook = Arc<dyn Fn(String) + Send + Sync>;

pub struct ControlState {
    pub store: Arc<Store>,
    pub poll_wait: Duration,
    pub on_node_ready: Option<NodeReadyHook>,
    nonce_seen: Mutex<HashMap<String, i64>>,
    reg_fails: Mutex<HashMap<String, Vec<Instant>>>,
}

impl ControlState {
    pub fn new(store: Arc<Store>, on_node_ready: Option<NodeReadyHook>) -> Arc<Self> {
        Arc::new(Self {
            store,
            poll_wait: Duration::from_secs(25),
            on_node_ready,
            nonce_seen: Mutex::new(HashMap::new()),
            reg_fails: Mutex::new(HashMap::new()),
        })
    }

    fn allow_register(&self, ip: &str, now: Instant) -> bool {
        let mut map = self.reg_fails.lock().unwrap();
        prune_reg_fails(&mut map, now);
        map.get(ip).map_or(true, |v| v.len() < REG_FAIL_LIMIT)
    }

    fn record_register_fail(&self, ip: &str, now: Instant) {
        let mut map = self.reg_fails.lock().unwrap();
        prune_reg_fails(&mut map, now);
        map.entry(ip.to_string()).or_default().push(now);
    }

    fn accept_nonce(&self, machine_id: &str, ts: i64, nonce: &str, now: i64) -> bool {
        if machine_id.is_empty() || nonce.is_empty() {
            return false;
        }
        let key = format!("{machine_id}\0{nonce}");
        let mut map = self.nonce_seen.lock().unwrap();
        if map.len() > 512 || now % 32 == 0 {
            map.retain(|_, exp| *exp >= now);
        }
        if map.get(&key).is_some_and(|&exp| exp >= now) {
            return false;
        }
        let exp = (ts + TIME_WINDOW_SECS).max(now + TIME_WINDOW_SECS);
        map.insert(key, exp);
        true
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Machine, (StatusCode, &'static str)> {
        let mid = header_str(headers, "x-machine-id");
        let ts_s = header_str(headers, "x-ts");
        let nonce = header_str(headers, "x-nonce");
        let sig = header_str(headers, "x-sig");

        let Ok(ts) = ts_s.parse::<i64>() else {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
        };
        let Some(m) = self.store.machine(mid) else {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
        };
        let now = Utc::now().timestamp();
        if m.revoked || !verify_request(&m.secret, ts, nonce, body, sig, now) {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
        }
        if !self.accept_nonce(&m.id, ts, nonce, now) {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
        }
        Ok(m)
    }
}

fn prune_reg_fails(map: &mut HashMap<String, Vec<Instant>>, now: Instant) {
    map.retain(|_, v| {
        v.retain(|t| now.saturating_duration_since(*t) < REG_FAIL_WINDOW);
        !v.is_empty()
    });
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

pub fn router(state: Arc<ControlState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/register", post(handle_register))
        .route("/v1/poll", post(handle_poll))
        .route("/v1/result", post(handle_result))
        .with_state(state)
}

async fn handle_register(
    State(state): State<Arc<ControlState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    let ip = addr.ip().to_string();
    let now = Instant::now();
    if !state.allow_register(&ip, now) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed register attempts".into(),
        ));
    }
    if body.len() > 4096 {
        state.record_register_fail(&ip, now);
        return Err((StatusCode::BAD_REQUEST, "payload too large".into()));
    }
    let req: RegisterRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            state.record_register_fail(&ip, now);
            return Err((StatusCode::BAD_REQUEST, "bad json".into()));
        }
    };
    let m = match state.store.consume_token(req.token.trim()) {
        Ok(m) => m,
        Err(e) => {
            state.record_register_fail(&ip, now);
            return Err((StatusCode::FORBIDDEN, e.to_string()));
        }
    };
    Ok(Json(RegisterResponse {
        machine_id: m.id,
        secret: m.secret,
        name: m.name,
        role: m.role,
    }))
}

async fn handle_poll(
    State(state): State<Arc<ControlState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PollResponse>, (StatusCode, &'static str)> {
    if body.len() > 1 << 20 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "payload too large"));
    }
    let m = state.authenticate(&headers, &body)?;
    if let Ok(req) = serde_json::from_slice::<PollRequest>(&body) {
        let newly_ready = state.store.touch_status(&m.id, req.status);
        if newly_ready {
            if let Some(ref hook) = state.on_node_ready {
                hook(m.id.clone());
            }
        }
    } else {
        state.store.touch_status(&m.id, None);
    }

    let commands = state.store.wait_for_commands(&m.id, state.poll_wait).await;
    Ok(Json(PollResponse { commands }))
}

async fn handle_result(
    State(state): State<Arc<ControlState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if body.len() > 1 << 20 {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "payload too large".into()));
    }
    let m = state
        .authenticate(&headers, &body)
        .map_err(|(s, msg)| (s, msg.to_string()))?;
    let req: ResultRequest =
        serde_json::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, "bad json".into()))?;
    if req.id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing id".into()));
    }
    if let Some(ref st) = req.result.status {
        let newly_ready = state.store.touch_status(&m.id, Some(st.clone()));
        if newly_ready {
            if let Some(ref hook) = state.on_node_ready {
                hook(m.id.clone());
            }
        }
    }
    state
        .store
        .finish_cmd(&m.id, &req.id, req.result)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{sign_request, CommandOp, CommandResult, Role};
    use crate::tls::{build_pinned_client, build_server_tls, generate_self_signed};

    #[tokio::test]
    async fn end_to_end_register_auth_replay_and_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        let pin = generate_self_signed(&cert, &key, "127.0.0.1").unwrap();
        let tls = build_server_tls(&cert, &key).unwrap();

        let state = Arc::new(ControlState {
            store: store.clone(),
            poll_wait: Duration::from_millis(50),
            on_node_ready: None,
            nonce_seen: Mutex::new(HashMap::new()),
            reg_fails: Mutex::new(HashMap::new()),
        });
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

        let cli = build_pinned_client(&pin, Duration::from_secs(5)).unwrap();
        let base = format!("https://{addr}");

        // 1. 合法注册
        let tok = store
            .new_install_token("测试线路", Role::Relay, Duration::from_secs(300))
            .unwrap();
        let reg: RegisterResponse = cli
            .post(format!("{base}/v1/register"))
            .json(&RegisterRequest { token: tok.token })
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(reg.role, Role::Relay);

        // 2. 下发命令并长轮询接收
        let (cid, rx) = store.enqueue_cmd(&reg.machine_id, CommandOp::Status).unwrap();
        let body = serde_json::to_vec(&PollRequest { status: None }).unwrap();
        let ts = Utc::now().timestamp();
        let nonce = "fixednonce";
        let sig = sign_request(&reg.secret, ts, nonce, &body);

        let resp = cli
            .post(format!("{base}/v1/poll"))
            .header("Content-Type", "application/json")
            .header("X-Machine-Id", &reg.machine_id)
            .header("X-Ts", ts.to_string())
            .header("X-Nonce", nonce)
            .header("X-Sig", &sig)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let pr: PollResponse = resp.json().await.unwrap();
        assert_eq!(pr.commands.len(), 1);
        assert_eq!(pr.commands[0].id, cid);

        // 3. 同一 nonce 重放必须被 401 拒绝
        let replay = cli
            .post(format!("{base}/v1/poll"))
            .header("Content-Type", "application/json")
            .header("X-Machine-Id", &reg.machine_id)
            .header("X-Ts", ts.to_string())
            .header("X-Nonce", nonce)
            .header("X-Sig", &sig)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        // 4. 回传结果
        let res_body = serde_json::to_vec(&ResultRequest {
            id: cid,
            result: CommandResult {
                ok: true,
                op: "status".into(),
                error: None,
                from: None,
                to: None,
                backup: None,
                status: None,
            },
        })
        .unwrap();
        let sig2 = sign_request(&reg.secret, ts, "nonce2", &res_body);
        let rresp = cli
            .post(format!("{base}/v1/result"))
            .header("Content-Type", "application/json")
            .header("X-Machine-Id", &reg.machine_id)
            .header("X-Ts", ts.to_string())
            .header("X-Nonce", "nonce2")
            .header("X-Sig", sig2)
            .body(res_body)
            .send()
            .await
            .unwrap();
        assert_eq!(rresp.status(), StatusCode::OK);
        assert!(rx.await.unwrap().ok);

        // 5. 注册失败限流（5 次后返回 429）
        for _ in 0..REG_FAIL_LIMIT {
            let r = cli
                .post(format!("{base}/v1/register"))
                .json(&RegisterRequest {
                    token: "wrong".into(),
                })
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::FORBIDDEN);
        }
        let limited = cli
            .post(format!("{base}/v1/register"))
            .json(&RegisterRequest {
                token: "wrong".into(),
            })
            .send()
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        handle.shutdown();
    }
}
