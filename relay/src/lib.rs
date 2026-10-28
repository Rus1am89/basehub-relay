//! Ретранслятор Basehub Remote.
//!
//! Держит в памяти, кто сейчас в сети (id → соединение), и пересылает конверты `send` → `recv`.
//! Содержимое зашифровано между телефоном и ПК — ретранслятор видит только id и размер.
//! На диск ничего не пишет; в журнал — только подключения и отказы, без данных.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use rand_core::RngCore;
use remote_proto::pair::{Invite, INVITE_TTL_SECS};
use remote_proto::relay::{encode_bytes, Relay, Role};
use tokio::sync::mpsc;

#[derive(Clone, Debug)]
pub struct Config {
    /// Брать IP клиента из X-Forwarded-For (за обратным прокси).
    pub trust_proxy: bool,
    pub max_conn_per_ip: usize,
    /// Предел кадра WebSocket: кусок канала 65 КБ в base64 + конверт.
    pub max_frame: usize,
    /// Тишина дольше — соединение закрывается (клиенты шлют ping раз в 30 с).
    pub idle: Duration,
    pub msgs_per_sec: u32,
    /// Неудачных `invite_get` за соединение.
    pub max_invite_misses: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            trust_proxy: false,
            max_conn_per_ip: 20,
            max_frame: 128 * 1024,
            idle: Duration::from_secs(90),
            msgs_per_sec: 200,
            max_invite_misses: 5,
        }
    }
}

struct Peer {
    conn: u64,
    tx: mpsc::UnboundedSender<Relay>,
}

struct Pending {
    invite: Invite,
    owner: String,
    until: Instant,
}

#[derive(Default)]
struct Hub {
    peers: HashMap<String, Peer>,
    /// id → кто за ним следит.
    watchers: HashMap<String, HashSet<String>>,
    invites: HashMap<String, Pending>,
    per_ip: HashMap<IpAddr, usize>,
    next_conn: u64,
}

impl Hub {
    fn presence(&self, id: &str, online: bool) {
        if let Some(ws) = self.watchers.get(id) {
            for w in ws {
                if let Some(p) = self.peers.get(w) {
                    let _ = p.tx.send(Relay::Presence { id: id.to_string(), online });
                }
            }
        }
    }

    fn purge_invites(&mut self) {
        let now = Instant::now();
        self.invites.retain(|_, p| p.until > now);
    }
}

struct Shared {
    hub: Mutex<Hub>,
    cfg: Config,
}

pub fn router(cfg: Config) -> Router {
    let st = Arc::new(Shared { hub: Mutex::new(Hub::default()), cfg });
    Router::new().route("/v1/ws", get(ws_handler)).route("/health", get(|| async { "ok" })).with_state(st)
}

/// Запустить на готовом слушателе (для main и тестов).
pub async fn serve(listener: tokio::net::TcpListener, cfg: Config, shutdown: impl std::future::Future<Output = ()> + Send + 'static) -> std::io::Result<()> {
    axum::serve(listener, router(cfg).into_make_service_with_connect_info::<SocketAddr>()).with_graceful_shutdown(shutdown).await
}

fn client_ip(headers: &HeaderMap, addr: SocketAddr, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    addr.ip()
}

async fn ws_handler(ws: WebSocketUpgrade, State(st): State<Arc<Shared>>, ConnectInfo(addr): ConnectInfo<SocketAddr>, headers: HeaderMap) -> impl IntoResponse {
    let ip = client_ip(&headers, addr, st.cfg.trust_proxy);
    let max = st.cfg.max_frame;
    ws.max_message_size(max).max_frame_size(max).on_upgrade(move |socket| session(socket, st, ip))
}

/// Освобождает место IP при выходе из сеанса.
struct IpSlot {
    st: Arc<Shared>,
    ip: IpAddr,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut h = self.st.hub.lock().unwrap();
        if let Some(n) = h.per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                h.per_ip.remove(&self.ip);
            }
        }
    }
}

async fn send(ws: &mut WebSocket, m: &Relay) -> bool {
    ws.send(Message::Text(m.to_text())).await.is_ok()
}

async fn next_text(ws: &mut WebSocket) -> Option<String> {
    loop {
        match ws.recv().await? {
            Ok(Message::Text(t)) => return Some(t),
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => continue,
            _ => return None,
        }
    }
}

/// Вход: hello → challenge → auth. Возвращает id и роль.
async fn authenticate(ws: &mut WebSocket) -> Result<(String, Role), Relay> {
    let bad = || Relay::error("bad_request", "ожидался вход");
    let (id, pk, role) = match next_text(ws).await.map(|t| Relay::from_text(&t)) {
        Some(Ok(Relay::Hello { id, pk, role, proto })) => {
            if proto != remote_proto::PROTOCOL {
                return Err(Relay::error("protocol", "версия протокола не поддерживается — обновите приложение"));
            }
            (id, pk, role)
        }
        _ => return Err(bad()),
    };
    let mut nonce = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut nonce);
    if !send(ws, &Relay::Challenge { n: encode_bytes(&nonce) }).await {
        return Err(bad());
    }
    match next_text(ws).await.map(|t| Relay::from_text(&t)) {
        Some(Ok(Relay::Auth { sig })) if remote_proto::identity::verify_auth(&id, &pk, &nonce, &sig) => Ok((id, role)),
        _ => Err(Relay::error("auth", "подпись не прошла проверку")),
    }
}

async fn session(mut ws: WebSocket, st: Arc<Shared>, ip: IpAddr) {
    let admitted = {
        let mut h = st.hub.lock().unwrap();
        let n = h.per_ip.entry(ip).or_default();
        *n += 1;
        *n <= st.cfg.max_conn_per_ip
    };
    // место занято в любом случае — освободит IpSlot
    let _slot = IpSlot { st: st.clone(), ip };
    if !admitted {
        let _ = send(&mut ws, &Relay::error("too_many", "слишком много соединений с одного адреса")).await;
        return;
    }
    let (id, role) = match tokio::time::timeout(Duration::from_secs(15), authenticate(&mut ws)).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let _ = send(&mut ws, &e).await;
            println!("{ip} вход отклонён");
            return;
        }
        Err(_) => return,
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Relay>();
    let conn = {
        let mut h = st.hub.lock().unwrap();
        h.next_conn += 1;
        let conn = h.next_conn;
        // повторный вход того же устройства вытесняет старое соединение (его rx закроется)
        h.peers.insert(id.clone(), Peer { conn, tx });
        h.presence(&id, true);
        conn
    };
    println!("{ip} {id} {role:?} в сети");
    if !send(&mut ws, &Relay::Ready).await {
        cleanup(&st, &id, conn);
        return;
    }

    let mut window = Instant::now();
    let mut count = 0u32;
    let mut misses = 0u32;
    loop {
        tokio::select! {
            incoming = tokio::time::timeout(st.cfg.idle, next_text(&mut ws)) => {
                let Ok(Some(text)) = incoming else { break };
                if window.elapsed() >= Duration::from_secs(1) {
                    window = Instant::now();
                    count = 0;
                }
                count += 1;
                if count > st.cfg.msgs_per_sec {
                    let _ = send(&mut ws, &Relay::error("rate", "слишком много сообщений")).await;
                    break;
                }
                let msg = match Relay::from_text(&text) {
                    Ok(m) => m,
                    Err(_) => { let _ = send(&mut ws, &Relay::error("bad_request", "непонятный кадр")).await; continue; }
                };
                let replies = handle(&st, &id, role, msg, &mut misses);
                let mut ok = true;
                for r in &replies {
                    ok &= send(&mut ws, r).await;
                }
                if !ok || misses > st.cfg.max_invite_misses {
                    break;
                }
            }
            out = rx.recv() => match out {
                Some(m) => if !send(&mut ws, &m).await { break },
                None => break, // вытеснено новым входом
            },
        }
    }
    cleanup(&st, &id, conn);
    println!("{ip} {id} отключился");
}

fn cleanup(st: &Shared, id: &str, conn: u64) {
    let mut h = st.hub.lock().unwrap();
    if h.peers.get(id).map(|p| p.conn) == Some(conn) {
        h.peers.remove(id);
        h.presence(id, false);
        for set in h.watchers.values_mut() {
            set.remove(id);
        }
        h.watchers.retain(|_, s| !s.is_empty());
        h.invites.retain(|_, p| p.owner != id);
    }
}

fn handle(st: &Shared, me: &str, role: Role, msg: Relay, misses: &mut u32) -> Vec<Relay> {
    let mut h = st.hub.lock().unwrap();
    match msg {
        Relay::Send { to, data } => match h.peers.get(&to) {
            Some(p) => {
                let _ = p.tx.send(Relay::Recv { from: me.to_string(), data });
                vec![]
            }
            None => vec![Relay::Offline { id: to }],
        },
        Relay::Watch { ids } => {
            if ids.len() > 50 {
                return vec![Relay::error("bad_request", "не больше 50 устройств")];
            }
            ids.into_iter()
                .map(|w| {
                    h.watchers.entry(w.clone()).or_default().insert(me.to_string());
                    let online = h.peers.contains_key(&w);
                    Relay::Presence { id: w, online }
                })
                .collect()
        }
        Relay::InvitePut { key, invite } => {
            if role != Role::Agent || invite.agent != me {
                return vec![Relay::error("forbidden", "приглашение может создать только сам компьютер")];
            }
            if key.len() != 4 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return vec![Relay::error("bad_request", "неверный номер приглашения")];
            }
            h.purge_invites();
            h.invites.retain(|_, p| p.owner != me);
            let until = Instant::now() + Duration::from_secs(INVITE_TTL_SECS);
            h.invites.insert(key, Pending { invite, owner: me.to_string(), until });
            vec![]
        }
        Relay::InviteGet { key } => {
            h.purge_invites();
            match h.invites.remove(&key) {
                Some(p) => vec![Relay::Invite { key, invite: p.invite }],
                None => {
                    *misses += 1;
                    vec![Relay::error("invite_not_found", "код не найден или устарел — получите новый на компьютере")]
                }
            }
        }
        Relay::Ping => vec![Relay::Pong],
        _ => vec![Relay::error("bad_request", "неожиданный кадр")],
    }
}
