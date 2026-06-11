use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::RwLock;

mod oui;
mod scanner;
mod storage;

const NEW_WINDOW_SECS: u64 = 24 * 3600;
const OFFLINE_WINDOW_SECS: u64 = 7 * 24 * 3600;

#[derive(Clone, Serialize)]
struct Device {
    ip: String,
    mac: Option<String>,
    vendor: Option<String>,
    hostname: Option<String>,
    title: Option<String>,
    label: Option<String>,
    notes: Option<String>,
    open_ports: Vec<u16>,
    rtt_ms: Option<u32>,
    ttl: Option<u8>,
    os_guess: Option<String>,
    sources: Vec<String>,
    last_seen: String,
    first_seen_epoch: Option<u64>,
    last_seen_epoch: Option<u64>,
    times_seen: u64,
    online: bool,
    is_new: bool,
}

#[derive(Deserialize)]
struct LabelReq {
    mac: String,
    label: Option<String>,
}

#[derive(Deserialize)]
struct NotesReq {
    mac: String,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct LoginReq {
    password: String,
}

const SESSION_COOKIE: &str = "lansight_session";
const SESSION_MAX_AGE: u64 = 30 * 24 * 3600;

struct AuthConfig {
    password: Option<String>,
    cookie_secure: bool,
}

impl AuthConfig {
    fn enabled(&self) -> bool {
        self.password.is_some()
    }
}

#[derive(Clone, Serialize)]
struct ScanState {
    local_ip: String,
    subnet: String,
    devices: Vec<Device>,
    last_scan: String,
    scanning: bool,
}

type SharedState = Arc<RwLock<ScanState>>;
type SharedDb = Arc<RwLock<storage::Database>>;
type SharedSessions = Arc<RwLock<HashSet<String>>>;

#[derive(Clone)]
struct AppState {
    state: SharedState,
    db: SharedDb,
    db_path: PathBuf,
    auth: Arc<AuthConfig>,
    sessions: SharedSessions,
}

fn format_ago(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s lalu", seconds)
    } else if seconds < 3600 {
        format!("{}m lalu", seconds / 60)
    } else if seconds < 86400 {
        format!("{}j lalu", seconds / 3600)
    } else {
        format!("{}h lalu", seconds / 86400)
    }
}

fn merge_with_history(
    mut live: Vec<Device>,
    db: &mut storage::Database,
    now: u64,
) -> Vec<Device> {
    let mut online_macs: HashSet<String> = HashSet::new();

    for d in live.iter_mut() {
        d.online = true;
        d.last_seen_epoch = Some(now);
        let Some(mac) = d.mac.clone() else { continue };
        online_macs.insert(mac.clone());

        let rec = db.devices.entry(mac).or_insert_with(|| storage::DeviceRecord {
            first_seen: now,
            last_seen: now,
            times_seen: 0,
            ip: d.ip.clone(),
            vendor: d.vendor.clone(),
            hostname: d.hostname.clone(),
            label: None,
            notes: None,
            os_guess: None,
            presence_events: vec![],
        });
        rec.last_seen = now;
        rec.times_seen += 1;
        rec.ip = d.ip.clone();
        if d.vendor.is_some() {
            rec.vendor = d.vendor.clone();
        }
        if d.hostname.is_some() {
            rec.hostname = d.hostname.clone();
        }
        // Persist a fresh OS guess; otherwise carry the last known one onto the live row.
        if d.os_guess.is_some() {
            rec.os_guess = d.os_guess.clone();
        } else {
            d.os_guess = rec.os_guess.clone();
        }
        rec.push_presence(now, true);

        d.first_seen_epoch = Some(rec.first_seen);
        d.times_seen = rec.times_seen;
        d.is_new = now.saturating_sub(rec.first_seen) < NEW_WINDOW_SECS;
        d.label = rec.label.clone();
        d.notes = rec.notes.clone();
    }

    let offline_macs: Vec<String> = db
        .devices
        .iter()
        .filter(|(mac, _)| !online_macs.contains(*mac))
        .map(|(mac, _)| mac.clone())
        .collect();
    for mac in offline_macs {
        if let Some(rec) = db.devices.get_mut(&mac) {
            rec.push_presence(now, false);
        }
    }

    for (mac, rec) in db.devices.iter() {
        if online_macs.contains(mac) {
            continue;
        }
        let age = now.saturating_sub(rec.last_seen);
        if age > OFFLINE_WINDOW_SECS {
            continue;
        }
        live.push(Device {
            ip: rec.ip.clone(),
            mac: Some(mac.clone()),
            vendor: rec.vendor.clone(),
            hostname: rec.hostname.clone(),
            title: None,
            label: rec.label.clone(),
            notes: rec.notes.clone(),
            open_ports: vec![],
            rtt_ms: None,
            ttl: None,
            os_guess: rec.os_guess.clone(),
            sources: vec![],
            last_seen: format_ago(age),
            first_seen_epoch: Some(rec.first_seen),
            last_seen_epoch: Some(rec.last_seen),
            times_seen: rec.times_seen,
            online: false,
            is_new: false,
        });
    }

    live
}

#[tokio::main]
async fn main() {
    let local_ip = match local_ip_address::local_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => "127.0.0.1".to_string(),
    };
    let subnet = scanner::detect_subnet(&local_ip);

    let db_path = storage::data_path();
    let db: SharedDb = Arc::new(RwLock::new(storage::load(&db_path)));

    println!("Local IP: {}", local_ip);
    println!("Subnet:   {}", subnet);
    println!("DB path:  {}", db_path.display());
    println!("DB size:  {} known devices", db.read().await.devices.len());

    let state: SharedState = Arc::new(RwLock::new(ScanState {
        local_ip: local_ip.clone(),
        subnet: subnet.clone(),
        devices: vec![],
        last_scan: "never".to_string(),
        scanning: false,
    }));

    let scan_state = state.clone();
    let scan_db = db.clone();
    let scan_db_path = db_path.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        loop {
            ticker.tick().await;
            {
                let mut s = scan_state.write().await;
                s.scanning = true;
            }

            let raw = scanner::scan_subnet(&subnet).await;
            let live: Vec<Device> = raw
                .into_iter()
                .map(|d| Device {
                    ip: d.ip,
                    mac: d.mac,
                    vendor: d.vendor,
                    hostname: d.hostname,
                    title: d.title,
                    label: None,
                    notes: None,
                    open_ports: d.open_ports,
                    rtt_ms: d.rtt_ms,
                    ttl: d.ttl,
                    os_guess: d.os_guess,
                    sources: d.sources,
                    last_seen: d.last_seen,
                    first_seen_epoch: None,
                    last_seen_epoch: None,
                    times_seen: 0,
                    online: true,
                    is_new: false,
                })
                .collect();

            let now = storage::now_epoch();
            let merged = {
                let mut db_w = scan_db.write().await;
                let m = merge_with_history(live, &mut db_w, now);
                m
            };

            let snapshot = scan_db.read().await.clone();
            let save_path = scan_db_path.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = storage::save(&save_path, &snapshot) {
                    eprintln!("warning: failed to save device DB: {}", e);
                }
            });

            {
                let mut s = scan_state.write().await;
                s.devices = merged;
                s.last_scan = scanner::now_str();
                s.scanning = false;
            }
        }
    });

    let auth = Arc::new(AuthConfig {
        password: std::env::var("LANSIGHT_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty()),
        cookie_secure: std::env::var("LANSIGHT_COOKIE_SECURE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
    });
    let sessions: SharedSessions = Arc::new(RwLock::new(HashSet::new()));
    println!(
        "Auth:     {}",
        if auth.enabled() {
            "ON (password required)"
        } else {
            "OFF (set LANSIGHT_PASSWORD to require login)"
        }
    );

    let app_state = AppState {
        state: state.clone(),
        db: db.clone(),
        db_path: db_path.clone(),
        auth: auth.clone(),
        sessions: sessions.clone(),
    };

    let protected = Router::new()
        .route("/", get(index))
        .route("/api/devices", get(api_devices))
        .route("/api/device/:mac", get(api_device_detail))
        .route("/api/label", post(api_set_label))
        .route("/api/notes", post(api_set_notes))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_auth,
        ));

    let public = Router::new()
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        .route("/favicon.svg", get(favicon))
        .route("/icon.svg", get(favicon))
        .route("/manifest.webmanifest", get(manifest));

    let app = protected.merge(public).with_state(app_state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("\nDashboard ready at http://localhost:{}", port);
    println!("Or from another device: http://{}:{}\n", local_ip, port);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("\nERROR: cannot bind to port {}: {}", port, e);
            eprintln!("Hint: port may be in use. Set PORT env var to a different value.");
            std::process::exit(1);
        }
    };
    axum::serve(listener, app).await.unwrap();
}

// Constant-time byte compare — avoids leaking the password via reply-time differences.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// 32 random bytes from the OS RNG, hex-encoded. Session tokens are independent of the
// password, so a leaked cookie never reveals the password.
fn new_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn set_cookie_header(token: &str, secure: bool) -> String {
    let mut c = format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        SESSION_COOKIE, token, SESSION_MAX_AGE
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_cookie_header(secure: bool) -> String {
    let mut c = format!("{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0", SESSION_COOKIE);
    if secure {
        c.push_str("; Secure");
    }
    c
}

async fn require_auth(State(app): State<AppState>, req: Request, next: Next) -> Response {
    if !app.auth.enabled() {
        return next.run(req).await;
    }
    let valid = match cookie_value(req.headers(), SESSION_COOKIE) {
        Some(t) => app.sessions.read().await.contains(&t),
        None => false,
    };
    if valid {
        return next.run(req).await;
    }
    if req.uri().path().starts_with("/api") {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn login_page(State(app): State<AppState>, headers: HeaderMap) -> Response {
    if !app.auth.enabled() {
        return Redirect::to("/").into_response();
    }
    if let Some(t) = cookie_value(&headers, SESSION_COOKIE) {
        if app.sessions.read().await.contains(&t) {
            return Redirect::to("/").into_response();
        }
    }
    Html(include_str!("login.html")).into_response()
}

async fn login_submit(State(app): State<AppState>, Form(req): Form<LoginReq>) -> Response {
    let Some(expected) = app.auth.password.as_ref() else {
        return Redirect::to("/").into_response();
    };
    if ct_eq(req.password.as_bytes(), expected.as_bytes()) {
        let token = new_token();
        app.sessions.write().await.insert(token.clone());
        let cookie = set_cookie_header(&token, app.auth.cookie_secure);
        ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
    } else {
        // Slow down brute-force guessing on a tiny single-password gate.
        tokio::time::sleep(Duration::from_millis(500)).await;
        Redirect::to("/login?e=1").into_response()
    }
}

async fn logout(State(app): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = cookie_value(&headers, SESSION_COOKIE) {
        app.sessions.write().await.remove(&t);
    }
    let cookie = clear_cookie_header(app.auth.cookie_secure);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/login")).into_response()
}

async fn index() -> Html<&'static str> {
    Html(include_str!("index.html"))
}

async fn api_devices(State(app): State<AppState>) -> Json<ScanState> {
    let s = app.state.read().await;
    Json(s.clone())
}

async fn api_set_label(
    State(app): State<AppState>,
    Json(req): Json<LabelReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mac = req.mac.trim().to_ascii_lowercase();
    if mac.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let new_label = req
        .label
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    {
        let mut db_w = app.db.write().await;
        let rec = db_w
            .devices
            .entry(mac.clone())
            .or_insert_with(|| storage::DeviceRecord {
                first_seen: storage::now_epoch(),
                last_seen: storage::now_epoch(),
                times_seen: 0,
                ip: String::new(),
                vendor: None,
                hostname: None,
                label: None,
                notes: None,
                os_guess: None,
                presence_events: vec![],
            });
        rec.label = new_label.clone();
    }

    {
        let mut s = app.state.write().await;
        for d in s.devices.iter_mut() {
            if d.mac.as_deref().map(|m| m.eq_ignore_ascii_case(&mac)) == Some(true) {
                d.label = new_label.clone();
            }
        }
    }

    let snapshot = app.db.read().await.clone();
    let path = app.db_path.clone();
    tokio::task::spawn_blocking(move || {
        let _ = storage::save(&path, &snapshot);
    });

    Ok(Json(serde_json::json!({ "ok": true, "label": new_label })))
}

async fn api_set_notes(
    State(app): State<AppState>,
    Json(req): Json<NotesReq>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mac = req.mac.trim().to_ascii_lowercase();
    if mac.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let new_notes = req
        .notes
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    {
        let mut db_w = app.db.write().await;
        let rec = db_w
            .devices
            .entry(mac.clone())
            .or_insert_with(|| storage::DeviceRecord {
                first_seen: storage::now_epoch(),
                last_seen: storage::now_epoch(),
                times_seen: 0,
                ip: String::new(),
                vendor: None,
                hostname: None,
                label: None,
                notes: None,
                os_guess: None,
                presence_events: vec![],
            });
        rec.notes = new_notes.clone();
    }

    {
        let mut s = app.state.write().await;
        for d in s.devices.iter_mut() {
            if d.mac.as_deref().map(|m| m.eq_ignore_ascii_case(&mac)) == Some(true) {
                d.notes = new_notes.clone();
            }
        }
    }

    let snapshot = app.db.read().await.clone();
    let path = app.db_path.clone();
    tokio::task::spawn_blocking(move || {
        let _ = storage::save(&path, &snapshot);
    });

    Ok(Json(serde_json::json!({ "ok": true, "notes": new_notes })))
}

async fn api_device_detail(
    State(app): State<AppState>,
    Path(mac): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mac_key = mac.trim().to_ascii_lowercase();
    let db = app.db.read().await;
    let rec = db.devices.get(&mac_key).ok_or(StatusCode::NOT_FOUND)?;

    let live = app.state.read().await;
    let current = live
        .devices
        .iter()
        .find(|d| {
            d.mac
                .as_deref()
                .map(|m| m.eq_ignore_ascii_case(&mac_key))
                == Some(true)
        })
        .cloned();

    let same_vendor_count = if let Some(v) = &rec.vendor {
        db.devices
            .values()
            .filter(|r| r.vendor.as_deref() == Some(v.as_str()))
            .count()
    } else {
        0
    };

    Ok(Json(serde_json::json!({
        "mac": mac_key,
        "record": rec,
        "current": current,
        "same_vendor_count": same_vendor_count,
        "now": storage::now_epoch(),
    })))
}

async fn favicon() -> impl axum::response::IntoResponse {
    (
        [
            ("content-type", "image/svg+xml"),
            ("cache-control", "public, max-age=86400"),
        ],
        include_str!("logo.svg"),
    )
}

async fn manifest() -> impl axum::response::IntoResponse {
    (
        [("content-type", "application/manifest+json")],
        include_str!("manifest.webmanifest"),
    )
}
