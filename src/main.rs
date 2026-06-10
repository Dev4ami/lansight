use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
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

#[derive(Clone)]
struct AppState {
    state: SharedState,
    db: SharedDb,
    db_path: PathBuf,
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

    let app_state = AppState {
        state: state.clone(),
        db: db.clone(),
        db_path: db_path.clone(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/devices", get(api_devices))
        .route("/api/device/:mac", get(api_device_detail))
        .route("/api/label", post(api_set_label))
        .route("/api/notes", post(api_set_notes))
        .route("/favicon.svg", get(favicon))
        .route("/icon.svg", get(favicon))
        .route("/manifest.webmanifest", get(manifest))
        .with_state(app_state);

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
