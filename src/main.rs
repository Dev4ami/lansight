use axum::{
    extract::State,
    response::{Html, Json},
    routing::get,
    Router,
};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::RwLock;

mod oui;
mod scanner;

#[derive(Clone, Serialize)]
struct Device {
    ip: String,
    mac: Option<String>,
    vendor: Option<String>,
    hostname: Option<String>,
    title: Option<String>,
    open_ports: Vec<u16>,
    sources: Vec<String>,
    last_seen: String,
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

#[tokio::main]
async fn main() {
    let local_ip = match local_ip_address::local_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => "127.0.0.1".to_string(),
    };
    let subnet = scanner::detect_subnet(&local_ip);

    println!("Local IP: {}", local_ip);
    println!("Subnet:   {}", subnet);

    let state: SharedState = Arc::new(RwLock::new(ScanState {
        local_ip: local_ip.clone(),
        subnet: subnet.clone(),
        devices: vec![],
        last_scan: "never".to_string(),
        scanning: false,
    }));

    // Background scan task: polls every 20 seconds
    let scan_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(20));
        loop {
            ticker.tick().await;
            {
                let mut s = scan_state.write().await;
                s.scanning = true;
            }
            let devices = scanner::scan_subnet(&subnet).await;
            {
                let mut s = scan_state.write().await;
                s.devices = devices;
                s.last_scan = scanner::now_str();
                s.scanning = false;
            }
        }
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/devices", get(api_devices))
        .with_state(state);

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

async fn api_devices(State(state): State<SharedState>) -> Json<ScanState> {
    let s = state.read().await;
    Json(s.clone())
}
