use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_PRESENCE_EVENTS: usize = 200;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PresenceEvent {
    pub ts: u64,
    pub online: bool,
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct DeviceRecord {
    pub first_seen: u64,
    pub last_seen: u64,
    pub times_seen: u64,
    pub ip: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub os_guess: Option<String>,
    #[serde(default)]
    pub presence_events: Vec<PresenceEvent>,
}

impl DeviceRecord {
    pub fn last_known_online(&self) -> Option<bool> {
        self.presence_events.last().map(|e| e.online)
    }

    pub fn push_presence(&mut self, ts: u64, online: bool) {
        if self.last_known_online() == Some(online) {
            return;
        }
        self.presence_events.push(PresenceEvent { ts, online });
        if self.presence_events.len() > MAX_PRESENCE_EVENTS {
            let drop = self.presence_events.len() - MAX_PRESENCE_EVENTS;
            self.presence_events.drain(0..drop);
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct Database {
    pub devices: HashMap<String, DeviceRecord>,
}

pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn data_path() -> PathBuf {
    let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    PathBuf::from(dir).join("devices.json")
}

pub fn load(path: &Path) -> Database {
    match fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Database::default(),
    }
}

pub fn save(path: &Path, db: &Database) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(db)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
