use crate::Device;
use futures::stream::{FuturesUnordered, StreamExt};
use std::{
    collections::HashMap,
    io::ErrorKind,
    net::SocketAddr,
    process::Command,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

// Expanded TCP probe list
const PROBE_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 631, 993, 995, 1883, 3306, 3389, 5000, 5555,
    5900, 7000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9100, 32400,
];
const HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8888, 8008, 8081, 5000, 7000, 32400];
const PROBE_TIMEOUT_MS: u64 = 350;
const HTTP_TIMEOUT_MS: u64 = 700;
const UDP_TIMEOUT_MS: u64 = 600;
const CONCURRENCY: usize = 48;

pub fn detect_subnet(local_ip: &str) -> String {
    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        "192.168.1.0/24".to_string()
    }
}

pub fn now_str() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + 7 * 3600;
    let h = (now / 3600) % 24;
    let m = (now / 60) % 60;
    let s = now % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

pub async fn scan_subnet(subnet: &str) -> Vec<Device> {
    let prefix = subnet
        .split('/')
        .next()
        .and_then(|s| {
            let p: Vec<&str> = s.split('.').collect();
            if p.len() == 4 {
                Some(format!("{}.{}.{}", p[0], p[1], p[2]))
            } else {
                None
            }
        })
        .unwrap_or_else(|| "192.168.1".to_string());

    let arp_table = read_arp_table();

    // Run broadcast UDP discovery concurrently
    let mdns_handle = tokio::spawn(mdns_discover());
    let ssdp_handle = tokio::spawn(ssdp_discover());

    let mut tasks = FuturesUnordered::new();
    let mut alive: HashMap<String, ProbeResult> = HashMap::new();
    let mut host_iter = 1u32..255u32;
    let mut active = 0usize;
    let now = now_str();

    loop {
        while active < CONCURRENCY {
            if let Some(host) = host_iter.next() {
                let ip = format!("{}.{}", prefix, host);
                tasks.push(probe_host(ip));
                active += 1;
            } else {
                break;
            }
        }
        if active == 0 {
            break;
        }
        if let Some(result) = tasks.next().await {
            active -= 1;
            if let Some(res) = result {
                alive.insert(res.ip.clone(), res);
            }
        }
    }

    // Merge UDP broadcast results
    let mdns_ips = mdns_handle.await.unwrap_or_default();
    let ssdp_ips = ssdp_handle.await.unwrap_or_default();

    for (ip, hostname) in mdns_ips {
        let entry = alive.entry(ip.clone()).or_insert_with(|| ProbeResult {
            ip,
            open_ports: vec![],
            title: None,
            sources: vec![],
            mac: None,
        });
        if !entry.sources.iter().any(|s| s == "mdns") {
            entry.sources.push("mdns".to_string());
        }
        if entry.title.is_none() && hostname.is_some() {
            entry.title = hostname;
        }
    }

    for (ip, server, ssdp_mac) in ssdp_ips {
        let entry = alive.entry(ip.clone()).or_insert_with(|| ProbeResult {
            ip,
            open_ports: vec![],
            title: None,
            sources: vec![],
            mac: None,
        });
        if !entry.sources.iter().any(|s| s == "ssdp") {
            entry.sources.push("ssdp".to_string());
        }
        if entry.title.is_none() && server.is_some() {
            entry.title = server;
        }
        if entry.mac.is_none() && ssdp_mac.is_some() {
            entry.mac = ssdp_mac;
        }
    }

    // Build Devices — MAC priority: ARP > SSDP-uuid > NBSTAT
    let mut devices: Vec<Device> = alive
        .into_iter()
        .map(|(ip, r)| {
            let mac = arp_table.get(&ip).cloned().or(r.mac);
            let vendor = mac.as_deref().and_then(crate::oui::lookup);
            let hostname = reverse_dns(&ip);
            Device {
                ip,
                mac,
                vendor,
                hostname,
                title: r.title,
                open_ports: r.open_ports,
                sources: r.sources,
                last_seen: now.clone(),
            }
        })
        .collect();

    devices.sort_by(|a, b| ip_sort_key(&a.ip).cmp(&ip_sort_key(&b.ip)));
    devices
}

struct ProbeResult {
    ip: String,
    open_ports: Vec<u16>,
    title: Option<String>,
    sources: Vec<String>,
    mac: Option<String>,
}

fn ip_sort_key(ip: &str) -> u32 {
    ip.split('.')
        .last()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

async fn probe_host(ip: String) -> Option<ProbeResult> {
    let mut open_ports = Vec::new();
    let mut alive_by_rst = false;

    for &port in PROBE_PORTS {
        let addr: SocketAddr = match format!("{}:{}", ip, port).parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        let connect = TcpStream::connect(addr);
        match timeout(Duration::from_millis(PROBE_TIMEOUT_MS), connect).await {
            Ok(Ok(_)) => open_ports.push(port),
            Ok(Err(e)) => {
                // ECONNREFUSED = host alive but port closed (RST received)
                if e.kind() == ErrorKind::ConnectionRefused {
                    alive_by_rst = true;
                }
            }
            Err(_) => {} // timeout
        }
    }

    // Try NetBIOS UDP probe (for Windows hosts)
    let (netbios_responded, netbios_mac) = netbios_probe(&ip).await;

    let mut sources: Vec<String> = open_ports.iter().map(|p| format!("tcp:{}", p)).collect();
    if alive_by_rst {
        sources.push("tcp-rst".to_string());
    }
    if netbios_responded {
        sources.push("netbios".to_string());
    }

    if sources.is_empty() {
        return None;
    }

    // HTTP title
    let mut title: Option<String> = None;
    for &port in &open_ports {
        if HTTP_PORTS.contains(&port) {
            if let Some(t) = fetch_http_title(&ip, port).await {
                title = Some(t);
                break;
            }
        }
    }

    Some(ProbeResult {
        ip,
        open_ports,
        title,
        sources,
        mac: netbios_mac,
    })
}

async fn fetch_http_title(ip: &str, port: u16) -> Option<String> {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
    let stream_fut = TcpStream::connect(addr);
    let mut stream = timeout(Duration::from_millis(HTTP_TIMEOUT_MS), stream_fut)
        .await
        .ok()?
        .ok()?;

    let req = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: netscanner/0.1\r\nConnection: close\r\n\r\n",
        ip
    );
    timeout(
        Duration::from_millis(HTTP_TIMEOUT_MS),
        stream.write_all(req.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    let read_deadline = tokio::time::Instant::now() + Duration::from_millis(HTTP_TIMEOUT_MS);
    loop {
        let remaining = read_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            _ => break,
        }
    }

    let body = String::from_utf8_lossy(&buf);
    let lower = body.to_lowercase();
    let start = lower.find("<title")?;
    let after_open = body[start..].find('>')? + start + 1;
    let end_rel = lower[after_open..].find("</title>")?;
    let raw = &body[after_open..after_open + end_rel];
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.chars().take(80).collect())
    }
}

// NetBIOS name service query (UDP 137) — returns (alive, optional MAC parsed from response)
async fn netbios_probe(ip: &str) -> (bool, Option<String>) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return (false, None),
    };
    // Standard NBSTAT query packet (asks for node status)
    let query: [u8; 50] = [
        0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00, 0x21, 0x00, 0x01,
    ];
    let target = match format!("{}:137", ip).parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return (false, None),
    };
    if sock.send_to(&query, target).await.is_err() {
        return (false, None);
    }
    let mut buf = [0u8; 1024];
    match timeout(Duration::from_millis(UDP_TIMEOUT_MS), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => (true, parse_nbstat_mac(&buf[..n])),
        _ => (false, None),
    }
}

// Parse the Unit ID (6-byte MAC) from an NBSTAT response payload.
// Layout: DNS header(12) + question(38) + answer{name(2 or 34) + type/class/ttl/rdlen(10) + rdata}
// RDATA: num_names(1) + names(18*N) + statistics{ unit_id(6) ... }
fn parse_nbstat_mac(buf: &[u8]) -> Option<String> {
    if buf.len() < 70 {
        return None;
    }
    let mut offset = 12 + 34 + 4; // past header + question

    // Answer NAME: compression pointer (0xC0 ..) = 2 bytes, otherwise full 34-byte name
    let name_len = if buf[offset] & 0xc0 == 0xc0 { 2 } else { 34 };
    offset += name_len + 10; // + type(2)+class(2)+ttl(4)+rdlen(2)

    if offset >= buf.len() {
        return None;
    }
    let num_names = buf[offset] as usize;
    offset += 1 + 18 * num_names;

    if offset + 6 > buf.len() {
        return None;
    }
    let m = &buf[offset..offset + 6];
    // Reject all-zero MAC
    if m.iter().all(|&b| b == 0) {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    ))
}

// mDNS broadcast discovery — returns (ip, optional_hostname)
async fn mdns_discover() -> Vec<(String, Option<String>)> {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let _ = sock.set_broadcast(true);

    // mDNS query for "_services._dns-sd._udp.local" PTR
    let query: [u8; 46] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'_', b's',
        b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
        0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0c, 0x00,
        0x01,
    ];

    let target: SocketAddr = "224.0.0.251:5353".parse().unwrap();
    let _ = sock.send_to(&query, target).await;

    let mut results: HashMap<String, Option<String>> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut buf = [0u8; 2048];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((_n, src))) => {
                let ip = src.ip().to_string();
                results.entry(ip).or_insert(None);
            }
            _ => break,
        }
    }

    results.into_iter().collect()
}

// SSDP discovery (UPnP) — returns (ip, server, mac_from_uuid)
async fn ssdp_discover() -> Vec<(String, Option<String>, Option<String>)> {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let _ = sock.set_broadcast(true);

    let msg = "M-SEARCH * HTTP/1.1\r\n\
               HOST: 239.255.255.250:1900\r\n\
               MAN: \"ssdp:discover\"\r\n\
               MX: 1\r\n\
               ST: ssdp:all\r\n\r\n";

    let target: SocketAddr = "239.255.255.250:1900".parse().unwrap();
    let _ = sock.send_to(msg.as_bytes(), target).await;

    let mut results: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut buf = [0u8; 2048];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                let ip = src.ip().to_string();
                let body = String::from_utf8_lossy(&buf[..n]);
                let mut server: Option<String> = None;
                let mut mac: Option<String> = None;
                for line in body.lines() {
                    let lower = line.to_lowercase();
                    if server.is_none() && lower.starts_with("server:") {
                        let s = line[7..].trim().to_string();
                        if !s.is_empty() {
                            server = Some(s);
                        }
                    }
                    if mac.is_none() && (lower.starts_with("usn:") || lower.starts_with("nt:")) {
                        mac = extract_mac_from_uuid(line);
                    }
                }
                let entry = results.entry(ip).or_insert((None, None));
                if entry.0.is_none() {
                    entry.0 = server;
                }
                if entry.1.is_none() {
                    entry.1 = mac;
                }
            }
            _ => break,
        }
    }

    results
        .into_iter()
        .map(|(ip, (s, m))| (ip, s, m))
        .collect()
}

// Pull MAC out of a UUID URN like "uuid:xxxxxxxx-xxxx-xxxx-xxxx-AABBCCDDEEFF"
fn extract_mac_from_uuid(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    let idx = lower.find("uuid:")?;
    let rest = &line[idx + 5..];
    // Stop at the next '::' or whitespace
    let end = rest.find("::").unwrap_or_else(|| {
        rest.find(char::is_whitespace).unwrap_or(rest.len())
    });
    let uuid = &rest[..end];
    // Last segment after final '-' should be 12 hex digits = MAC
    let last = uuid.rsplit('-').next()?;
    if last.len() != 12 || !last.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let b = last.as_bytes();
    let mac = format!(
        "{}{}:{}{}:{}{}:{}{}:{}{}:{}{}",
        b[0] as char, b[1] as char,
        b[2] as char, b[3] as char,
        b[4] as char, b[5] as char,
        b[6] as char, b[7] as char,
        b[8] as char, b[9] as char,
        b[10] as char, b[11] as char,
    );
    Some(mac.to_lowercase())
}

fn read_arp_table() -> HashMap<String, String> {
    let mut map = HashMap::new();

    if let Ok(out) = Command::new("ip").args(["neigh", "show"]).output() {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let ip = parts[0].to_string();
                    if let Some(idx) = parts.iter().position(|p| *p == "lladdr") {
                        if let Some(mac) = parts.get(idx + 1) {
                            map.insert(ip, mac.to_string());
                        }
                    }
                }
            }
            if !map.is_empty() {
                return map;
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let ip = parts[0].to_string();
                let mac = parts[3].to_string();
                if mac != "00:00:00:00:00:00" {
                    map.insert(ip, mac);
                }
            }
        }
    }

    map
}

fn reverse_dns(ip: &str) -> Option<String> {
    let output = Command::new("nslookup").arg(ip).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);

    for line in s.lines() {
        if let Some(idx) = line.find("name =") {
            let name = line[idx + 6..].trim().trim_end_matches('.').to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        if let Some(stripped) = line.trim_start().strip_prefix("Name:") {
            let name = stripped.trim().trim_end_matches('.').to_string();
            if !name.is_empty() && !name.eq_ignore_ascii_case(ip) {
                return Some(name);
            }
        }
    }
    None
}
