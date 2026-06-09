use futures::stream::{FuturesUnordered, StreamExt};
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct ScanResult {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub title: Option<String>,
    pub open_ports: Vec<u16>,
    pub sources: Vec<String>,
    pub last_seen: String,
}

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

pub async fn scan_subnet(subnet: &str) -> Vec<ScanResult> {
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

    for ip in mdns_ips {
        let entry = alive.entry(ip.clone()).or_insert_with(|| ProbeResult {
            ip,
            open_ports: vec![],
            title: None,
            sources: vec![],
            mac: None,
            hostname: None,
        });
        if !entry.sources.iter().any(|s| s == "mdns") {
            entry.sources.push("mdns".to_string());
        }
    }

    for (ip, server, ssdp_mac) in ssdp_ips {
        let entry = alive.entry(ip.clone()).or_insert_with(|| ProbeResult {
            ip,
            open_ports: vec![],
            title: None,
            sources: vec![],
            mac: None,
            hostname: None,
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

    // Reverse mDNS lookup for any alive IP that doesn't yet have a hostname
    let need_hostname: Vec<String> = alive
        .iter()
        .filter(|(_, r)| r.hostname.is_none())
        .map(|(ip, _)| ip.clone())
        .collect();
    let mdns_names = mdns_reverse_lookup(&need_hostname).await;
    for (ip, name) in mdns_names {
        if let Some(entry) = alive.get_mut(&ip) {
            entry.hostname = Some(name);
            if !entry.sources.iter().any(|s| s == "mdns") {
                entry.sources.push("mdns".to_string());
            }
        }
    }

    // Build results — MAC priority: ARP > SSDP-uuid > NBSTAT
    // Hostname priority: NetBIOS/mDNS (from probe) > reverse DNS
    let mut devices: Vec<ScanResult> = alive
        .into_iter()
        .map(|(ip, r)| {
            let mac = arp_table.get(&ip).cloned().or(r.mac);
            let vendor = mac.as_deref().and_then(crate::oui::lookup);
            let hostname = r.hostname.or_else(|| reverse_dns(&ip));
            ScanResult {
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
    hostname: Option<String>,
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
    let (netbios_responded, netbios_mac, netbios_name) = netbios_probe(&ip).await;

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
        hostname: netbios_name,
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

// NetBIOS name service query (UDP 137) — returns (alive, optional MAC, optional computer name)
async fn netbios_probe(ip: &str) -> (bool, Option<String>, Option<String>) {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return (false, None, None),
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
        Err(_) => return (false, None, None),
    };
    if sock.send_to(&query, target).await.is_err() {
        return (false, None, None);
    }
    let mut buf = [0u8; 1024];
    match timeout(Duration::from_millis(UDP_TIMEOUT_MS), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            let (mac, name) = parse_nbstat(&buf[..n]);
            (true, mac, name)
        }
        _ => (false, None, None),
    }
}

// Parse the NBSTAT response payload — returns (MAC, computer_name).
// Layout: DNS header(12) + question(38) + answer{name(2 or 34) + type/class/ttl/rdlen(10) + rdata}
// RDATA: num_names(1) + names(18*N) + statistics{ unit_id(6) ... }
// Each name entry: 15 bytes NetBIOS name + 1 byte suffix (service type) + 2 bytes flags
fn parse_nbstat(buf: &[u8]) -> (Option<String>, Option<String>) {
    if buf.len() < 70 {
        return (None, None);
    }
    let mut offset = 12 + 34 + 4; // past header + question

    // Answer NAME: compression pointer (0xC0 ..) = 2 bytes, otherwise full 34-byte name
    let name_len = if buf[offset] & 0xc0 == 0xc0 { 2 } else { 34 };
    offset += name_len + 10; // + type(2)+class(2)+ttl(4)+rdlen(2)

    if offset >= buf.len() {
        return (None, None);
    }
    let num_names = buf[offset] as usize;
    offset += 1;

    // Walk the name list and pick the first non-group Workstation/Server entry
    let mut computer_name: Option<String> = None;
    for i in 0..num_names {
        let entry_off = offset + i * 18;
        if entry_off + 18 > buf.len() {
            break;
        }
        let raw = &buf[entry_off..entry_off + 15];
        let suffix = buf[entry_off + 15];
        let flags = u16::from_be_bytes([buf[entry_off + 16], buf[entry_off + 17]]);
        let is_group = flags & 0x8000 != 0;
        // Workstation Service (0x00) is the canonical computer name; Server Service (0x20) is fallback
        if !is_group && (suffix == 0x00 || suffix == 0x20) {
            let s: String = raw
                .iter()
                .map(|&b| b as char)
                .collect::<String>()
                .trim_end()
                .to_string();
            if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                computer_name = Some(s);
                break;
            }
        }
    }

    let mac_off = offset + 18 * num_names;
    let mac = if mac_off + 6 <= buf.len() {
        let m = &buf[mac_off..mac_off + 6];
        if m.iter().all(|&b| b == 0) {
            None
        } else {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ))
        }
    } else {
        None
    };

    (mac, computer_name)
}

// mDNS broadcast discovery — returns alive IPs that responded to the service enum
async fn mdns_discover() -> Vec<String> {
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

    let mut results: std::collections::HashSet<String> = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut buf = [0u8; 2048];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((_n, src))) => {
                results.insert(src.ip().to_string());
            }
            _ => break,
        }
    }

    results.into_iter().collect()
}

// Send mDNS reverse PTR queries (X.X.X.X.in-addr.arpa) for each IP and collect hostnames.
// Devices that speak mDNS respond with their .local hostname.
async fn mdns_reverse_lookup(ips: &[String]) -> HashMap<String, String> {
    if ips.is_empty() {
        return HashMap::new();
    }
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };
    let _ = sock.set_broadcast(true);

    let target: SocketAddr = "224.0.0.251:5353".parse().unwrap();

    for (idx, ip) in ips.iter().enumerate() {
        let octets: Vec<&str> = ip.split('.').collect();
        if octets.len() != 4 {
            continue;
        }
        let labels = [octets[3], octets[2], octets[1], octets[0], "in-addr", "arpa"];

        let mut query: Vec<u8> = Vec::with_capacity(48);
        query.extend_from_slice(&(idx as u16).to_be_bytes()); // ID
        query.extend_from_slice(&[0x00, 0x00]); // Flags
        query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR

        for label in &labels {
            if label.len() > 63 {
                continue;
            }
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0x00); // root label

        query.extend_from_slice(&[0x00, 0x0c]); // QTYPE = PTR
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        let _ = sock.send_to(&query, target).await;
    }

    let mut results: HashMap<String, String> = HashMap::new();
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
                if results.contains_key(&ip) {
                    continue;
                }
                if let Some(raw) = parse_first_ptr_answer(&buf[..n]) {
                    let cleaned = raw
                        .trim_end_matches('.')
                        .trim_end_matches(".local")
                        .trim_end_matches('.')
                        .to_string();
                    if !cleaned.is_empty() {
                        results.insert(ip, cleaned);
                    }
                }
            }
            _ => break,
        }
    }

    results
}

// Parse a DNS name starting at `offset`. Returns (name, offset_after_name).
// Handles compression pointers per RFC 1035 §4.1.4.
fn parse_dns_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut offset = start;
    let mut after: Option<usize> = None;
    let mut hops = 0;

    loop {
        if offset >= buf.len() {
            return None;
        }
        let len = buf[offset];
        if len == 0 {
            offset += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len as usize) & 0x3f) << 8) | buf[offset + 1] as usize;
            if after.is_none() {
                after = Some(offset + 2);
            }
            offset = ptr;
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        let llen = len as usize;
        offset += 1;
        if offset + llen > buf.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &buf[offset..offset + llen] {
            name.push(b as char);
        }
        offset += llen;
    }

    Some((name, after.unwrap_or(offset)))
}

// Walk a DNS response and return the first PTR answer's target name.
fn parse_first_ptr_answer(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut offset = 12;
    for _ in 0..qdcount {
        let (_, next) = parse_dns_name(buf, offset)?;
        offset = next + 4; // QTYPE + QCLASS
        if offset > buf.len() {
            return None;
        }
    }

    for _ in 0..ancount {
        let (_, next) = parse_dns_name(buf, offset)?;
        offset = next;
        if offset + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > buf.len() {
            return None;
        }
        if rtype == 12 {
            let (name, _) = parse_dns_name(buf, offset)?;
            return Some(name);
        }
        offset += rdlen;
    }

    None
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
