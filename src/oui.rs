use std::collections::HashMap;
use std::sync::OnceLock;

// Full IEEE OUI registry (MA-L/MA-M/MA-S), embedded at compile time.
// Generated from https://standards-oui.ieee.org/oui/oui.csv — one entry per line,
// tab-separated: `AABBCC\tVendor` where the key is the first 3 MAC bytes, uppercase hex.
static OUI_TSV: &str = include_str!("oui_data.tsv");

static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

fn map() -> &'static HashMap<&'static str, &'static str> {
    MAP.get_or_init(|| {
        OUI_TSV
            .lines()
            .filter_map(|line| {
                let (key, vendor) = line.split_once('\t')?;
                let key = key.trim();
                let vendor = vendor.trim();
                if key.len() == 6 && !vendor.is_empty() {
                    Some((key, vendor))
                } else {
                    None
                }
            })
            .collect()
    })
}

pub fn lookup(mac: &str) -> Option<String> {
    let oui = normalize(mac)?;

    // Locally-administered bit set → randomized MAC (modern phones)
    if is_locally_administered(&oui) {
        return Some("Randomized MAC".to_string());
    }

    map().get(oui.as_str()).map(|v| v.to_string())
}

// Reduce a MAC to its 6-hex-digit OUI key, uppercase, no separators. Accepts
// colon- or dash-separated input (e.g. "a8:29:48:..." or "A8-29-48-...").
fn normalize(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() == 6 {
        Some(hex)
    } else {
        None
    }
}

fn is_locally_administered(oui: &str) -> bool {
    // Bit 1 (0x02) of first octet = locally administered (randomized)
    u8::from_str_radix(&oui[..2], 16)
        .map(|b| b & 0x02 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors_resolve() {
        assert!(lookup("a8:29:48:14:25:e0").is_some());
        assert!(lookup("A8-A1-59-E5-DC-14").is_some());
    }

    #[test]
    fn randomized_mac_flagged() {
        // 0x72 has the locally-administered bit set
        assert_eq!(lookup("72:b6:c0:bf:ec:59").as_deref(), Some("Randomized MAC"));
    }

    #[test]
    fn bad_input_is_none() {
        assert_eq!(lookup("xyz"), None);
        assert_eq!(lookup(""), None);
    }
}
