use std::collections::HashMap;
use std::sync::OnceLock;

// Curated OUI database — first 3 bytes of MAC → vendor name.
// Format: "XX:XX:XX" uppercase, colon-separated.
static OUI_ENTRIES: &[(&str, &str)] = &[
    // Apple
    ("00:03:93", "Apple"),
    ("00:0A:27", "Apple"),
    ("00:0D:93", "Apple"),
    ("00:10:FA", "Apple"),
    ("00:14:51", "Apple"),
    ("00:16:CB", "Apple"),
    ("00:17:F2", "Apple"),
    ("00:19:E3", "Apple"),
    ("00:1B:63", "Apple"),
    ("00:1F:F3", "Apple"),
    ("00:21:E9", "Apple"),
    ("00:23:32", "Apple"),
    ("00:25:00", "Apple"),
    ("00:25:BC", "Apple"),
    ("00:26:08", "Apple"),
    ("00:26:B0", "Apple"),
    ("00:26:BB", "Apple"),
    ("00:3E:E1", "Apple"),
    ("00:50:E4", "Apple"),
    ("00:88:65", "Apple"),
    ("00:A0:40", "Apple"),
    ("04:0C:CE", "Apple"),
    ("04:48:9A", "Apple"),
    ("04:4B:ED", "Apple"),
    ("04:54:53", "Apple"),
    ("04:DB:56", "Apple"),
    ("04:E5:36", "Apple"),
    ("04:F1:3E", "Apple"),
    ("04:F7:E4", "Apple"),
    ("28:5A:EB", "Apple"),
    ("28:6A:B8", "Apple"),
    ("28:CF:E9", "Apple"),
    ("28:E1:4C", "Apple"),
    ("28:E7:CF", "Apple"),
    ("28:ED:6A", "Apple"),
    ("28:F0:76", "Apple"),
    ("3C:07:54", "Apple"),
    ("3C:15:C2", "Apple"),
    ("3C:AB:8E", "Apple"),
    ("3C:E0:72", "Apple"),
    ("60:33:4B", "Apple"),
    ("60:F8:1D", "Apple"),
    ("70:56:81", "Apple"),
    ("70:CD:60", "Apple"),
    ("8C:85:90", "Apple"),
    ("A4:5E:60", "Apple"),
    ("AC:CF:5C", "Apple"),
    ("B8:E8:56", "Apple"),
    ("C8:1E:E7", "Apple"),
    ("C8:2A:14", "Apple"),
    ("D0:23:DB", "Apple"),
    ("D8:96:95", "Apple"),
    ("F0:DC:E2", "Apple"),
    ("F4:0F:24", "Apple"),
    // Samsung
    ("00:00:F0", "Samsung"),
    ("00:07:AB", "Samsung"),
    ("00:12:FB", "Samsung"),
    ("00:15:99", "Samsung"),
    ("00:17:C9", "Samsung"),
    ("00:1A:8A", "Samsung"),
    ("00:21:19", "Samsung"),
    ("00:23:39", "Samsung"),
    ("00:23:99", "Samsung"),
    ("08:08:C2", "Samsung"),
    ("18:3A:2D", "Samsung"),
    ("28:BA:B5", "Samsung"),
    ("38:01:97", "Samsung"),
    ("5C:0A:5B", "Samsung"),
    ("78:1F:DB", "Samsung"),
    ("84:25:DB", "Samsung"),
    ("8C:77:12", "Samsung"),
    ("A0:0B:BA", "Samsung"),
    ("AC:5F:3E", "Samsung"),
    ("BC:14:85", "Samsung"),
    ("E8:50:8B", "Samsung"),
    ("EC:1F:72", "Samsung"),
    // Xiaomi
    ("00:9E:C8", "Xiaomi"),
    ("0C:1D:AF", "Xiaomi"),
    ("14:F6:5A", "Xiaomi"),
    ("28:E3:1F", "Xiaomi"),
    ("28:6C:07", "Xiaomi"),
    ("50:64:2B", "Xiaomi"),
    ("58:44:98", "Xiaomi"),
    ("64:09:80", "Xiaomi"),
    ("64:CC:2E", "Xiaomi"),
    ("68:DF:DD", "Xiaomi"),
    ("74:23:44", "Xiaomi"),
    ("78:11:DC", "Xiaomi"),
    ("8C:BE:BE", "Xiaomi"),
    ("98:FA:E3", "Xiaomi"),
    ("A0:86:C6", "Xiaomi"),
    ("AC:C1:EE", "Xiaomi"),
    ("F0:B4:29", "Xiaomi"),
    ("F8:A4:5F", "Xiaomi"),
    // Huawei
    ("00:18:82", "Huawei"),
    ("00:25:9E", "Huawei"),
    ("00:46:4B", "Huawei"),
    ("00:E0:FC", "Huawei"),
    ("04:79:70", "Huawei"),
    ("04:BD:70", "Huawei"),
    ("04:F9:38", "Huawei"),
    ("28:31:52", "Huawei"),
    ("4C:54:99", "Huawei"),
    ("80:38:BC", "Huawei"),
    ("88:CE:FA", "Huawei"),
    ("A4:99:47", "Huawei"),
    ("E0:24:7F", "Huawei"),
    // Honor (Huawei sub-brand)
    ("84:7C:8B", "Honor"),
    // Google / Nest
    ("00:1A:11", "Google"),
    ("3C:5A:B4", "Google"),
    ("6C:AD:F8", "Google"),
    ("94:EB:2C", "Google"),
    ("F4:F5:E8", "Google"),
    ("F8:8F:CA", "Google"),
    ("18:B4:30", "Nest Labs (Google)"),
    ("64:16:66", "Google Home"),
    // TP-Link
    ("00:14:78", "TP-Link"),
    ("00:1D:0F", "TP-Link"),
    ("00:27:19", "TP-Link"),
    ("14:CC:20", "TP-Link"),
    ("50:C7:BF", "TP-Link"),
    ("60:A4:B7", "TP-Link"),
    ("98:DA:C4", "TP-Link"),
    ("A4:2B:B0", "TP-Link"),
    ("C0:25:E9", "TP-Link"),
    ("EC:08:6B", "TP-Link"),
    // D-Link
    ("00:05:5D", "D-Link"),
    ("00:13:46", "D-Link"),
    ("00:15:E9", "D-Link"),
    ("00:17:9A", "D-Link"),
    ("00:1B:11", "D-Link"),
    ("00:24:01", "D-Link"),
    // Cisco
    ("00:00:0C", "Cisco"),
    ("00:01:42", "Cisco"),
    ("00:0A:41", "Cisco"),
    ("00:0D:65", "Cisco"),
    ("00:11:5C", "Cisco"),
    ("00:14:6A", "Cisco"),
    ("00:1B:67", "Cisco"),
    ("00:24:50", "Cisco"),
    ("00:26:0B", "Cisco"),
    // Intel
    ("00:02:B3", "Intel"),
    ("00:0E:0C", "Intel"),
    ("00:13:02", "Intel"),
    ("00:13:CE", "Intel"),
    ("00:15:00", "Intel"),
    ("00:16:6F", "Intel"),
    ("00:19:D1", "Intel"),
    ("00:1B:21", "Intel"),
    ("00:1B:77", "Intel"),
    ("00:1E:64", "Intel"),
    ("00:1F:3C", "Intel"),
    ("00:21:5C", "Intel"),
    ("00:22:FB", "Intel"),
    ("00:24:D7", "Intel"),
    ("00:27:10", "Intel"),
    ("3C:A9:F4", "Intel"),
    ("44:85:00", "Intel"),
    ("48:51:B7", "Intel"),
    ("7C:7A:91", "Intel"),
    ("A0:A8:CD", "Intel"),
    ("DC:53:60", "Intel"),
    // Realtek
    ("00:E0:4C", "Realtek"),
    ("52:54:00", "QEMU / KVM"),
    ("90:0F:0C", "Realtek"),
    // MediaTek
    ("00:0C:E7", "MediaTek"),
    ("1C:62:88", "MediaTek"),
    // Espressif (ESP8266 / ESP32)
    ("24:0A:C4", "Espressif (ESP)"),
    ("24:6F:28", "Espressif (ESP)"),
    ("30:AE:A4", "Espressif (ESP)"),
    ("48:3F:DA", "Espressif (ESP)"),
    ("84:0D:8E", "Espressif (ESP)"),
    ("8C:AA:B5", "Espressif (ESP)"),
    ("A8:03:2A", "Espressif (ESP)"),
    ("AC:67:B2", "Espressif (ESP)"),
    ("BC:DD:C2", "Espressif (ESP)"),
    ("EC:FA:BC", "Espressif (ESP)"),
    // Raspberry Pi
    ("28:CD:C1", "Raspberry Pi"),
    ("B8:27:EB", "Raspberry Pi"),
    ("D8:3A:DD", "Raspberry Pi"),
    ("DC:A6:32", "Raspberry Pi"),
    ("E4:5F:01", "Raspberry Pi"),
    // Amazon
    ("0C:47:C9", "Amazon"),
    ("18:74:2E", "Amazon"),
    ("34:D2:70", "Amazon"),
    ("44:65:0D", "Amazon"),
    ("50:F5:DA", "Amazon"),
    ("74:75:48", "Amazon"),
    ("B0:47:BF", "Amazon"),
    ("F0:27:2D", "Amazon"),
    // Microsoft
    ("00:03:FF", "Microsoft"),
    ("00:1D:D8", "Microsoft"),
    ("00:50:F2", "Microsoft"),
    ("7C:1E:52", "Microsoft (Surface)"),
    ("C8:3A:6B", "Microsoft (Xbox)"),
    // Sony
    ("00:13:A9", "Sony"),
    ("00:1A:80", "Sony"),
    ("00:1D:0D", "Sony"),
    ("FC:F1:52", "Sony"),
    ("F0:BF:97", "Sony"),
    // LG
    ("00:1C:62", "LG"),
    ("00:1F:6B", "LG"),
    ("00:50:BA", "LG"),
    ("38:8C:50", "LG"),
    // Sonos
    ("00:0E:58", "Sonos"),
    ("B8:E9:37", "Sonos"),
    // Dell
    ("00:14:22", "Dell"),
    ("00:18:8B", "Dell"),
    ("00:21:9B", "Dell"),
    ("A4:1F:72", "Dell"),
    ("F8:DB:88", "Dell"),
    // HP
    ("00:08:02", "HP"),
    ("00:1A:4B", "HP"),
    ("00:30:6E", "HP"),
    ("3C:D9:2B", "HP"),
    ("80:CE:62", "HP"),
    // Lenovo
    ("00:21:CC", "Lenovo"),
    ("6C:5D:63", "Lenovo"),
    ("A4:8E:38", "Lenovo"),
    ("E8:6F:38", "Lenovo"),
    // ASUS
    ("00:0C:6E", "ASUS"),
    ("00:1F:C6", "ASUS"),
    ("04:D9:F5", "ASUS"),
    ("30:5A:3A", "ASUS"),
    ("88:D7:F6", "ASUS"),
    ("AC:22:0B", "ASUS"),
    // Netgear
    ("00:09:5B", "Netgear"),
    ("00:1B:2F", "Netgear"),
    ("00:24:B2", "Netgear"),
    ("28:C6:8E", "Netgear"),
    ("A0:21:B7", "Netgear"),
    // Linksys
    ("00:0C:41", "Linksys"),
    ("00:13:10", "Linksys"),
    ("00:14:BF", "Linksys"),
    ("48:F8:B3", "Linksys"),
    // Ubiquiti
    ("00:15:6D", "Ubiquiti"),
    ("04:18:D6", "Ubiquiti"),
    ("24:5A:4C", "Ubiquiti"),
    ("44:D9:E7", "Ubiquiti"),
    ("78:8A:20", "Ubiquiti"),
    ("F0:9F:C2", "Ubiquiti"),
    // MikroTik
    ("00:0C:42", "MikroTik"),
    ("4C:5E:0C", "MikroTik"),
    ("6C:3B:6B", "MikroTik"),
    ("B8:69:F4", "MikroTik"),
    ("E4:8D:8C", "MikroTik"),
    // Roku
    ("B0:A7:37", "Roku"),
    ("B8:A1:75", "Roku"),
    ("CC:6D:A0", "Roku"),
    // Oppo / Realme
    ("00:9A:CD", "OPPO"),
    ("8C:E5:C0", "OPPO"),
    ("F4:F5:DB", "OPPO"),
    // Vivo
    ("30:46:CB", "Vivo"),
    ("80:6C:1B", "Vivo"),
    ("D4:8A:39", "Vivo"),
    // OnePlus
    ("64:A2:F9", "OnePlus"),
    ("94:65:2D", "OnePlus"),
    ("C8:E8:8F", "OnePlus"),
    // ZTE
    ("00:1E:73", "ZTE"),
    ("00:1F:1F", "ZTE"),
    ("34:E0:CF", "ZTE"),
    // Roborock
    ("04:CF:8C", "Roborock"),
    // Virtualization
    ("00:0C:29", "VMware"),
    ("00:50:56", "VMware"),
    ("00:1C:14", "VMware"),
    ("08:00:27", "VirtualBox"),
    ("02:42:AC", "Docker"),
    // Common IoT / smart-plug chipsets
    ("50:02:91", "Tuya Smart"),
    ("84:E3:42", "Tuya Smart"),
    ("D8:F1:5B", "Espressif (ESP)"),
];

static MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

pub fn lookup(mac: &str) -> Option<String> {
    let oui = normalize(mac)?;

    // Locally-administered bit set → randomized MAC (modern phones)
    if is_locally_administered(&oui) {
        return Some("Randomized MAC".to_string());
    }

    let map = MAP.get_or_init(|| OUI_ENTRIES.iter().copied().collect());
    map.get(oui.as_str()).map(|v| v.to_string())
}

fn normalize(mac: &str) -> Option<String> {
    let cleaned = mac.replace('-', ":").to_uppercase();
    let parts: Vec<&str> = cleaned.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    if parts[0].len() != 2 || parts[1].len() != 2 || parts[2].len() != 2 {
        return None;
    }
    Some(format!("{}:{}:{}", parts[0], parts[1], parts[2]))
}

fn is_locally_administered(oui: &str) -> bool {
    // Bit 1 (0x02) of first octet = locally administered (randomized)
    u8::from_str_radix(&oui[..2], 16)
        .map(|b| b & 0x02 != 0)
        .unwrap_or(false)
}
