# lansight

Friendly LAN scanner & dashboard untuk home network. Tahu siapa saja yang lagi tersambung ke Wi-Fi rumah — IP, MAC, vendor, hostname, port terbuka — semua tersaji di satu halaman responsif yang juga enak dibuka dari HP.

## Fitur

- **Auto subnet detection** — deteksi `/24` dari local IP
- **Multi-source discovery** — TCP probe, NetBIOS, mDNS, SSDP/UPnP, ARP table
- **MAC + vendor lookup** — OUI database ter-embed (~250 vendor)
- **MAC dari SSDP UUID & NBSTAT** — tetap dapat MAC walau ARP tidak accessible
- **Randomized MAC detection** — flag merah untuk MAC privacy-randomized
- **Web dashboard** — card layout mobile-first, search & filter, auto-refresh 5 detik
- **Background scan** tiap 20 detik

## Quick start (local)

```bash
cargo build --release
./target/release/lansight
```

Buka `http://localhost:8080` atau dari HP di network yang sama: `http://<server-ip>:8080`.

## Deploy ke Coolify

1. Push repo ini ke GitHub.
2. Di Coolify: **+ New Resource → Public Repository** (atau pakai GitHub App).
3. Repository URL: `https://github.com/<user>/lansight`
4. Branch: `main` · Build Pack: **Dockerfile**
5. Port: **8080**
6. ⚠️ **WAJIB**: Service settings → **Network Mode: `host`**
   - Tanpa ini, container hanya bisa lihat jaringan Docker internal, bukan LAN host.
7. Deploy.

### Akses dari luar rumah (Cloudflare Tunnel)

Setelah jalan di Coolify (port 8080), tunnel via `cloudflared`:

```bash
cloudflared tunnel create lansight
cloudflared tunnel route dns lansight lansight.domainmu.com
# config.yml:
#   ingress:
#     - hostname: lansight.domainmu.com
#       service: http://localhost:8080
```

⚠️ **Tambahkan Cloudflare Access policy** (email OTP / Google login) sebelum expose ke publik. Tanpa auth, siapapun yang tahu URL bisa lihat semua device di rumah Anda.

## Catatan tentang MAC address

- **Linux server (akses host network)**: ARP table accessible → MAC lengkap untuk semua device aktif.
- **Android tanpa root**: SELinux block `/proc/net/arp`. MAC hanya didapat dari SSDP UUID (router, smart TV, printer) atau NBSTAT (PC Windows). Phone Android/iOS biasanya kosong (mereka pakai randomized MAC + jarang broadcast UPnP).

## Troubleshooting

| Gejala | Sebab | Solusi |
|---|---|---|
| Tidak ada device terdeteksi | Container bukan host network | Set Network Mode: host di Coolify |
| MAC selalu kosong | Tidak akses ke ARP cache | Pastikan host network mode aktif |
| Vendor `Randomized MAC` | MAC privacy aktif di device (normal di iOS/Android modern) | Tidak ada — disengaja oleh OS device |
| Scan stuck di "scanning" | Network bermasalah / firewall block | Cek server bisa ping ke device LAN |

## Stack

Rust · Axum · Tokio · Vanilla HTML/CSS/JS (no framework di frontend)

## License

MIT
