# lansight

Friendly LAN scanner & dashboard untuk home network. Tahu siapa saja yang lagi tersambung ke Wi-Fi rumah — IP, MAC, vendor, hostname, port terbuka — semua tersaji di satu halaman responsif yang juga enak dibuka dari HP.

## Fitur

- **Auto subnet detection** — deteksi `/24` dari local IP
- **Multi-source discovery** — TCP probe, NetBIOS, mDNS, SSDP/UPnP, ARP table
- **MAC + vendor lookup** — full IEEE OUI database ter-embed (~40rb prefix)
- **MAC dari SSDP UUID & NBSTAT** — tetap dapat MAC walau ARP tidak accessible
- **Randomized MAC detection** — flag merah untuk MAC privacy-randomized
- **OS guess via ICMP TTL** — tebak OS (Windows / Linux / Apple / Android / Router·IoT) dari TTL reply + pola port + vendor
- **Latensi per-device** — RTT dari ICMP echo (fallback TCP connect)
- **Web dashboard** — card layout mobile-first, search & filter, auto-refresh 5 detik
- **Login password (opsional)** — gate dashboard di balik password via `LANSIGHT_PASSWORD`, cookie sesi HttpOnly
- **Background scan** tiap 20 detik

> **Catatan ICMP:** tebakan OS via TTL & latensi ICMP butuh raw socket (`CAP_NET_RAW`). `docker-compose.yml` sudah set `cap_add: [NET_RAW]`. Tanpa privilege itu, app tetap jalan — otomatis fallback ke probe TCP-only (tanpa TTL/OS guess).

## Quick start (local)

```bash
cargo build --release
./target/release/lansight
```

Buka `http://localhost:8080` atau dari HP di network yang sama: `http://<server-ip>:8080`.

## Login password (opsional)

Default: dashboard terbuka (tanpa login) — enak buat akses LAN lokal. Untuk wajibkan password
(mis. saat di-expose ke luar), set env var:

```bash
LANSIGHT_PASSWORD=rahasia ./target/release/lansight
```

- Tanpa `LANSIGHT_PASSWORD` (atau kosong) → auth **mati**, perilaku lama.
- Dengan password di-set → semua route minta login. Buka `/` → redirect ke `/login`, isi password,
  dapat cookie sesi (HttpOnly, SameSite=Lax) yang berlaku 30 hari. Tombol **Keluar** di header buat logout.
- Token sesi acak (bukan turunan password) dan disimpan di memory — **restart server = semua harus login ulang**.
- `LANSIGHT_COOKIE_SECURE=1` → tambah atribut `Secure` ke cookie. Set ini kalau akses **hanya** lewat
  HTTPS/tunnel (kalau di-set tapi akses via http LAN polos, browser tidak akan simpan cookie → tidak bisa login).

> ⚠️ Di LAN http polos, password login terkirim plaintext. Fitur ini lapisan tambahan — untuk expose
> ke publik tetap taruh di balik HTTPS (Cloudflare Tunnel/Access di bawah).

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

⚠️ **Pakai auth sebelum expose ke publik.** Minimal set `LANSIGHT_PASSWORD` (lihat [Login password](#login-password-opsional)), idealnya tambah **Cloudflare Access policy** (email OTP / Google login) juga. Tanpa auth, siapapun yang tahu URL bisa lihat semua device di rumah Anda.

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
