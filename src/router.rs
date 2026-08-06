// TP-Link Archer AX12 management client.
//
// The router has no documented local API. Its web UI logs in over an
// RSA+AES handshake (TP-Link "luci ;stok=" scheme) and then tunnels every
// request as AES-CBC ciphertext with an RSA-signed header. This module ports
// that handshake so LANSight can block a device's internet access via the
// HomeShield / Parental-Controls endpoint.
//
// STATUS: PAUSED — foundation only, not wired to any live feature.
// The crypto primitives below (RSA/AES/MD5/sign) are ported from the reference
// `EncryptionWrapper` (github.com/AlexandrErohin/TP-Link-Archer-C6U) and are
// unit-tested. Login does NOT yet succeed against this unit's firmware
// (Last-Modified 2026-04): a captured real login shows a 7-block RSA signature
// (~320-370 char plaintext), whereas every known reference client — legacy and
// MR — builds only a ~84-char `k=&i=&h=&s=` sign (2 blocks). The AES `data`
// body format is confirmed correct; only the `sign` plaintext template differs.
// Resuming requires capturing the real sign plaintext (browser-console hook on
// crypto.getRandomValues + the sign builder) to learn the exact format.
//
// `#![allow(dead_code)]`: this whole module is deliberately unreferenced while
// paused; keeping it compiled (and its tests running) preserves the working
// crypto core as a foundation without emitting unused-code warnings.
#![allow(dead_code)]

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use md5::{Digest, Md5};
use num_bigint_dig::BigUint;
use serde_json::Value;
use tokio::sync::RwLock;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

// RSA plaintext chunk size for the 512-bit signing key: 64-byte modulus minus
// the 11-byte PKCS#1 v1.5 overhead.
const SIGN_CHUNK: usize = 53;

pub type RouterResult<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------

/// 16 random bytes rendered as a 16-char lowercase hex string, used as an
/// AES-128 key or IV (the router treats the ASCII hex text as the raw key).
fn gen_hex16() -> RouterResult<String> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|e| format!("OS RNG unavailable: {e}"))?;
    Ok(hex::encode(buf))
}

/// AES-128-CBC encrypt `plain` under the 16-byte ASCII `key`/`iv`, base64 out.
fn aes_encrypt(plain: &str, key: &[u8], iv: &[u8]) -> String {
    let ct = Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes());
    B64.encode(ct)
}

/// Inverse of [`aes_encrypt`]. Errors on bad base64 or padding.
fn aes_decrypt(b64: &str, key: &[u8], iv: &[u8]) -> RouterResult<String> {
    let ct = B64.decode(b64.trim()).map_err(|e| format!("b64 decode: {e}"))?;
    let pt = Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|e| format!("aes decrypt/unpad: {e}"))?;
    String::from_utf8(pt).map_err(|e| format!("utf8: {e}"))
}

/// One PKCS#1 v1.5 (type 2) RSA encryption block, hex-encoded, left-padded to
/// the full modulus length. `n_hex`/`e_hex` are the router-provided pubkey.
fn rsa_encrypt_block(msg: &[u8], n_hex: &str, e_hex: &str) -> RouterResult<String> {
    let n = BigUint::parse_bytes(n_hex.as_bytes(), 16).ok_or("bad RSA modulus")?;
    let e = BigUint::parse_bytes(e_hex.as_bytes(), 16).ok_or("bad RSA exponent")?;
    let k = n.bits().div_ceil(8); // modulus length in bytes
    if msg.len() > k.saturating_sub(11) {
        return Err(format!("RSA message {} too long for {}-byte key", msg.len(), k));
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M   (PS = random non-zero padding)
    let ps_len = k - msg.len() - 3;
    let mut ps = vec![0u8; ps_len];
    getrandom::getrandom(&mut ps).map_err(|e| format!("OS RNG unavailable: {e}"))?;
    for b in ps.iter_mut() {
        while *b == 0 {
            let mut one = [0u8; 1];
            getrandom::getrandom(&mut one).map_err(|e| format!("OS RNG unavailable: {e}"))?;
            *b = one[0];
        }
    }

    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x02);
    em.extend_from_slice(&ps);
    em.push(0x00);
    em.extend_from_slice(msg);

    let c = BigUint::from_bytes_be(&em).modpow(&e, &n);
    let mut out = c.to_bytes_be();
    if out.len() < k {
        // I2OSP: left-pad to exactly k bytes.
        let mut padded = vec![0u8; k - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    Ok(hex::encode(out))
}

/// RSA-sign the request header. The signed string is chunked at 53 bytes, each
/// chunk encrypted with the 512-bit signing key and concatenated as hex.
fn build_signature(
    seq: u64,
    is_login: bool,
    hash: &str,
    key: &str,
    iv: &str,
    n_hex: &str,
    e_hex: &str,
) -> RouterResult<String> {
    let s = if is_login {
        format!("k={key}&i={iv}&h={hash}&s={seq}")
    } else {
        format!("h={hash}&s={seq}")
    };
    let bytes = s.as_bytes();
    let mut sign = String::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let end = (pos + SIGN_CHUNK).min(bytes.len());
        sign.push_str(&rsa_encrypt_block(&bytes[pos..end], n_hex, e_hex)?);
        pos = end;
    }
    Ok(sign)
}

fn md5_hex(a: &str, b: &str) -> String {
    let mut h = Md5::new();
    h.update(a.as_bytes());
    h.update(b.as_bytes());
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Session {
    stok: String,
    sysauth: String,
    key: String, // AES-128 key (16 ASCII hex chars) negotiated at login
    iv: String,
    seq: u64, // base sequence from form=auth; each request adds its data length
    nn: String, // 512-bit signing-key modulus
    ee: String,
}

pub struct RouterClient {
    base: String, // e.g. http://192.168.0.1
    user: String,
    password: String,
    http: reqwest::Client,
    session: RwLock<Option<Session>>,
}

impl RouterClient {
    pub fn new(base: String, user: String, password: String) -> RouterResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            user,
            password,
            http,
            session: RwLock::new(None),
        })
    }

    fn referer(&self) -> String {
        format!("{}/webpages/index.html", self.base)
    }

    /// Perform the full RSA+AES login handshake and cache the session.
    pub async fn login(&self) -> RouterResult<()> {
        // 1. Password RSA public key (1024-bit).
        let keys = self
            .pre_login("keys")
            .await?
            .get("password")
            .and_then(|v| v.as_array().cloned())
            .ok_or("form=keys: no password key")?;
        let pwd_nn = keys.first().and_then(|v| v.as_str()).ok_or("no pwd modulus")?;
        let pwd_ee = keys.get(1).and_then(|v| v.as_str()).ok_or("no pwd exponent")?;

        // 2. Sequence + signing RSA public key (512-bit).
        let auth = self.pre_login("auth").await?;
        let seq = auth
            .get("seq")
            .and_then(|v| v.as_u64())
            .ok_or("form=auth: no seq")?;
        let sign_key = auth
            .get("key")
            .and_then(|v| v.as_array().cloned())
            .ok_or("form=auth: no sign key")?;
        let nn = sign_key.first().and_then(|v| v.as_str()).ok_or("no sign modulus")?.to_string();
        let ee = sign_key.get(1).and_then(|v| v.as_str()).ok_or("no sign exponent")?.to_string();

        // 3. Fresh AES session key/iv for E2E-encrypted traffic.
        let key = gen_hex16()?;
        let iv = gen_hex16()?;

        // 4. RSA-encrypt the password, wrap the login body, AES-encrypt it,
        //    and RSA-sign the header. Field order matches the AX-series web UI:
        //    `password=<hex>&operation=login` (no confirm field).
        let crypted_pwd = rsa_encrypt_block(self.password.as_bytes(), pwd_nn, pwd_ee)?;
        let body = format!("password={crypted_pwd}&operation=login");
        let enc = aes_encrypt(&body, key.as_bytes(), iv.as_bytes());
        let hash = md5_hex(&self.user, &self.password);
        let sign = build_signature(seq + enc.len() as u64, true, &hash, &key, &iv, &nn, &ee)?;

        // 5. POST the login. Response is AES-encrypted with our own key.
        let url = format!("{}/cgi-bin/luci/;stok=/login?form=login", self.base);
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::REFERER, self.referer())
            .form(&[("sign", sign.as_str()), ("data", enc.as_str())])
            .send()
            .await
            .map_err(|e| format!("login POST: {e}"))?;

        let status = resp.status();
        let set_cookie = resp
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp.text().await.map_err(|e| format!("login body: {e}"))?;
        if std::env::var("LANSIGHT_ROUTER_DUMP").as_deref() == Ok("1") {
            println!(
                "login: HTTP {status}; set-cookie={:?}; body={}",
                set_cookie,
                &body[..body.len().min(400)]
            );
        }

        let outer: Value =
            serde_json::from_str(&body).map_err(|e| format!("login JSON: {e}; body={body}"))?;
        let enc_data = outer
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("login: unexpected response {outer}"))?;
        let decrypted = aes_decrypt(enc_data, key.as_bytes(), iv.as_bytes())?;
        let sysauth = set_cookie
            .as_deref()
            .and_then(extract_sysauth)
            .ok_or("login: no sysauth cookie")?;
        let inner: Value =
            serde_json::from_str(&decrypted).map_err(|e| format!("login inner JSON: {e}"))?;
        let stok = inner
            .pointer("/data/stok")
            .or_else(|| inner.get("stok"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("login: no stok in {inner}"))?
            .to_string();

        *self.session.write().await = Some(Session {
            stok,
            sysauth,
            key,
            iv,
            seq,
            nn,
            ee,
        });
        Ok(())
    }

    /// GET one of the unauthenticated pre-login forms (keys/auth), returning
    /// its `data` object.
    async fn pre_login(&self, form: &str) -> RouterResult<Value> {
        let url = format!("{}/cgi-bin/luci/;stok=/login?form={form}", self.base);
        let resp = self
            .http
            .post(&url)
            .form(&[("operation", "read")])
            .send()
            .await
            .map_err(|e| format!("form={form} POST: {e}"))?;
        let json: Value = resp.json().await.map_err(|e| format!("form={form} JSON: {e}"))?;
        json.get("data")
            .cloned()
            .ok_or_else(|| format!("form={form}: no data in {json}"))
    }

    /// Send an authenticated, AES-tunneled request. `data` is the plaintext
    /// form body (e.g. `operation=load`). Returns the decrypted `data` block.
    /// Re-logs in once on an auth failure.
    pub async fn request(&self, path: &str, data: &str) -> RouterResult<Value> {
        match self.request_once(path, data).await {
            Ok(v) => Ok(v),
            Err(_) => {
                self.login().await?;
                self.request_once(path, data).await
            }
        }
    }

    /// One-shot diagnostic: log in and dump the HomeShield owner/device
    /// structures so the MAC→owner blocking logic can be finalized against the
    /// real router. Called from the `LANSIGHT_ROUTER_DUMP=1` startup path.
    pub async fn dump_discovery(&self) -> RouterResult<()> {
        self.login().await?;
        println!("router: login OK");
        for (label, path, op) in [
            ("owner_list", "admin/smart_network?form=patrol_owner_list", "load"),
            ("patrol_devices", "admin/smart_network?form=patrol_devices", "load"),
            ("patrol_enable", "admin/smart_network?form=patrol_enable", "read"),
        ] {
            match self.request(path, &format!("operation={op}")).await {
                Ok(v) => println!(
                    "=== {label} ===\n{}",
                    serde_json::to_string_pretty(&v).unwrap_or_default()
                ),
                Err(e) => println!("=== {label} === ERROR: {e}"),
            }
        }
        Ok(())
    }

    async fn request_once(&self, path: &str, data: &str) -> RouterResult<Value> {
        let guard = self.session.read().await;
        let s = guard.as_ref().ok_or("not authorised")?;

        let enc = aes_encrypt(data, s.key.as_bytes(), s.iv.as_bytes());
        let hash = md5_hex(&self.user, &self.password);
        let sign = build_signature(
            s.seq + enc.len() as u64,
            false,
            &hash,
            &s.key,
            &s.iv,
            &s.nn,
            &s.ee,
        )?;
        let url = format!("{}/cgi-bin/luci/;stok={}/{}", self.base, s.stok, path);

        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::REFERER, self.referer())
            .header(reqwest::header::ORIGIN, &self.base)
            .header(reqwest::header::COOKIE, format!("sysauth={}", s.sysauth))
            .form(&[("sign", sign.as_str()), ("data", enc.as_str())])
            .send()
            .await
            .map_err(|e| format!("{path} POST: {e}"))?;

        if resp.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(format!("{path}: 403 (session expired)"));
        }
        let outer: Value = resp.json().await.map_err(|e| format!("{path} JSON: {e}"))?;
        let enc_data = outer
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{path}: unexpected response {outer}"))?;
        let decrypted = aes_decrypt(enc_data, s.key.as_bytes(), s.iv.as_bytes())?;
        let inner: Value =
            serde_json::from_str(&decrypted).map_err(|e| format!("{path} inner JSON: {e}"))?;

        if inner.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!("{path}: router error {inner}"));
        }
        Ok(inner.get("data").cloned().unwrap_or(Value::Null))
    }
}

/// Pull the sysauth token out of a Set-Cookie header value.
fn extract_sysauth(cookie: &str) -> Option<String> {
    let start = cookie.find("sysauth=")? + "sysauth=".len();
    let rest = &cookie[start..];
    let end = rest.find([';', ',']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_answer() {
        // md5("ab" + "c") == md5("abc")
        assert_eq!(md5_hex("ab", "c"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex("", ""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn aes_round_trip() {
        let key = b"0123456789abcdef"; // 16-byte ASCII key, as the router uses
        let iv = b"fedcba9876543210";
        for plain in ["", "operation=login&password=deadbeef&confirm=true", "x"] {
            let enc = aes_encrypt(plain, key, iv);
            let dec = aes_decrypt(&enc, key, iv).unwrap();
            assert_eq!(dec, plain);
        }
    }

    #[test]
    fn rsa_block_length_matches_modulus() {
        // 512-bit signing-style key: output must be exactly 64 bytes (128 hex).
        let n = "DBBF149B525796DCB380BE29E25A64022443BE0F315822414DAC9FC54F4CBC82\
                 B4C2F0CC97D433909939DD1526C8D3E0C41AB2F8117F6E300C0CCC30EAFAF9D1";
        let out = rsa_encrypt_block(b"h=abc&s=123", n, "010001").unwrap();
        assert_eq!(out.len(), 128, "512-bit RSA block should be 128 hex chars");
    }

    #[test]
    fn rsa_rejects_oversized_message() {
        let n = "DBBF149B525796DCB380BE29E25A64022443BE0F315822414DAC9FC54F4CBC82\
                 B4C2F0CC97D433909939DD1526C8D3E0C41AB2F8117F6E300C0CCC30EAFAF9D1";
        // 54 bytes > 64-11 for the 512-bit key.
        assert!(rsa_encrypt_block(&[b'a'; 54], n, "010001").is_err());
    }

    #[test]
    fn signature_chunks_at_53() {
        let n = "DBBF149B525796DCB380BE29E25A64022443BE0F315822414DAC9FC54F4CBC82\
                 B4C2F0CC97D433909939DD1526C8D3E0C41AB2F8117F6E300C0CCC30EAFAF9D1";
        // A login sign string > 53 chars must span 2 blocks => 256 hex chars.
        let sig = build_signature(
            999_999_999,
            true,
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef",
            "fedcba9876543210",
            n,
            "010001",
        )
        .unwrap();
        assert_eq!(sig.len() % 128, 0);
        assert!(sig.len() >= 256, "login signature should need >=2 RSA blocks");
    }
}
