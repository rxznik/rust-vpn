//! Загрузка и разбор подписки Happ.
//!
//! Заголовки запроса задаёт вызывающий код. На смене хоста при редиректе
//! срезаются x-hwid, x-device-os, x-ver-os, x-device-model.
//! Тело с заголовком encrypt-tag расшифровывается AES-128-GCM.
//! Nonce фиксирован и описан у константы GCM_IV.
//! DoH принимает только четыре хоста из DNS_HOSTS и отвергает частные A-записи.
//! Каждый адрес подписки проверяется до соединения: частный, loopback, link-local,
//! CGNAT и ULA отвергаются. Исходный hop на `127.0.0.1`, `::1` или `localhost` остаётся.
//! new-url и new-domain применяются внутри того же сайта.

use std::collections::BTreeMap;
use rvpn_model::{Server, SubscriptionKind, SubscriptionMeta, UserInfo};
use url::Url;

mod crypto;
mod fetch;
mod meta;

pub use crypto::{decrypt_body, encrypt_body};
pub use fetch::{blocked_ip, fetch_subscription, resolve_ipv4};
pub use meta::{apply_url_rewrite, hwid_query, key_query, parse_subscription, update_due, with_query};


/// Fetch, decrypt, or parse failure. [`Display`] is what the UI shows.
#[derive(Debug, thiserror::Error)]
pub enum SubError {
    #[error("{0}")]
    Message(String),
    #[error("http {status}: {detail}")]
    Http { status: u16, detail: String },
    #[error("{0}")]
    Decrypt(String),
    #[error("{0}")]
    Dns(String),
    #[error("encrypted Happ links need a private key that is not embedded in this client")]
    EncryptedHappLink,
    #[error("subscription body is encrypted and key `{0}` is not in the local registry")]
    MissingKey(String),
}

pub struct FetchOutput {
    pub url: String,
    pub body: String,
    pub headers: BTreeMap<String, String>,
}

pub struct ParsedSubscription {
    pub name: Option<String>,
    pub kind: SubscriptionKind,
    pub raw_json: Option<String>,
    pub servers: Vec<Server>,
    pub userinfo: Option<UserInfo>,
    pub meta: SubscriptionMeta,
    pub routing_links: Vec<String>,
}


fn host_of(url: &str) -> Option<String> {
    let host = Url::parse(url).ok().and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))?;
    Some(host.trim_matches(['[', ']']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fetch::{ensure_public_destination, ensure_public_with, join_redirect, maybe_decrypt, resolver_url};
    use super::meta::apply_pair;
    use rvpn_model::{PerAppMode, Protocol, Subscription};
    use std::io::{Read, Write};
    use std::net::{IpAddr, TcpListener};
    use std::thread;

    #[test]
    fn meta_from_headers_and_body() {
        let mut headers = BTreeMap::new();
        headers.insert("profile-title".into(), "Name VPN".into());
        headers.insert("subscription-userinfo".into(), "upload=0; download=2048; total=4096; expire=1790951622".into());
        headers.insert("routing".into(), "happ://routing/off".into());
        let body = "#announce: base64:SGFwcA==\n#fragmentation-enable: 1\n#fragmentation-length: 10-20\nvless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#a\nhapp://routing/off\n";
        let parsed = parse_subscription(body, &headers, "sub").unwrap();
        assert_eq!(parsed.name.as_deref(), Some("Name VPN"));
        assert_eq!(parsed.userinfo.as_ref().unwrap().download, 2048);
        assert_eq!(parsed.meta.announce.as_deref(), Some("Happ"));
        assert!(parsed.meta.fragmentation_enable);
        assert_eq!(parsed.meta.fragmentation.as_ref().unwrap().length, "10-20");
        assert_eq!(parsed.servers.len(), 1);
        assert!(parsed.routing_links.iter().any(|link| link == "happ://routing/off"));
        assert!(parsed.meta.extra.contains_key("routing"));
    }

    #[test]
    fn aes_gcm_roundtrip_uses_separate_tag() {
        let key = b"0123456789abcdef";
        let (body, tag) = encrypt_body(key, b"vless://example").unwrap();
        let plain = decrypt_body(key, &body, &tag).unwrap();
        assert_eq!(plain, b"vless://example");
    }

    #[test]
    fn maybe_decrypt_succeeds_with_caller_key() {
        let key = b"0123456789abcdef";
        let plain = "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none#Example\n";
        let (body, tag) = encrypt_body(key, plain.as_bytes()).unwrap();
        let mut headers = BTreeMap::new();
        headers.insert("encrypt-tag".into(), tag);
        let decrypted = maybe_decrypt("https://example.com/sub", &body, &headers, Some(key)).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn fallback_after_http_error() {
        let primary = serve("500 Internal Server Error", "nope");
        let fallback = serve("200 OK", "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none#ok\n");
        let output = fetch_subscription(&format!("http://127.0.0.1:{primary}/"), Some(&format!("http://127.0.0.1:{fallback}/")), &[], None).unwrap();
        assert!(output.body.contains("vless://"));
        assert!(output.url.contains(&fallback.to_string()));
    }

    #[test]
    fn rewrite_stays_on_the_same_site() {
        let mut meta = SubscriptionMeta::default();
        meta.new_url = Some("https://evil.example/x".into());
        assert_eq!(apply_url_rewrite("https://cdn.example/sub", &meta), "https://cdn.example/sub");
        meta.new_url = Some("https://sub.cdn.example/x".into());
        assert_eq!(apply_url_rewrite("https://cdn.example/sub", &meta), "https://sub.cdn.example/x");
        meta.new_url = None;
        meta.new_domain = Some("evil.example".into());
        assert_eq!(apply_url_rewrite("https://cdn.example/sub", &meta), "https://cdn.example/sub");
    }

    #[test]
    fn blocked_addresses_are_not_dialed() {
        assert!(blocked_ip("127.0.0.1"));
        assert!(blocked_ip("10.1.2.3"));
        assert!(blocked_ip("169.254.1.1"));
        assert!(blocked_ip("100.64.0.1"));
        assert!(!blocked_ip("203.0.113.10"));
        assert!(resolver_url("http://dns.google/resolve").is_err());
        assert!(resolver_url("https://evil.example/dns-query").is_err());
        assert!(resolver_url("https://dns.google/resolve").is_ok());
    }

    #[test]
    fn blocked_hops_are_rejected_before_dial() {
        assert!(ensure_public_destination(Some("127.0.0.1"), "http://127.0.0.1/panel").is_ok());
        assert!(ensure_public_destination(Some("localhost"), "http://127.0.0.1/panel").is_ok());
        assert!(ensure_public_destination(Some("::1"), "http://[::1]/panel").is_ok());
        assert!(ensure_public_destination(Some("example.com"), "http://10.0.0.1/latest").is_err());
        assert!(ensure_public_destination(Some("example.com"), "http://169.254.169.254/").is_err());
        assert!(ensure_public_destination(Some("example.com"), "http://127.0.0.1/").is_err());
        assert!(ensure_public_destination(Some("10.0.0.1"), "http://10.0.0.1/").is_err());
        assert!(ensure_public_destination(Some("localhost"), "http://169.254.169.254/").is_err());
        let private_hop = join_redirect("https://example.com/sub", "http://10.0.0.1/x").unwrap();
        assert!(ensure_public_destination(Some("example.com"), &private_hop).is_err());
        let link_local = join_redirect("https://example.com/sub", "http://169.254.169.254/").unwrap();
        assert!(ensure_public_destination(Some("example.com"), &link_local).is_err());
        fn to_private(_: &str) -> Result<Vec<IpAddr>, SubError> {
            Ok(vec!["10.0.0.1".parse().unwrap()])
        }
        assert!(ensure_public_with(Some("example.com"), "https://example.com/sub", to_private).is_err());
        fn to_metadata(_: &str) -> Result<Vec<IpAddr>, SubError> {
            Ok(vec!["169.254.169.254".parse().unwrap()])
        }
        assert!(ensure_public_with(Some("example.com"), "https://example.com/sub", to_metadata).is_err());
    }

    #[test]
    fn link_lines_with_no_servers_are_an_error() {
        let Err(err) = parse_subscription("https://example.com/list\n", &BTreeMap::new(), "sub") else {
            panic!("https-only body must fail");
        };
        assert!(matches!(err, SubError::Message(_)));
        let body = "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none#a\nhttps://example.com/skip\n";
        let Ok(parsed) = parse_subscription(body, &BTreeMap::new(), "sub") else {
            panic!("one valid server must remain");
        };
        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].address, "example.com");
        assert!(matches!(parse_subscription("happ://crypt4/aabb\n", &BTreeMap::new(), "sub"), Err(SubError::EncryptedHappLink)));
    }

    #[test]
    fn interval_is_due_when_missed() {
        let mut sub = Subscription::local(0);
        sub.url = Some("https://example.invalid/sub".into());
        sub.meta.update_interval_hours = Some(1);
        sub.updated_at = Some(0);
        assert!(update_due(&sub, 3600, false));
        assert!(!update_due(&sub, 10, false));
        sub.meta.extra.insert("subscription-auto-update-enable".into(), "0".into());
        assert!(!update_due(&sub, 99999, false));
    }

    #[test]
    fn redirect_to_another_host_drops_hwid_and_bad_crypto_is_typed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else { return };
            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]);
            assert!(!text.to_ascii_lowercase().contains("x-hwid"), "{text}");
            let body = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none#ok\n";
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = socket.write_all(resp.as_bytes());
        });
        let primary = serve_redirect(&format!("http://127.0.0.1:{port}/next"));
        let output = fetch_subscription(
            &format!("http://localhost:{primary}/start"),
            None,
            &[("x-hwid", "abc"), ("user-agent", "rustvpn/0.1")],
            None,
        )
        .unwrap();
        assert!(output.body.contains("vless://"));
        assert!(matches!(decrypt_body(b"0123456789abcdef", "aaaa", "bbbb"), Err(SubError::Decrypt(_))));
        assert!(matches!(maybe_decrypt("https://cdn.example/sub", "body", &{
            let mut headers = BTreeMap::new();
            headers.insert("encrypt-tag".into(), "dGFn".into());
            headers
        }, None), Err(SubError::MissingKey(_))));
    }

    #[test]
    fn json_subscription_and_per_app_invert_and_ipv6() {
        let body = r#"{"outbounds":[{"protocol":"freedom"}]}"#;
        let parsed = parse_subscription(body, &BTreeMap::new(), "sub").unwrap();
        assert!(matches!(parsed.servers[0].protocol, Protocol::Json { .. }));
        let mut meta = SubscriptionMeta::default();
        let mut name = None;
        let mut userinfo = None;
        apply_pair(&mut meta, &mut name, &mut userinfo, "per-app-proxy-list-invert", "com.a,com.b");
        assert_eq!(meta.per_app_mode, Some(PerAppMode::Bypass));
        assert_eq!(meta.per_app_list, vec!["com.a".to_string(), "com.b".to_string()]);
        assert!(blocked_ip("::1"));
        assert!(blocked_ip("fe80::1"));
        assert!(!blocked_ip("2001:db8::1"));
    }

    fn serve_redirect(location: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let location = location.to_string();
        thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else { return };
            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]);
            assert!(text.to_ascii_lowercase().contains("x-hwid"));
            let resp = format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = socket.write_all(resp.as_bytes());
        });
        port
    }

    fn serve(status: &str, body: &str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let status = status.to_string();
        let body = body.to_string();
        thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else { return };
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf);
            let resp = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let _ = socket.write_all(resp.as_bytes());
        });
        port
    }
}
