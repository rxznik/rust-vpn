//! Разбор share-ссылок в `rvpn_model::Server`.
//!
//! Схемы: vless, vmess, trojan, ss, socks, socks5, hysteria2, hy2, wireguard.
//! `happ://crypt4`, `happ://crypt5` и `happ://crypto` возвращают `EncryptedHappLink`.
//! `server_id` стабилен для пары (id подписки, сырой текст) и занимает 16 hex-символов.
//! Query `fragment` и `noises` пишутся в `Server` как есть, списком через запятую.
//! Сборщика ссылки из `Server` в этом крейте нет.

use rvpn_model::{Fragment, Noise, Protocol, Server};
use sha2::{Digest, Sha256};
use url::Url;

mod common;
mod hysteria;
mod shadowsocks;
mod socks;
mod trojan;
mod vless;
mod vmess;
mod wireguard;

use common::{hex_encode, maybe_b64_text, percent_decode, query_map, query_pairs};
pub use common::{b64_decode, encode_b64};

/// Why a share link was rejected.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("encrypted Happ links need a private key that is not embedded in this client")]
    EncryptedHappLink,
    #[error("unsupported link: {0}")]
    Unsupported(String),
    #[error("invalid link: {0}")]
    Invalid(String),
}

/// First 8 bytes of SHA-256 over the subscription id, a newline, and the raw link, as 16 hex characters.
pub fn server_id(subscription_id: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subscription_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(raw.as_bytes());
    hex_encode(&hasher.finalize()[..8])
}

/// Parses one Happ share link into a [`Server`].
pub fn parse_server(raw: &str, subscription_id: Option<&str>) -> Result<Server, LinkError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(LinkError::Invalid("empty link".into()));
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("happ://crypt4/") || lower.starts_with("happ://crypt5/") || lower.starts_with("happ://crypto") {
        return Err(LinkError::EncryptedHappLink);
    }
    let (url_part, fragment_name, description) = split_name(raw);
    let server = if lower.starts_with("vmess://") {
        vmess::parse_vmess(url_part)?
    } else if lower.starts_with("ss://") && !url_part[5..].contains('@') {
        shadowsocks::parse_ss_legacy(url_part)?
    } else {
        let url = Url::parse(url_part).map_err(|e| LinkError::Invalid(e.to_string()))?;
        match url.scheme() {
            "vless" => vless::parse_vless(&url)?,
            "trojan" => trojan::parse_trojan(&url)?,
            "ss" => shadowsocks::parse_ss_sip002(&url)?,
            "socks" | "socks5" => socks::parse_socks(url_part, &url, false)?,
            "hysteria2" | "hy2" => hysteria::parse_hy2(&url)?,
            "wireguard" => wireguard::parse_wireguard(&url)?,
            other => return Err(LinkError::Unsupported(other.into())),
        }
    };
    let mut server = server;
    reject_incomplete(&server)?;
    if !fragment_name.is_empty() {
        server.name = fragment_name;
    }
    if server.name.is_empty() {
        server.name = server.endpoint();
    }
    server.description = description.or(server.description);
    apply_fragment_params(&mut server, url_part);
    server.raw_link = Some(raw.to_string());
    let sub = subscription_id.unwrap_or("");
    server.subscription_id = subscription_id.map(|s| s.to_string());
    server.id = server_id(sub, raw);
    Ok(server)
}

fn reject_incomplete(server: &Server) -> Result<(), LinkError> {
    if server.address.is_empty() {
        return Err(LinkError::Invalid("empty host".into()));
    }
    match &server.protocol {
        Protocol::Vless { uuid, .. } | Protocol::Vmess { uuid, .. } if uuid.is_empty() => Err(LinkError::Invalid("empty uuid".into())),
        Protocol::Trojan { password, .. } if password.is_empty() => Err(LinkError::Invalid("empty uuid".into())),
        _ => Ok(()),
    }
}

fn split_name(raw: &str) -> (&str, String, Option<String>) {
    let Some(hash) = raw.find('#') else {
        return (raw, String::new(), None);
    };
    let (head, frag) = raw.split_at(hash);
    let frag = &frag[1..];
    let decoded = percent_decode(frag);
    let (name, extra) = match decoded.split_once('?') {
        Some((name, extra)) => (name, Some(extra)),
        None => (decoded.as_str(), None),
    };
    let description = extra.and_then(|q| query_map(q).get("serverdescription").cloned().and_then(|v| maybe_b64_text(&v)));
    (head, name.to_string(), description)
}

fn apply_fragment_params(server: &mut Server, url_part: &str) {
    let Ok(url) = Url::parse(url_part) else {
        return;
    };
    let query = query_pairs(&url);
    if let Some(fragment) = query.get("fragment").and_then(|v| parse_fragment(v)) {
        server.fragment = Some(fragment);
    }
    if let Some(noise) = query.get("noises").and_then(|v| parse_noise(v)) {
        server.noise = Some(noise);
    }
    if server.description.is_none() {
        if let Some(desc) = query.get("serverdescription").and_then(|v| maybe_b64_text(v)) {
            server.description = Some(desc);
        }
    }
}

pub fn parse_fragment(value: &str) -> Option<Fragment> {
    let parts: Vec<&str> = value.split(',').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(Fragment {
        length: parts[0].to_string(),
        interval: parts[1].to_string(),
        packets: parts[2].to_string(),
        max_split: parts.get(3).map(|s| (*s).to_string()),
    })
}

pub fn parse_noise(value: &str) -> Option<Noise> {
    let parts: Vec<&str> = value.split(',').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(Noise {
        kind: parts[0].to_string(),
        packet: parts[1].to_string(),
        delay: parts[2].to_string(),
        apply_to: parts.get(3).map(|s| (*s).to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rvpn_model::{Protocol, Security};

    const VLESS: &str = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=reality&pbk=qGPTy8EZokn3hWp6hKBQ0MVvEuLRJCcv5UdWeP4TVhI&headerType=none&type=tcp&sni=www.example.com&fp=chrome&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#Example";

    #[test]
    fn parses_vless_reality() {
        let server = parse_server(VLESS, Some("sub")).unwrap();
        assert_eq!(server.name, "Example");
        assert_eq!(server.address, "203.0.113.10");
        assert_eq!(server.port, 443);
        match server.protocol {
            Protocol::Vless { uuid, flow, transport, security, .. } => {
                assert_eq!(uuid, "11111111-1111-4111-8111-111111111111");
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
                assert_eq!(transport.network, "tcp");
                match security {
                    Security::Reality(r) => {
                        assert_eq!(r.server_name, "www.example.com");
                        assert_eq!(r.public_key, "qGPTy8EZokn3hWp6hKBQ0MVvEuLRJCcv5UdWeP4TVhI");
                        assert_eq!(r.short_id, "6ba85179e30d4fc2");
                        assert_eq!(r.fingerprint.as_deref(), Some("chrome"));
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_vless_websocket() {
        let raw = "vless://11111111-1111-4111-8111-111111111111@example.com:8443?encryption=none&security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=www.example.com#Ws";
        let server = parse_server(raw, None).unwrap();
        assert_eq!(server.address, "example.com");
        assert_eq!(server.port, 8443);
        match server.protocol {
            Protocol::Vless { transport, security, .. } => {
                assert_eq!(transport.network, "ws");
                assert_eq!(transport.path.as_deref(), Some("/ws"));
                assert_eq!(transport.host.as_deref(), Some("cdn.example.com"));
                match security {
                    Security::Tls(tls) => assert_eq!(tls.sni.as_deref(), Some("www.example.com")),
                    other => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_fragment_and_description() {
        let raw = "trojan://secret@203.0.113.8:443?security=tls&type=ws&path=%2Fws&host=cdn.example&sni=cdn.example&fragment=3,1,tlshello&noises=rand,50-150,10-50,ip#Node?serverDescription=SGFwcCB0aGUgYmVzdA==";
        let server = parse_server(raw, None).unwrap();
        assert_eq!(server.name, "Node");
        assert_eq!(server.description.as_deref(), Some("Happ the best"));
        assert_eq!(server.fragment.as_ref().unwrap().packets, "tlshello");
        assert_eq!(server.fragment.as_ref().unwrap().length, "3");
        assert_eq!(server.noise.as_ref().unwrap().kind, "rand");
        assert_eq!(server.noise.as_ref().unwrap().apply_to.as_deref(), Some("ip"));
        match server.protocol {
            Protocol::Trojan { password, transport, .. } => {
                assert_eq!(password, "secret");
                assert_eq!(transport.network, "ws");
                assert_eq!(transport.path.as_deref(), Some("/ws"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_vmess_ss_socks_hy2() {
        let vmess_json = r#"{"v":"2","ps":"vm","add":"203.0.113.9","port":"10086","id":"22222222-2222-4222-8222-222222222222","aid":"0","scy":"auto","net":"tcp","type":"none","tls":"tls","sni":"ex.com"}"#;
        let vmess = format!("vmess://{}", STANDARD.encode(vmess_json.as_bytes()));
        let vm = parse_server(&vmess, None).unwrap();
        assert_eq!(vm.name, "vm");
        assert!(matches!(vm.protocol, Protocol::Vmess { .. }));

        let ss = parse_server("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@203.0.113.4:8388#ssnode", None).unwrap();
        match ss.protocol {
            Protocol::Shadowsocks { method, password, .. } => {
                assert_eq!(method, "aes-256-gcm");
                assert_eq!(password, "password");
            }
            other => panic!("unexpected {other:?}"),
        }

        let socks = parse_server("socks://user:pass@203.0.113.5:1080#sock", None).unwrap();
        match socks.protocol {
            Protocol::Socks { username, password } => {
                assert_eq!(username.as_deref(), Some("user"));
                assert_eq!(password.as_deref(), Some("pass"));
            }
            other => panic!("unexpected {other:?}"),
        }

        let hy = parse_server("hy2://s3cret@203.0.113.6:443?sni=hy.example&insecure=1&obfs=salamander&obfs-password=ob#hy", None).unwrap();
        match hy.protocol {
            Protocol::Hysteria2 { password, sni, insecure, obfs, .. } => {
                assert_eq!(password, "s3cret");
                assert_eq!(sni.as_deref(), Some("hy.example"));
                assert!(insecure);
                assert_eq!(obfs.as_deref(), Some("salamander"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_happ_crypt_links() {
        let err = parse_server("happ://crypt4/aabb", None).unwrap_err();
        assert!(matches!(err, LinkError::EncryptedHappLink));
    }

    #[test]
    fn legacy_ss_wireguard_ipv6_and_crypt5() {
        let legacy = parse_server(&format!("ss://{}#old", STANDARD.encode(b"aes-256-gcm:secret@203.0.113.4:8388")), None).unwrap();
        match legacy.protocol {
            Protocol::Shadowsocks { method, password, .. } => {
                assert_eq!(method, "aes-256-gcm");
                assert_eq!(password, "secret");
            }
            other => panic!("unexpected {other:?}"),
        }
        let wg = parse_server("wireguard://c2VjcmV0@[2001:db8::1]:51820?publickey=cHVi&address=10.0.0.2/32", None).unwrap();
        assert!(wg.address.contains("2001:db8::1"));
        assert!(matches!(wg.protocol, Protocol::Wireguard(_)));
        assert!(matches!(parse_server("happ://crypt5/aabb", None), Err(LinkError::EncryptedHappLink)));
        assert!(matches!(parse_server("vless://@203.0.113.10:443", None), Err(LinkError::Invalid(_))));
        let body = STANDARD.encode(b"user:pass@203.0.113.5:1080");
        let socks = parse_server(&format!("socks://{body}"), None).unwrap();
        match socks.protocol {
            Protocol::Socks { username, password } => {
                assert_eq!(username.as_deref(), Some("user"));
                assert_eq!(password.as_deref(), Some("pass"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse_server("vmess://not-base64", None).is_err());
    }

    #[test]
    fn rejects_empty_host_and_empty_uuid() {
        assert!(matches!(parse_server("vless://11111111-1111-4111-8111-111111111111@?encryption=none", None), Err(LinkError::Invalid(_))));
        assert!(matches!(parse_server("vless://@example.com:443?encryption=none", None), Err(LinkError::Invalid(_))));
        let empty_host = format!("vmess://{}", STANDARD.encode(br#"{"add":"","port":"443","id":"11111111-1111-4111-8111-111111111111"}"#));
        assert!(matches!(parse_server(&empty_host, None), Err(LinkError::Invalid(_))));
        let empty_id = format!("vmess://{}", STANDARD.encode(br#"{"add":"example.com","port":"443"}"#));
        assert!(matches!(parse_server(&empty_id, None), Err(LinkError::Invalid(_))));
        assert!(matches!(parse_server("trojan://secret@?security=tls", None), Err(LinkError::Invalid(_))));
        assert!(matches!(parse_server("trojan://@example.com:443", None), Err(LinkError::Invalid(_))));
        let socks = parse_server("socks://example.com:1080", None).unwrap();
        assert_eq!(socks.address, "example.com");
        assert!(matches!(socks.protocol, Protocol::Socks { username: None, password: None }));
        assert!(matches!(parse_server("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@", None), Err(LinkError::Invalid(_))));
    }

    #[test]
    fn server_id_is_stable() {
        let a = parse_server(VLESS, Some("sub")).unwrap();
        let b = parse_server(VLESS, Some("sub")).unwrap();
        assert_eq!(a.id, b.id);
        let c = parse_server(VLESS, Some("other")).unwrap();
        assert_ne!(a.id, c.id);
    }
}
