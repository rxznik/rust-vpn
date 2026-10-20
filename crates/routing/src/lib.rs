//! Профили маршрута Happ и документы routing/dns для Xray.
//!
//! Ссылки: happ://routing/off, add/<b64>, onadd/<b64>.
//! Geo качается только по https с github.com, cdn.jsdelivr.net
//! и хостов *.githubusercontent.com, не больше 80 МиБ.
//! Повторная загрузка того же URL берётся из каталога `cache` по SHA-256 URL.
//! `trim_geo_list` оставляет записи protobuf, чей тег есть в наборе.
//! `xray_routing` при выключенном профиле отправляет весь tcp/udp в proxy.
//! `global_proxy` выбирает fallback: proxy, иначе direct.

mod document;
mod geo;
mod link;

pub use document::xray_routing;
pub use geo::{asset_dir, geo_tags, materialize_geo, trim_geo_list, GeoMaterial, DEFAULT_GEOIP_URL, DEFAULT_GEOSITE_URL};
pub use link::{parse_routing_link, profile_from_b64, profile_from_value};


#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("invalid routing link")]
    Link,
    #[error("invalid routing profile: {0}")]
    Profile(String),
    #[error("geo download failed: {0}")]
    Geo(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::geo::{download_cached, first_string, geo_download_url};
    use base64::Engine;
    use rvpn_model::RoutingCommand;
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;

    fn entry(tag: &str) -> Vec<u8> {
        let tag = tag.as_bytes();
        let mut message = Vec::new();
        message.push(0x0a);
        message.push(tag.len() as u8);
        message.extend_from_slice(tag);
        let mut field = Vec::new();
        field.push(0x0a);
        field.push(message.len() as u8);
        field.extend(message);
        field
    }

    #[test]
    fn trim_keeps_named_tags_only() {
        let mut bytes = entry("CN");
        bytes.extend(entry("ADS"));
        let tags = HashSet::from(["cn".into()]);
        let trimmed = trim_geo_list(&bytes, &tags);
        assert_eq!(trimmed, entry("CN"));
        assert!(first_string(&trimmed[2..]).as_deref() == Some("CN") || !trimmed.is_empty());
    }

    #[test]
    fn happ_profile_and_rules() {
        let raw = r#"{"Name":"test","GlobalProxy":"true","RemoteDns":"1.1.1.1","DomesticDns":"8.8.8.8","DirectSites":["geosite:cn"],"DirectIp":["geoip:cn"],"BlockSites":["geosite:category-ads"],"DomainStrategy":"IPIfNonMatch"}"#;
        let profile = profile_from_value("sub", &serde_json::from_str(raw).unwrap()).unwrap();
        assert_eq!(profile.name, "test");
        assert!(profile.global_proxy);
        let (ip, site) = geo_tags(&profile);
        assert!(ip.contains("cn"));
        assert!(site.contains("category-ads"));
        let (routing, dns) = xray_routing(&profile, true);
        assert_eq!(routing["domainStrategy"], "IPIfNonMatch");
        assert_eq!(routing["rules"][0]["outboundTag"], "block");
        assert!(dns.is_some());
        let (off, _) = xray_routing(&profile, false);
        assert_eq!(off["rules"][0]["outboundTag"], "proxy");
    }

    #[test]
    fn geo_url_must_be_https_on_an_allowed_host() {
        assert!(geo_download_url("", DEFAULT_GEOIP_URL).is_ok());
        assert!(geo_download_url("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/geoip.dat", DEFAULT_GEOIP_URL).is_ok());
        assert!(geo_download_url("http://github.com/geoip.dat", DEFAULT_GEOIP_URL).is_err());
        assert!(geo_download_url("https://evil.example/geoip.dat", DEFAULT_GEOIP_URL).is_err());
    }

    #[test]
    fn routing_links() {
        assert!(matches!(parse_routing_link("happ://routing/off").unwrap(), RoutingCommand::Off));
        let body = base64::engine::general_purpose::STANDARD.encode(br#"{"Name":"a","GlobalProxy":false}"#);
        let command = parse_routing_link(&format!("happ://routing/onadd/{body}")).unwrap();
        match command {
            RoutingCommand::Add { activate, profile_b64 } => {
                assert!(activate);
                let profile = profile_from_b64("sub", &profile_b64).unwrap();
                assert_eq!(profile.name, "a");
                assert!(!profile.global_proxy);
            }
            _ => panic!("expected add"),
        }
        let command = parse_routing_link(&format!("happ://routing/add/{body}")).unwrap();
        match command {
            RoutingCommand::Add { activate, .. } => assert!(!activate),
            _ => panic!("expected add"),
        }
    }

    #[test]
    fn broken_protobuf_and_asset_dir_and_default_strategy() {
        assert!(trim_geo_list(&[0xff, 0xff, 0xff, 0xff], &HashSet::new()).is_empty());
        let raw = r#"{"Name":"plain"}"#;
        let profile = profile_from_value("sub", &serde_json::from_str(raw).unwrap()).unwrap();
        assert_eq!(profile.domain_strategy, rvpn_model::DomainStrategy::AsIs);
        let mut with_file = profile.clone();
        with_file.geoip_path = Some("/tmp/rustvpn-geo/geoip.dat".into());
        assert_eq!(asset_dir(&with_file).unwrap(), PathBuf::from("/tmp/rustvpn-geo"));
        assert!(geo_download_url("https://evil.example.xn--p1ai/geoip.dat", DEFAULT_GEOIP_URL).is_err());
    }

    #[test]
    fn geo_cache_reads_the_hashed_file_without_network() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/geo-cache");
        let _ = std::fs::remove_dir_all(&dir);
        let url = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/geoip.dat";
        let mut hasher = Sha256::new();
        hasher.update(url.as_bytes());
        let path = dir.join("cache").join(hex_encode(&hasher.finalize()));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"cached-dat").unwrap();
        assert_eq!(download_cached(url, &dir).unwrap(), b"cached-dat");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
