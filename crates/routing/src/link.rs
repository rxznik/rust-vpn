use super::RoutingError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rvpn_model::{DomainStrategy, RoutingCommand, RoutingProfile};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn parse_routing_link(link: &str) -> Result<RoutingCommand, RoutingError> {
    let link = link.trim();
    let rest = link.strip_prefix("happ://routing/").ok_or(RoutingError::Link)?;
    if rest == "off" {
        return Ok(RoutingCommand::Off);
    }
    if let Some(body) = rest.strip_prefix("onadd/") {
        return Ok(RoutingCommand::Add { activate: true, profile_b64: body.to_string() });
    }
    if let Some(body) = rest.strip_prefix("add/") {
        return Ok(RoutingCommand::Add { activate: false, profile_b64: body.to_string() });
    }
    Err(RoutingError::Link)
}

pub fn profile_from_b64(subscription_id: &str, body: &str) -> Result<RoutingProfile, RoutingError> {
    let bytes = decode_b64(body).ok_or_else(|| RoutingError::Profile("base64".into()))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| RoutingError::Profile(e.to_string()))?;
    profile_from_value(subscription_id, &value)
}

pub fn profile_from_value(subscription_id: &str, value: &Value) -> Result<RoutingProfile, RoutingError> {
    let obj = value.as_object().ok_or_else(|| RoutingError::Profile("object".into()))?;
    let name = string_field(obj, &["Name", "name"]).unwrap_or_else(|| "profile".into());
    let mut hasher = Sha256::new();
    hasher.update(subscription_id.as_bytes());
    hasher.update(serde_json::to_vec(value).unwrap_or_default());
    let id = super::hex_encode(&hasher.finalize()[..8]);
    Ok(RoutingProfile {
        id,
        subscription_id: subscription_id.to_string(),
        name,
        global_proxy: bool_field(obj, &["GlobalProxy", "globalProxy", "global_proxy"]).unwrap_or(true),
        remote_dns: string_field(obj, &["RemoteDns", "remoteDns", "remote_dns"]).unwrap_or_default(),
        domestic_dns: string_field(obj, &["DomesticDns", "domesticDns", "domestic_dns"]).unwrap_or_default(),
        geoip_url: string_field(obj, &["Geoipurl", "geoipurl", "geoipUrl", "geoip_url"]).unwrap_or_default(),
        geosite_url: string_field(obj, &["Geositeurl", "geositeurl", "geositeUrl", "geosite_url"]).unwrap_or_default(),
        dns_hosts: map_field(obj, &["DnsHosts", "dnsHosts", "dns_hosts"]),
        direct_sites: list_field(obj, &["DirectSites", "directSites", "direct_sites"]),
        direct_ip: list_field(obj, &["DirectIp", "directIp", "direct_ip"]),
        proxy_sites: list_field(obj, &["ProxySites", "proxySites", "proxy_sites"]),
        proxy_ip: list_field(obj, &["ProxyIp", "proxyIp", "proxy_ip"]),
        block_sites: list_field(obj, &["BlockSites", "blockSites", "block_sites"]),
        block_ip: list_field(obj, &["BlockIp", "blockIp", "block_ip"]),
        domain_strategy: string_field(obj, &["DomainStrategy", "domainStrategy", "domain_strategy"]).map(|value| DomainStrategy::parse(&value)).unwrap_or_default(),
        geoip_path: None,
        geosite_path: None,
    })
}

fn string_field(obj: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| obj.get(*key)).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn bool_field(obj: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    let value = keys.iter().find_map(|key| obj.get(*key))?;
    Some(match value {
        Value::Bool(v) => *v,
        Value::String(s) => s == "1" || s.eq_ignore_ascii_case("true"),
        Value::Number(n) => n.as_i64() == Some(1),
        _ => false,
    })
}

fn list_field(obj: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    let Some(Value::Array(items)) = keys.iter().find_map(|key| obj.get(*key)) else {
        return Vec::new();
    };
    items.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
}

fn map_field(obj: &Map<String, Value>, keys: &[&str]) -> std::collections::BTreeMap<String, String> {
    let Some(Value::Object(map)) = keys.iter().find_map(|key| obj.get(*key)) else {
        return std::collections::BTreeMap::new();
    };
    map.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()
}

fn decode_b64(value: &str) -> Option<Vec<u8>> {
    let standard = value.trim().replace('-', "+").replace('_', "/");
    let pad = (4 - standard.len() % 4) % 4;
    STANDARD.decode(format!("{standard}{}", "=".repeat(pad))).ok()
}
