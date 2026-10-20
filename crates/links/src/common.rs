use super::LinkError;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rvpn_model::{Protocol, Server, TlsSettings, Transport};
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

pub(crate) fn transport_from_query(query: &BTreeMap<String, String>) -> Transport {
    let network = query.get("type").cloned().unwrap_or_else(|| "tcp".into());
    let header = query.get("headertype").cloned().filter(|s| !s.is_empty() && s != "none");
    let path = query.get("path").cloned().filter(|s| !s.is_empty());
    let service_name = if network == "grpc" {
        query.get("servicename").cloned().or_else(|| path.clone())
    } else {
        query.get("servicename").cloned()
    };
    Transport {
        network,
        path,
        host: query.get("host").cloned().filter(|s| !s.is_empty()),
        service_name,
        header_type: header,
        mode: query.get("mode").cloned(),
        authority: query.get("authority").cloned(),
    }
}

pub(crate) fn tls_from_query(query: &BTreeMap<String, String>, url: &Url) -> TlsSettings {
    TlsSettings {
        sni: query.get("sni").cloned().or_else(|| query.get("peer").cloned()).or_else(|| Some(host_of(url))),
        alpn: query.get("alpn").map(|v| split_csv(v)).unwrap_or_default(),
        fingerprint: query.get("fp").cloned(),
        insecure: flag_on(query.get("insecure").map(|s| s.as_str())) || flag_on(query.get("allowinsecure").map(|s| s.as_str())),
        pinned_sha256: query.get("pinsha256").cloned(),
    }
}

pub(crate) fn bare_server(address: String, port: u16, protocol: Protocol) -> Server {
    Server {
        id: String::new(),
        subscription_id: None,
        name: format!("{address}:{port}"),
        address,
        port,
        protocol,
        description: None,
        fragment: None,
        noise: None,
        raw_link: None,
        delay_ms: None,
    }
}

pub(crate) fn query_pairs(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.into_owned()))
        .collect()
}

pub(crate) fn query_map(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k.is_empty() {
                None
            } else {
                Some((percent_decode(k).to_ascii_lowercase(), percent_decode(v)))
            }
        })
        .collect()
}

pub(crate) fn host_of(url: &Url) -> String {
    url.host_str().unwrap_or_default().to_string()
}

pub(crate) fn port_of(url: &Url, default: u16) -> u16 {
    url.port().unwrap_or(default)
}

pub(crate) fn split_method_password(text: &str) -> Result<(String, String), LinkError> {
    let (method, password) = text.split_once(':').ok_or_else(|| LinkError::Invalid("method:password".into()))?;
    Ok((method.to_string(), password.to_string()))
}

pub(crate) fn split_host_port(hostport: &str, default: u16) -> Result<(String, u16), LinkError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(|| LinkError::Invalid("ipv6 host".into()))?;
        let port = port.parse().map_err(|_| LinkError::Invalid("port".into()))?;
        return Ok((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) => Ok((host.to_string(), port.parse().map_err(|_| LinkError::Invalid("port".into()))?)),
        None => Ok((hostport.to_string(), default)),
    }
}

pub(crate) fn json_str(obj: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

pub(crate) fn json_port(value: Option<&Value>) -> Option<u16> {
    match value? {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

pub(crate) fn split_csv(value: &str) -> Vec<String> {
    value.split(',').map(|s| percent_decode(s.trim())).filter(|s| !s.is_empty()).collect()
}

pub(crate) fn flag_on(value: Option<&str>) -> bool {
    matches!(value.map(|s| s.trim()), Some("1") | Some("true") | Some("TRUE"))
}

pub(crate) fn nonempty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

pub(crate) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn b64_decode(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let standard = trimmed.replace('-', "+").replace('_', "/");
    let pad = (4 - standard.len() % 4) % 4;
    let padded = format!("{standard}{}", "=".repeat(pad));
    STANDARD.decode(padded).ok()
}

pub(crate) fn maybe_b64_text(value: &str) -> Option<String> {
    let decoded = b64_decode(value)?;
    let text = String::from_utf8(decoded).ok()?;
    if text.chars().all(|c| !c.is_control()) && !text.is_empty() {
        Some(text)
    } else {
        Some(value.to_string())
    }
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

pub fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
