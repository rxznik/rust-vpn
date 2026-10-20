use super::{host_of, FetchOutput, SubError};
use crate::crypto::decrypt_body;
use crate::meta::key_query;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;

const FETCH_TIMEOUT: Duration = Duration::from_secs(9);
const BODY_LIMIT: u64 = 10 * 1024 * 1024;
/// DoH hosts the client will query: dns.google, cloudflare-dns.com, one.one.one.one, dns.quad9.net.
const DNS_HOSTS: &[&str] = &["dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net"];

pub fn fetch_subscription(primary: &str, fallback: Option<&str>, headers: &[(&str, &str)], key: Option<&[u8]>) -> Result<FetchOutput, SubError> {
    match fetch_one(primary, headers, fallback.is_some()) {
        Ok(mut output) => {
            output.body = maybe_decrypt(&output.url, &output.body, &output.headers, key)?;
            Ok(output)
        }
        Err(primary_err) => {
            let Some(fallback) = fallback.filter(|u| !u.is_empty()) else {
                return Err(primary_err);
            };
            let mut output = fetch_one(fallback, headers, false)?;
            output.body = maybe_decrypt(&output.url, &output.body, &output.headers, key)?;
            Ok(output)
        }
    }
}

pub fn resolve_ipv4(resolver: &str, name: &str) -> Result<String, SubError> {
    if !dns_name_ok(name) {
        return Err(SubError::Dns("name is not a DNS label".into()));
    }
    let mut url = resolver_url(resolver)?;
    url.query_pairs_mut().append_pair("name", name).append_pair("type", "A");
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build()
        .get(url.as_str())
        .set("accept", "application/dns-json")
        .call()
        .map_err(|e| SubError::Dns(e.to_string()))?;
    let text = response.into_string().map_err(|e| SubError::Dns(e.to_string()))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| SubError::Dns(e.to_string()))?;
    let ip = value["Answer"]
        .as_array()
        .and_then(|answers| {
            answers.iter().find_map(|item| {
                if item.get("type").and_then(|t| t.as_u64()) == Some(1) {
                    item.get("data").and_then(|d| d.as_str()).map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| SubError::Dns(format!("no A record for {name}")))?;
    if blocked_ip(&ip) {
        return Err(SubError::Dns("resolved address is not a public address".into()));
    }
    Ok(ip)
}

pub(crate) fn resolver_url(resolver: &str) -> Result<Url, SubError> {
    let url = if resolver.starts_with("https://") {
        Url::parse(resolver).map_err(|e| SubError::Dns(e.to_string()))?
    } else if resolver.contains("://") {
        return Err(SubError::Dns("resolver must use https".into()));
    } else {
        Url::parse(&format!("https://{resolver}/dns-query")).map_err(|e| SubError::Dns(e.to_string()))?
    };
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    if !DNS_HOSTS.iter().any(|allowed| host == *allowed) {
        return Err(SubError::Dns("resolver host is not allowed".into()));
    }
    Ok(url)
}

fn dns_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.contains(['/', '?', '&', ' ', '\\'])
        && name.parse::<IpAddr>().is_err()
        && name.split('.').all(|label| !label.is_empty() && label.len() <= 63 && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

pub fn blocked_ip(ip: &str) -> bool {
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return true;
    };
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified() || v4.is_multicast() || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
}

fn explicit_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

/// Rejects a destination whose host is a blocked address or resolves to one.
/// The original user URL may stay on `127.0.0.1`, `::1`, or `localhost`.
pub(crate) fn ensure_public_destination(original_host: Option<&str>, url: &str) -> Result<(), SubError> {
    ensure_public_with(original_host, url, lookup_ips)
}

pub(crate) fn ensure_public_with(original_host: Option<&str>, url: &str, lookup: impl Fn(&str) -> Result<Vec<IpAddr>, SubError>) -> Result<(), SubError> {
    let host = host_of(url).ok_or_else(|| SubError::Message("subscription url has no host".into()))?;
    if original_host.is_some_and(explicit_loopback_host) && explicit_loopback_host(&host) {
        return Ok(());
    }
    if host.parse::<IpAddr>().is_ok() {
        if blocked_ip(&host) {
            return Err(SubError::Message("subscription address is not a public address".into()));
        }
        return Ok(());
    }
    if explicit_loopback_host(&host) {
        return Err(SubError::Message("subscription address is not a public address".into()));
    }
    let ips = lookup(&host)?;
    if ips.is_empty() || ips.iter().any(|ip| blocked_ip(&ip.to_string())) {
        return Err(SubError::Message("subscription address is not a public address".into()));
    }
    Ok(())
}

fn lookup_ips(host: &str) -> Result<Vec<IpAddr>, SubError> {
    let mut ips = Vec::new();
    for addr in (host, 0u16).to_socket_addrs().map_err(|err| SubError::Dns(err.to_string()))? {
        ips.push(addr.ip());
    }
    if ips.is_empty() {
        return Err(SubError::Dns(format!("no address for {host}")));
    }
    Ok(ips)
}

fn fetch_one(url: &str, headers: &[(&str, &str)], strict_status: bool) -> Result<FetchOutput, SubError> {
    let origin = host_of(url);
    let mut current = url.to_string();
    let mut hops = 0u8;
    let max_hops = if strict_status { 0 } else { 5 };
    loop {
        ensure_public_destination(origin.as_deref(), &current)?;
        let crossed = origin.as_ref().is_some_and(|origin| host_of(&current).as_deref() != Some(origin.as_str()));
        let agent = ureq::AgentBuilder::new().timeout(FETCH_TIMEOUT).redirects(0).build();
        let mut request = agent.get(&current);
        for (key, value) in headers {
            if crossed && sensitive_header(key) {
                continue;
            }
            request = request.set(key, value);
        }
        match request.call() {
            Ok(response) if (300..400).contains(&response.status()) && hops < max_hops => {
                let code = response.status();
                let location = response.header("location").map(|value| value.to_string()).ok_or_else(|| SubError::Http { status: code, detail: "missing location".into() })?;
                current = join_redirect(&current, &location)?;
                hops += 1;
            }
            Ok(response) => return read_body(&current, response),
            Err(ureq::Error::Status(code, response)) if (300..400).contains(&code) && hops < max_hops => {
                let location = response.header("location").map(|value| value.to_string()).ok_or_else(|| SubError::Http { status: code, detail: "missing location".into() })?;
                current = join_redirect(&current, &location)?;
                hops += 1;
            }
            Err(ureq::Error::Status(code, response)) if !strict_status && (200..300).contains(&code) => return read_body(&current, response),
            Err(ureq::Error::Status(code, _)) => return Err(SubError::Http { status: code, detail: format!("HTTP {code}") }),
            Err(err) => return Err(SubError::Http { status: 0, detail: err.to_string() }),
        }
    }
}

fn read_body(url: &str, response: ureq::Response) -> Result<FetchOutput, SubError> {
    if !(200..300).contains(&response.status()) {
        return Err(SubError::Http { status: response.status(), detail: format!("HTTP {}", response.status()) });
    }
    let headers = header_map(&response);
    let mut body = Vec::new();
    response.into_reader().take(BODY_LIMIT).read_to_end(&mut body).map_err(|e| SubError::Message(e.to_string()))?;
    let body = String::from_utf8_lossy(&body).into_owned();
    Ok(FetchOutput { url: url.to_string(), body, headers })
}

fn sensitive_header(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "x-hwid" | "x-device-os" | "x-ver-os" | "x-device-model")
}

pub(crate) fn join_redirect(current: &str, location: &str) -> Result<String, SubError> {
    let base = Url::parse(current).map_err(|e| SubError::Message(e.to_string()))?;
    let next = base.join(location).map_err(|e| SubError::Message(e.to_string()))?;
    if next.scheme() != "http" && next.scheme() != "https" {
        return Err(SubError::Message("redirect scheme is not http".into()));
    }
    Ok(next.to_string())
}

fn header_map(response: &ureq::Response) -> BTreeMap<String, String> {
    response
        .headers_names()
        .into_iter()
        .filter_map(|name| response.header(&name).map(|value| (name.to_ascii_lowercase(), value.to_string())))
        .collect()
}

pub(crate) fn maybe_decrypt(url: &str, body: &str, headers: &BTreeMap<String, String>, key: Option<&[u8]>) -> Result<String, SubError> {
    let Some(tag) = headers.get("encrypt-tag") else {
        return Ok(body.to_string());
    };
    let key_id = key_query(url).unwrap_or_else(|| "default".into());
    let Some(key) = key else {
        return Err(SubError::MissingKey(key_id));
    };
    let plain = decrypt_body(key, body.trim(), tag)?;
    String::from_utf8(plain).map_err(|e| SubError::Message(e.to_string()))
}
