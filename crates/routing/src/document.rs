//! Порядок правил `xray_routing` при включённом профиле: block, затем direct, затем proxy,
//! затем fallback. В каждой группе сначала домены, потом IP.
//! Если DNS задан адресом, перед fallback домашний DNS идёт в direct, удалённый — в proxy.
//! Fallback выбирает `global_proxy`: proxy, иначе direct.
//! Выключенный профиль отправляет весь tcp/udp в proxy.

use rvpn_model::{DomainStrategy, RoutingProfile, OUTBOUND_BLOCK, OUTBOUND_DIRECT, OUTBOUND_PROXY};
use serde_json::{json, Value};

pub fn xray_routing(profile: &RoutingProfile, enabled: bool) -> (Value, Option<Value>) {
    if !enabled {
        return (
            json!({
                "domainStrategy": DomainStrategy::AsIs,
                "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": OUTBOUND_PROXY}]
            }),
            None,
        );
    }
    let mut rules = Vec::new();
    push_domain(&mut rules, &profile.block_sites, OUTBOUND_BLOCK);
    push_ip(&mut rules, &profile.block_ip, OUTBOUND_BLOCK);
    push_domain(&mut rules, &profile.direct_sites, OUTBOUND_DIRECT);
    push_ip(&mut rules, &profile.direct_ip, OUTBOUND_DIRECT);
    push_domain(&mut rules, &profile.proxy_sites, OUTBOUND_PROXY);
    push_ip(&mut rules, &profile.proxy_ip, OUTBOUND_PROXY);
    if let Some(ip) = host_only(&profile.domestic_dns) {
        rules.push(json!({"type": "field", "ip": [ip], "outboundTag": OUTBOUND_DIRECT}));
    }
    if let Some(ip) = host_only(&profile.remote_dns) {
        rules.push(json!({"type": "field", "ip": [ip], "outboundTag": OUTBOUND_PROXY}));
    }
    let fallback = if profile.global_proxy { OUTBOUND_PROXY } else { OUTBOUND_DIRECT };
    rules.push(json!({"type": "field", "network": "tcp,udp", "outboundTag": fallback}));
    let routing = json!({"domainStrategy": profile.domain_strategy, "rules": rules});
    (routing, dns_document(profile))
}

fn dns_document(profile: &RoutingProfile) -> Option<Value> {
    let mut servers = Vec::new();
    if !profile.remote_dns.is_empty() {
        servers.push(json!(profile.remote_dns));
    }
    if !profile.domestic_dns.is_empty() && profile.domestic_dns != profile.remote_dns {
        servers.push(json!(profile.domestic_dns));
    }
    if servers.is_empty() && profile.dns_hosts.is_empty() {
        return None;
    }
    Some(json!({
        "hosts": profile.dns_hosts,
        "servers": servers,
        "queryStrategy": QUERY_USE_IP
    }))
}

const QUERY_USE_IP: &str = "UseIP";

fn push_domain(rules: &mut Vec<Value>, items: &[String], tag: &str) {
    if items.is_empty() {
        return;
    }
    rules.push(json!({"type": "field", "domain": items, "outboundTag": tag}));
}

fn push_ip(rules: &mut Vec<Value>, items: &[String], tag: &str) {
    if items.is_empty() {
        return;
    }
    rules.push(json!({"type": "field", "ip": items, "outboundTag": tag}));
}

fn host_only(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.contains("://") {
        return None;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Some(value.to_string());
    }
    let host = if value.starts_with('[') {
        let inside = value.strip_prefix('[')?;
        let (host, rest) = inside.split_once(']')?;
        if !(rest.is_empty() || rest.starts_with(':')) {
            return None;
        }
        host
    } else {
        value.rsplit_once(':').map(|(host, _)| host).unwrap_or(value)
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        Some(host.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::host_only;

    #[test]
    fn host_only_keeps_ip_dns_targets() {
        let cases = [
            ("2001:db8::1", Some("2001:db8::1")),
            ("[::1]:53", Some("::1")),
            ("[::1]", Some("::1")),
            ("[2001:db8::1]:53", Some("2001:db8::1")),
            ("1.1.1.1", Some("1.1.1.1")),
            ("8.8.8.8:53", Some("8.8.8.8")),
            ("dns.example:53", None),
            ("dns.example", None),
            ("https://1.1.1.1/dns-query", None),
            ("", None),
        ];
        for (input, expected) in cases {
            assert_eq!(host_only(input).as_deref(), expected, "{input}");
        }
    }
}
