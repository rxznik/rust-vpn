use super::{host_of, ParsedSubscription, SubError};
use crate::crypto::decode_b64;
use rvpn_links::{parse_server, LinkError};
use rvpn_model::{
    parse_flag, AuthMode, AutoConnectType, Fragment, MuxSettings, Noise, PerAppMode, PingStyle, PingType, Protocol, Server, SortType, Subscription, SubscriptionKind,
    SubscriptionMeta, UserInfo,
};
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

pub fn parse_subscription(body: &str, headers: &BTreeMap<String, String>, subscription_id: &str) -> Result<ParsedSubscription, SubError> {
    let mut meta = SubscriptionMeta::default();
    let mut name = None;
    let mut userinfo = None;
        let mut routing_links = Vec::new();
        for (key, value) in headers {
            apply_pair(&mut meta, &mut name, &mut userinfo, key, value);
            if key == "routing" && value.starts_with("happ://routing/") {
                routing_links.push(value.clone());
            }
        }
    let text = decode_container(body);
    if let Some(raw) = json_config(&text) {
        apply_body_meta(&text, &mut meta, &mut name, &mut userinfo);
        let server = json_server(subscription_id, &raw, name.as_deref());
        return Ok(ParsedSubscription {
            name: name.or_else(|| Some(server.name.clone())),
            kind: SubscriptionKind::Json,
            raw_json: Some(raw),
            servers: vec![server],
            userinfo,
            meta,
            routing_links,
        });
    }
        let mut servers = Vec::new();
        let mut saw_link = false;
        let mut skipped_link = None;
        for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            if let Some((key, value)) = split_meta(rest) {
                apply_pair(&mut meta, &mut name, &mut userinfo, &key, &value);
            }
            continue;
        }
        if line.starts_with("happ://routing/") {
            routing_links.push(line.to_string());
            continue;
        }
        if line.starts_with("happ://crypt") {
            return Err(SubError::EncryptedHappLink);
        }
        if line.contains("://") {
            saw_link = true;
            match parse_server(line, Some(subscription_id)) {
                Ok(server) => servers.push(server),
                Err(LinkError::EncryptedHappLink) => return Err(SubError::EncryptedHappLink),
                Err(err) => {
                    if servers.is_empty() && !line.starts_with("http") {
                        return Err(SubError::Message(err.to_string()));
                    }
                    skipped_link = Some(err.to_string());
                }
            }
        }
    }
    if servers.is_empty() && saw_link {
        return Err(SubError::Message(skipped_link.unwrap_or_else(|| "subscription contained no servers".into())));
    }
    Ok(ParsedSubscription { name, kind: SubscriptionKind::Links, raw_json: None, servers, userinfo, meta, routing_links })
}

pub fn update_due(sub: &Subscription, now: i64, on_open: bool) -> bool {
    if sub.url.is_none() {
        return false;
    }
    if on_open && sub.meta.auto_update_on_open {
        return true;
    }
    if let Some(flag) = sub.meta.extra.get("subscription-auto-update-enable") {
        if parse_flag(flag) == Some(false) {
            return false;
        }
    }
    let Some(hours) = sub.meta.update_interval_hours.filter(|h| *h > 0) else {
        return false;
    };
    match sub.updated_at {
        None => true,
        Some(ts) => now.saturating_sub(ts) >= i64::from(hours) * 3600,
    }
}

pub fn hwid_query(url: &str) -> Option<String> {
    Url::parse(url).ok()?.query_pairs().find(|(k, _)| k.eq_ignore_ascii_case("hwid")).map(|(_, v)| v.into_owned())
}

pub fn key_query(url: &str) -> Option<String> {
    Url::parse(url).ok()?.query_pairs().find(|(k, _)| k.eq_ignore_ascii_case("key")).map(|(_, v)| v.into_owned())
}

pub fn with_query(url: &str, key: &str, value: &str) -> String {
    let Ok(mut parsed) = Url::parse(url) else {
        return url.to_string();
    };
    let mut pairs: Vec<(String, String)> = parsed.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).filter(|(k, _)| !k.eq_ignore_ascii_case(key)).collect();
    pairs.push((key.to_string(), value.to_string()));
    parsed.query_pairs_mut().clear().extend_pairs(pairs);
    parsed.to_string()
}

pub fn apply_url_rewrite(url: &str, meta: &SubscriptionMeta) -> String {
    if let Some(new_url) = &meta.new_url {
        if same_org(url, new_url) {
            return new_url.clone();
        }
        return url.to_string();
    }
    if let Some(domain) = &meta.new_domain {
        if let Ok(mut parsed) = Url::parse(url) {
            let current = parsed.host_str().unwrap_or("").to_string();
            if same_org_host(&current, domain) && parsed.set_host(Some(domain)).is_ok() {
                return parsed.to_string();
            }
        }
    }
    url.to_string()
}

fn same_org(left: &str, right: &str) -> bool {
    match (host_of(left), host_of(right)) {
        (Some(left), Some(right)) => same_org_host(&left, &right),
        _ => false,
    }
}

fn same_org_host(left: &str, right: &str) -> bool {
    let left = left.trim_matches('.').to_ascii_lowercase();
    let right = right.trim_matches('.').to_ascii_lowercase();
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

fn decode_container(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.contains("://") {
        return trimmed.to_string();
    }
    if let Some(bytes) = decode_b64(trimmed) {
        if let Ok(text) = String::from_utf8(bytes) {
            let text = text.trim().to_string();
            if text.contains("://") || text.starts_with('{') || text.starts_with('[') {
                return text;
            }
        }
    }
    trimmed.to_string()
}

fn json_config(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    match value {
        Value::Object(obj) if obj.contains_key("outbounds") || obj.contains_key("inbounds") => Some(text.to_string()),
        Value::Array(items) => items.into_iter().find(|item| item.get("outbounds").is_some()).map(|item| item.to_string()),
        _ => None,
    }
}

fn json_server(subscription_id: &str, raw: &str, name: Option<&str>) -> Server {
    let remarks = serde_json::from_str::<Value>(raw).ok().and_then(|v| v.get("remarks").and_then(|r| r.as_str()).map(|s| s.to_string()));
    Server {
        id: rvpn_links::server_id(subscription_id, raw),
        subscription_id: Some(subscription_id.to_string()),
        name: name.unwrap_or(remarks.as_deref().unwrap_or("JSON")).to_string(),
        address: "json".into(),
        port: 0,
        protocol: Protocol::Json { raw: raw.to_string() },
        description: None,
        fragment: None,
        noise: None,
        raw_link: None,
        delay_ms: None,
    }
}

fn apply_body_meta(text: &str, meta: &mut SubscriptionMeta, name: &mut Option<String>, userinfo: &mut Option<UserInfo>) {
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix('#') {
            if let Some((key, value)) = split_meta(rest) {
                apply_pair(meta, name, userinfo, &key, &value);
            }
        }
    }
}

fn split_meta(rest: &str) -> Option<(String, String)> {
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    let (key, value) = if let Some((k, v)) = rest.split_once(':') {
        (k, v)
    } else {
        rest.split_once(char::is_whitespace)?
    };
    Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
}

/// Applies one Happ metadata key. Unknown keys are stored in `meta.extra`.

pub(crate) fn apply_pair(meta: &mut SubscriptionMeta, name: &mut Option<String>, userinfo: &mut Option<UserInfo>, key: &str, value: &str) {
    let key = key.trim().trim_start_matches('#').to_ascii_lowercase();
    let value = value.trim();
    if key.is_empty() {
        return;
    }
    match key.as_str() {
        "profile-title" => *name = Some(limit_chars(&decode_text(value), 25)),
        "subscription-userinfo" => *userinfo = parse_userinfo(value),
        "support-url" => meta.support_url = Some(value.to_string()),
        "profile-web-page-url" => meta.web_page_url = Some(value.to_string()),
        "announce" => meta.announce = Some(limit_chars(&decode_text(value), 200)),
        "profile-update-interval" => meta.update_interval_hours = value.parse().ok(),
        "routing-enable" => meta.routing_enabled = parse_flag(value).unwrap_or(true),
        "fallback-url" => meta.fallback_url = Some(value.to_string()),
        "new-url" => meta.new_url = Some(value.to_string()),
        "new-domain" => meta.new_domain = Some(value.to_string()),
        "custom-tunnel-config" => meta.custom_tunnel_config = Some(value.to_string()),
        "tun-type" => meta.tun_type = Some(value.to_string()),
        "socks-auth-mode" => meta.socks_auth_mode = parse_auth(value),
        "socks-auth-user" => meta.socks_auth_user = Some(value.to_string()),
        "socks-auth-password" => meta.socks_auth_password = Some(value.to_string()),
        "http-auth-mode" => meta.http_auth_mode = parse_auth(value),
        "http-auth-user" => meta.http_auth_user = Some(value.to_string()),
        "http-auth-password" => meta.http_auth_password = Some(value.to_string()),
        "no-limit-enabled" => meta.no_limit = parse_flag(value).unwrap_or(false),
        "no-limit-xhttp-enabled" => meta.no_limit_xhttp = parse_flag(value).unwrap_or(false),
        "subscription-always-hwid-enable" => meta.always_hwid = parse_flag(value).unwrap_or(false),
        "notification-subs-expire" => meta.notify_expire = parse_flag(value).unwrap_or(false),
        "hide-settings" => meta.hide_settings = parse_flag(value).unwrap_or(false),
        "server-address-resolve-enable" => meta.resolve_enable = parse_flag(value).unwrap_or(false),
        "server-address-resolve-dns-domain" => meta.resolve_dns_domain = Some(value.to_string()),
        "server-address-resolve-dns-ip" => meta.resolve_dns_ip = Some(value.to_string()),
        "subscription-autoconnect" => meta.autoconnect = parse_flag(value).unwrap_or(false),
        "subscription-autoconnect-type" => meta.autoconnect_type = AutoConnectType::parse(value).unwrap_or_default(),
        "subscription-ping-onopen-enabled" => meta.ping_on_open = parse_flag(value).unwrap_or(false),
        "subscription-auto-update-enable" => {
            meta.auto_update = parse_flag(value).unwrap_or(false);
            meta.extra.insert(key, value.to_string());
        }
        "subscription-auto-update-open-enable" => meta.auto_update_on_open = parse_flag(value).unwrap_or(false),
        "fragmentation-enable" => meta.fragmentation_enable = parse_flag(value).unwrap_or(false),
        "fragmentation-packets" => fragment(meta).packets = value.to_string(),
        "fragmentation-length" => fragment(meta).length = value.to_string(),
        "fragmentation-interval" => fragment(meta).interval = value.to_string(),
        "fragmentation-maxsplit" => fragment(meta).max_split = Some(value.to_string()),
        "noises-enable" => meta.noises_enable = parse_flag(value).unwrap_or(false),
        "noises-packet-type" => noise(meta).kind = value.to_string(),
        "noises-packet" => noise(meta).packet = value.to_string(),
        "noises-delay" => noise(meta).delay = value.to_string(),
        "noises-rand" => noise(meta).packet = value.to_string(),
        "ping-type" => meta.ping_type = PingType::parse(value),
        "check-url-via-proxy" => meta.check_url = Some(value.to_string()),
        "change-user-agent" => meta.user_agent = Some(value.to_string()),
        "app-auto-start" => meta.autostart = parse_flag(value),
        "per-app-proxy-mode" => meta.per_app_mode = PerAppMode::parse(value),
        "per-app-proxy-list" | "per-app-proxy-list-set" => meta.per_app_list = split_list(value),
        "per-app-proxy-list-invert" => {
            meta.per_app_list = split_list(value);
            if meta.per_app_mode.is_none() {
                meta.per_app_mode = Some(PerAppMode::Bypass);
            }
        }
        "sniffing-enable" => meta.sniffing = parse_flag(value),
        "subscriptions-collapse" => meta.collapse = parse_flag(value).unwrap_or(false),
        "subscriptions-expand-now" => meta.expand_now = parse_flag(value).unwrap_or(false),
        "ping-result" => meta.ping_result = Some(PingStyle::parse(value)),
        "mux-enable" => mux(meta).enabled = parse_flag(value).unwrap_or(false),
        "mux-tcp-connections" => mux(meta).tcp_connections = value.parse().unwrap_or(8),
        "mux-xudp-connections" => mux(meta).xudp_connections = value.parse().unwrap_or(16),
        "mux-quic" => mux(meta).quic = parse_flag(value).unwrap_or(false),
        "proxy-enable" => meta.proxy_enable = parse_flag(value),
        "tun-enable" => meta.tun_enable = parse_flag(value),
        "tun-mode" => meta.tun_mode = Some(value.to_string()),
        "exclude-routes" => meta.exclude_routes.extend(split_list(value)),
        "exclude-routes-set" => meta.exclude_routes = split_list(value),
        "color-profile" => meta.color_profile = Some(decode_text(value)),
        "include-all-networks-enable" => meta.include_all_networks = parse_flag(value),
        "exclude-local-networks-enable" => meta.exclude_local_networks = parse_flag(value),
        "exclude-apns-enable" => meta.exclude_apns = parse_flag(value),
        "dont-use-filter" => meta.dont_use_filter = parse_flag(value).unwrap_or(false),
        "subscription-pin" => meta.pinned = parse_flag(value).unwrap_or(false),
        "manual-block-user-agent" => meta.manual_block_ua = parse_flag(value).unwrap_or(false),
        "subscriptions-sort-type" => meta.sort_type = SortType::parse(value).unwrap_or_default(),
        "dns-from-json-enable" => meta.dns_from_json = parse_flag(value).unwrap_or(false),
        "hide-vpn-icon" => meta.hide_vpn_icon = parse_flag(value).unwrap_or(false),
        "inbound-http-enable" => meta.inbound_http = parse_flag(value),
        "xray-tun-enable" => meta.xray_tun = parse_flag(value).unwrap_or(false),
        "block-bind-to-tunnel-enable" => meta.block_bind_to_tunnel = parse_flag(value).unwrap_or(false),
        "subscription-alternative-hwid-enabled" => meta.alternative_hwid = parse_flag(value).unwrap_or(false),
        "sub-expire" => meta.sub_expire = parse_flag(value).unwrap_or(false),
        "sub-expire-button-link" => meta.sub_expire_button_link = Some(value.to_string()),
        "sub-info-color" => meta.sub_info_color = Some(value.to_string()),
        "sub-info-text" => meta.sub_info_text = Some(decode_text(value)),
        "sub-info-button-text" => meta.sub_info_button_text = Some(value.to_string()),
        "sub-info-button-link" => meta.sub_info_button_link = Some(value.to_string()),
        _ => {
            meta.extra.insert(key, value.to_string());
        }
    }
}

fn fragment(meta: &mut SubscriptionMeta) -> &mut Fragment {
    if meta.fragmentation.is_none() {
        meta.fragmentation = Some(Fragment { length: "50-100".into(), interval: "10-20".into(), packets: "tlshello".into(), max_split: None });
    }
    meta.fragmentation.as_mut().expect("fragment")
}

fn noise(meta: &mut SubscriptionMeta) -> &mut Noise {
    if meta.noise.is_none() {
        meta.noise = Some(Noise { kind: "rand".into(), packet: "10-20".into(), delay: "10-16".into(), apply_to: None });
    }
    meta.noise.as_mut().expect("noise")
}

fn mux(meta: &mut SubscriptionMeta) -> &mut MuxSettings {
    if meta.mux.is_none() {
        meta.mux = Some(MuxSettings::default());
    }
    meta.mux.as_mut().expect("mux")
}

fn parse_userinfo(value: &str) -> Option<UserInfo> {
    let mut info = UserInfo::default();
    let mut seen = false;
    for part in value.split(';') {
        let Some((k, v)) = part.split_once('=') else { continue };
        seen = true;
        let n: u64 = v.trim().parse().unwrap_or(0);
        match k.trim() {
            "upload" => info.upload = n,
            "download" => info.download = n,
            "total" => info.total = n,
            "expire" => info.expire = Some(n as i64),
            _ => {}
        }
    }
    seen.then_some(info)
}

fn parse_auth(value: &str) -> Option<AuthMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(AuthMode::Auto),
        "manual" => Some(AuthMode::Manual),
        "from-json" => Some(AuthMode::FromJson),
        "disable" => Some(AuthMode::Disable),
        _ => None,
    }
}

fn split_list(value: &str) -> Vec<String> {
    value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn decode_text(value: &str) -> String {
    let rest = value.strip_prefix("base64:").unwrap_or(value);
    if rest != value {
        if let Some(bytes) = decode_b64(rest) {
            if let Ok(text) = String::from_utf8(bytes) {
                return text;
            }
        }
    }
    value.to_string()
}

fn limit_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
