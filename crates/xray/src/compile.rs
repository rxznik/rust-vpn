//! JSON compiler for one Xray process.
//!
//! Sniffing sets `routeOnly` so the sniffed name is used for routing while the ClientHello stays original.
//! `tls.insecure` and Hysteria2 `insecure` are accepted on the server model and dropped here.

use rvpn_model::{AuthMode, CoreSettings, DomainStrategy, Fragment, Noise, Protocol, Server, OUTBOUND_BLOCK, OUTBOUND_DIRECT, OUTBOUND_PROXY};

use crate::LOOPBACK;

const LOCALHOST: &str = "localhost";
const LOOPBACK_V6: &str = "::1";
const SOCKS_IN: &str = "socks-in";
const API_TAG: &str = "api";
use serde_json::{json, Value};
use std::path::{Component, Path};

#[path = "stream.rs"]
mod stream;
#[path = "vless.rs"]
mod vless;
#[path = "vmess.rs"]
mod vmess;
#[path = "trojan.rs"]
mod trojan;
#[path = "shadowsocks.rs"]
mod shadowsocks;
#[path = "socks.rs"]
mod socks;
#[path = "hysteria.rs"]
mod hysteria;
#[path = "wireguard.rs"]
mod wireguard;
#[path = "json_outbound.rs"]
mod json_outbound;


#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("json subscription is not an object")]
    JsonShape,
    #[error("json subscription listens outside the local machine")]
    Listen,
    #[error("invalid json subscription: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct CompileRequest<'a> {
    pub server: &'a Server,
    pub settings: &'a CoreSettings,
    pub fragment: Option<&'a Fragment>,
    pub noise: Option<&'a Noise>,
    pub routing: Option<Value>,
    pub dns: Option<Value>,
}

pub fn compile(request: &CompileRequest<'_>) -> Value {
    let dialer = request.fragment.is_some() || request.noise.is_some();
    let mut proxy = outbound(request.server, dialer);
    if request.settings.mux.enabled && mux_supported(&request.server.protocol) {
        proxy["mux"] = json!({
            "enabled": true,
            "concurrency": request.settings.mux.tcp_connections,
            "xudpConcurrency": request.settings.mux.xudp_connections,
            "xudpProxyUDP443": if request.settings.mux.quic { "allow" } else { "reject" }
        });
    }
    let mut outbounds = vec![proxy];
    if dialer {
        outbounds.push(fragment_outbound(request.fragment, request.noise));
    }
    outbounds.push(json!({"protocol": "freedom", "tag": OUTBOUND_DIRECT}));
    outbounds.push(json!({"protocol": "blackhole", "tag": OUTBOUND_BLOCK}));

    let mut config = json!({
        "log": {"loglevel": request.settings.log_level},
        "stats": {},
        "api": {"tag": API_TAG, "listen": format!("{LOOPBACK}:{}", request.settings.api_port), "services": ["StatsService"]},
        "policy": policy(request.settings.no_limit),
        "inbounds": inbounds(request.settings),
        "outbounds": outbounds,
        "routing": request.routing.clone().unwrap_or_else(default_routing)
    });
    if let Some(dns) = &request.dns {
        config["dns"] = dns.clone();
    }
    config
}

pub fn prepare_passthrough(raw: &str, dns: Option<&Value>, keep_existing_dns: bool, log_root: &Path) -> Result<String, CompileError> {
    let mut value: Value = serde_json::from_str(raw)?;
    let obj = value.as_object_mut().ok_or(CompileError::JsonShape)?;
    if !keep_existing_dns {
        if let Some(dns) = dns {
            obj.insert("dns".into(), dns.clone());
        }
    }
    confine_listeners(obj)?;
    confine_logs(obj, log_root);
    Ok(serde_json::to_string_pretty(&value)?)
}

fn confine_listeners(obj: &mut serde_json::Map<String, Value>) -> Result<(), CompileError> {
    if let Some(inbounds) = obj.get_mut("inbounds").and_then(|v| v.as_array_mut()) {
        for inbound in inbounds {
            let Some(item) = inbound.as_object_mut() else {
                return Err(CompileError::Listen);
            };
            match item.get("listen").and_then(|v| v.as_str()) {
                None => {
                    item.insert("listen".into(), json!(LOOPBACK));
                }
                Some(listen) if is_loopback_listen(listen) => {}
                Some(_) => return Err(CompileError::Listen),
            }
        }
    }
    if let Some(api) = obj.get_mut("api").and_then(|v| v.as_object_mut()) {
        let fill = match api.get("listen").and_then(|v| v.as_str()).map(str::trim) {
            None | Some("") => true,
            Some(listen) if !is_loopback_listen(listen) => return Err(CompileError::Listen),
            Some(_) => false,
        };
        if fill {
            api.insert("listen".into(), json!(format!("{LOOPBACK}:10085")));
        }
    }
    Ok(())
}

fn confine_logs(obj: &mut serde_json::Map<String, Value>, log_root: &Path) {
    let Some(log) = obj.get_mut("log").and_then(|v| v.as_object_mut()) else {
        return;
    };
    for key in ["access", "error"] {
        let escape = log.get(key).and_then(|v| v.as_str()).is_some_and(|path| !log_path_ok(path, log_root));
        if escape {
            log.remove(key);
        }
    }
}

fn is_loopback_listen(listen: &str) -> bool {
    let listen = listen.trim();
    if listen.is_empty() {
        return false;
    }
    let host = if let Some(rest) = listen.strip_prefix('[') {
        rest.split_once(']').map(|(host, _)| host).unwrap_or(rest)
    } else if listen.matches(':').count() == 1 {
        listen.split_once(':').map(|(host, _)| host).unwrap_or(listen)
    } else {
        listen
    };
    matches!(host, LOOPBACK | LOCALHOST | LOOPBACK_V6)
}

fn log_path_ok(path: &str, root: &Path) -> bool {
    let path = Path::new(path);
    if path.components().any(|component| matches!(component, Component::ParentDir)) {
        return false;
    }
    if path.is_absolute() {
        path.starts_with(root)
    } else {
        true
    }
}

fn policy(no_limit: bool) -> Value {
    let mut policy = json!({
        "system": {
            "statsOutboundUplink": true,
            "statsOutboundDownlink": true
        }
    });
    if no_limit {
        policy["levels"] = json!({"0": {"bufferSize": 0}});
    }
    policy
}

fn default_routing() -> Value {
    json!({
        "domainStrategy": DomainStrategy::AsIs,
        "rules": [{"type": "field", "network": "tcp,udp", "outboundTag": OUTBOUND_PROXY}]
    })
}

fn inbounds(settings: &CoreSettings) -> Vec<Value> {
    let mut list = vec![socks_inbound(settings)];
    if settings.http_enabled {
        list.push(http_inbound(settings));
    }
    list
}

fn socks_inbound(settings: &CoreSettings) -> Value {
    let mut inbound = json!({
        "listen": LOOPBACK,
        "port": settings.socks_port,
        "protocol": "socks",
        "tag": SOCKS_IN,
        "settings": {"udp": true, "auth": "noauth"},
        "sniffing": sniffing(settings.sniffing)
    });
    if settings.socks_auth_mode != AuthMode::Disable && !settings.socks_user.is_empty() {
        inbound["settings"] = json!({
            "udp": true,
            "auth": "password",
            "accounts": [{"user": settings.socks_user, "pass": settings.socks_password}]
        });
    }
    inbound
}

fn http_inbound(settings: &CoreSettings) -> Value {
    let mut inbound = json!({
        "listen": LOOPBACK,
        "port": settings.http_port,
        "protocol": "http",
        "tag": "http-in",
        "settings": {},
        "sniffing": sniffing(settings.sniffing)
    });
    if settings.http_auth_mode != AuthMode::Disable && !settings.http_user.is_empty() {
        inbound["settings"] = json!({
            "accounts": [{"user": settings.http_user, "pass": settings.http_password}]
        });
    }
    inbound
}

fn sniffing(enabled: bool) -> Value {
    // routeOnly uses the sniffed name only for routing. Vision must still send the original ClientHello.
    json!({
        "enabled": enabled,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
    })
}

fn fragment_outbound(fragment: Option<&Fragment>, noise: Option<&Noise>) -> Value {
    let mut settings = json!({});
    if let Some(fragment) = fragment {
        let mut body = json!({
            "packets": fragment.packets,
            "length": fragment.length,
            "interval": fragment.interval
        });
        if let Some(max_split) = &fragment.max_split {
            body["maxSplit"] = json!(max_split);
        }
        settings["fragment"] = body;
    }
    if let Some(noise) = noise {
        let mut item = json!({
            "type": noise.kind,
            "packet": noise.packet,
            "delay": noise.delay
        });
        if let Some(apply) = &noise.apply_to {
            item["applyTo"] = json!(apply);
        }
        settings["noises"] = json!([item]);
    }
    json!({"protocol": "freedom", "tag": "fragment", "settings": settings})
}

fn outbound(server: &Server, dialer: bool) -> Value {
    let mut value = match &server.protocol {
        Protocol::Vless { uuid, encryption, flow, transport, security } => vless::outbound(server, uuid, encryption, flow, transport, security, dialer),
        Protocol::Vmess { uuid, alter_id, security, transport, tls } => vmess::outbound(server, uuid, alter_id, security, transport, tls, dialer),
        Protocol::Trojan { password, transport, tls } => trojan::outbound(server, password, transport, tls, dialer),
        Protocol::Shadowsocks { method, password, .. } => shadowsocks::outbound(server, method, password),
        Protocol::Socks { username, password } => socks::outbound(server, username, password),
        Protocol::Hysteria2 { password, sni, insecure, obfs, obfs_password, alpn, pin_sha256 } => {
            hysteria::outbound(server, password, sni, insecure, obfs, obfs_password, alpn, pin_sha256, dialer)
        }
        Protocol::Wireguard(peer) => wireguard::outbound(server, peer),
        Protocol::Json { raw } => json_outbound::outbound(raw),
    };
    value["tag"] = json!(OUTBOUND_PROXY);
    value
}


fn mux_supported(protocol: &Protocol) -> bool {
    matches!(protocol, Protocol::Vless { .. } | Protocol::Vmess { .. } | Protocol::Trojan { .. } | Protocol::Shadowsocks { .. })
}
