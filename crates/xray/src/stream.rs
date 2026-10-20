use rvpn_model::{Security, Transport};
use serde_json::{json, Value};

pub(crate) fn stream(transport: &Transport, security: &Security, dialer: bool) -> Value {
    let network = match transport.network.as_str() {
        "raw" | "" => "tcp",
        "http" | "h2" | "http2" => "h2",
        "websocket" => "ws",
        "splithttp" => "xhttp",
        other => other,
    };
    let mut stream = json!({"network": network, "security": security_name(security)});
    match network {
        "ws" => {
            stream["wsSettings"] = json!({
                "path": transport.path.clone().unwrap_or_else(|| "/".into()),
                "host": transport.host.clone().unwrap_or_default()
            });
        }
        "grpc" => {
            stream["grpcSettings"] = json!({
                "serviceName": transport.service_name.clone().or(transport.path.clone()).unwrap_or_default(),
                "authority": transport.authority.clone().unwrap_or_default(),
                "multiMode": transport.mode.as_deref() == Some("multi")
            });
        }
        "h2" => {
            let host = transport.host.clone().unwrap_or_default();
            stream["httpSettings"] = json!({
                "host": if host.is_empty() { Vec::<String>::new() } else { vec![host] },
                "path": transport.path.clone().unwrap_or_else(|| "/".into())
            });
        }
        "httpupgrade" => {
            stream["httpupgradeSettings"] = json!({
                "path": transport.path.clone().unwrap_or_else(|| "/".into()),
                "host": transport.host.clone().unwrap_or_default()
            });
        }
        "xhttp" => {
            let mut body = json!({
                "path": transport.path.clone().unwrap_or_else(|| "/".into()),
                "host": transport.host.clone().unwrap_or_default()
            });
            if let Some(mode) = &transport.mode {
                body["mode"] = json!(mode);
            }
            stream["xhttpSettings"] = body;
        }
        "kcp" | "mkcp" => {
            stream["network"] = json!("kcp");
            stream["kcpSettings"] = json!({"header": {"type": transport.header_type.clone().unwrap_or_else(|| "none".into())}});
        }
        "quic" => {
            stream["quicSettings"] = json!({
                "security": "none",
                "header": {"type": transport.header_type.clone().unwrap_or_else(|| "none".into())}
            });
        }
        _ => {
            if transport.header_type.as_deref() == Some("http") {
                let host = transport.host.clone().unwrap_or_default();
                stream["tcpSettings"] = json!({
                    "header": {
                        "type": "http",
                        "request": {
                            "path": [transport.path.clone().unwrap_or_else(|| "/".into())],
                            "headers": {"Host": [host]}
                        }
                    }
                });
            }
        }
    }
    match security {
        Security::None => {}
        Security::Tls(tls) => stream["tlsSettings"] = tls_settings(tls),
        Security::Reality(reality) => {
            stream["realitySettings"] = json!({
                "serverName": reality.server_name,
                "fingerprint": reality.fingerprint.clone().unwrap_or_else(|| "chrome".into()),
                "publicKey": reality.public_key,
                "shortId": reality.short_id,
                "spiderX": reality.spider_x.clone().unwrap_or_else(|| "/".into())
            });
        }
    }
    if dialer {
        stream["sockopt"] = json!({"dialerProxy": "fragment"});
    }
    stream
}

fn tls_settings(tls: &rvpn_model::TlsSettings) -> Value {
    let mut body = json!({
        "serverName": tls.sni.clone().unwrap_or_default()
    });
    // `allowInsecure` is intentionally omitted. The link flag is kept on `TlsSettings` only.
    let _ = tls.insecure;
    if !tls.alpn.is_empty() {
        body["alpn"] = json!(tls.alpn);
    }
    if let Some(fp) = &tls.fingerprint {
        body["fingerprint"] = json!(fp);
    }
    if let Some(pin) = &tls.pinned_sha256 {
        body["pinnedPeerCertSha256"] = json!(pin);
    }
    body
}

fn security_name(security: &Security) -> &'static str {
    match security {
        Security::None => "none",
        Security::Tls(_) => "tls",
        Security::Reality(_) => "reality",
    }
}
