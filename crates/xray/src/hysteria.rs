use rvpn_model::Server;
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, password: &str, sni: &Option<String>, insecure: &bool, obfs: &Option<String>, obfs_password: &Option<String>, alpn: &[String], pin_sha256: &Option<String>, dialer: bool) -> Value {
            let mut hysteria = json!({"version": 2, "auth": password});
            if let Some(kind) = obfs {
                let mut body = json!({"type": kind});
                if let Some(pass) = obfs_password {
                    body["password"] = json!(pass);
                }
                hysteria["obfs"] = body;
            }
            let mut tls = json!({
                "serverName": sni.clone().unwrap_or_else(|| server.address.clone())
            });
            // Hysteria2 `insecure` is not an Xray field this compiler already emits.
            let _ = insecure;
            if !alpn.is_empty() {
                tls["alpn"] = json!(alpn);
            }
            if let Some(pin) = pin_sha256 {
                tls["pinnedPeerCertSha256"] = json!(pin);
            }
            let mut stream = json!({
                "network": "hysteria",
                "security": "tls",
                "hysteriaSettings": hysteria,
                "tlsSettings": tls
            });
            if dialer {
                stream["sockopt"] = json!({"dialerProxy": "fragment"});
            }
            json!({
                "protocol": "hysteria",
                "settings": {"version": 2, "address": server.address, "port": server.port},
                "streamSettings": stream
            })
}
