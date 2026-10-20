use super::stream::stream;
use rvpn_model::{Security, Server, TlsSettings, Transport};
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, uuid: &str, alter_id: &u16, security: &str, transport: &Transport, tls: &Option<TlsSettings>, dialer: bool) -> Value {
            let sec = if tls.is_some() { Security::Tls(tls.clone().unwrap()) } else { Security::None };
            json!({
                "protocol": "vmess",
                "settings": {"vnext": [{"address": server.address, "port": server.port, "users": [{
                    "id": uuid,
                    "alterId": alter_id,
                    "security": security
                }]}]},
                "streamSettings": stream(transport, &sec, dialer)
            })
}
