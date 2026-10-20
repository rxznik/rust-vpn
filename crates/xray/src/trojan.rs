use super::stream::stream;
use rvpn_model::{Security, Server, TlsSettings, Transport};
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, password: &str, transport: &Transport, tls: &TlsSettings, dialer: bool) -> Value {
 json!({
            "protocol": "trojan",
            "settings": {"servers": [{"address": server.address, "port": server.port, "password": password}]},
            "streamSettings": stream(transport, &Security::Tls(tls.clone()), dialer)
        })
}
