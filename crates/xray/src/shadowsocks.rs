use rvpn_model::Server;
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, method: &str, password: &str) -> Value {
 json!({
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": server.address, "port": server.port, "method": method, "password": password}]}
        })
}
