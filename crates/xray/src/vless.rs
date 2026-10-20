use super::stream::stream;
use rvpn_model::{Security, Server, Transport};
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, uuid: &str, encryption: &str, flow: &Option<String>, transport: &Transport, security: &Security, dialer: bool) -> Value {
            let mut user = json!({"id": uuid, "encryption": encryption});
            if let Some(flow) = flow {
                user["flow"] = json!(flow);
            }
            json!({
                "protocol": "vless",
                "settings": {"vnext": [{"address": server.address, "port": server.port, "users": [user]}]},
                "streamSettings": stream(transport, security, dialer)
            })
}
