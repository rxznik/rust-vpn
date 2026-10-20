use rvpn_model::Server;
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, username: &Option<String>, password: &Option<String>) -> Value {
            let mut item = json!({"address": server.address, "port": server.port});
            if let (Some(user), Some(pass)) = (username, password) {
                item["users"] = json!([{"user": user, "pass": pass}]);
            }
            json!({"protocol": "socks", "settings": {"servers": [item]}})
}
