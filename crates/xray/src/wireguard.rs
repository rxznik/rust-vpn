use rvpn_model::{Server, WireGuardPeer};
use serde_json::{json, Value};

pub(crate) fn outbound(server: &Server, peer: &WireGuardPeer) -> Value {
            let address = peer.address.clone().filter(|a| a.contains('/') || a.parse::<std::net::IpAddr>().is_ok()).unwrap_or_else(|| "10.0.0.2/32".into());
            let mut settings = json!({
                "secretKey": peer.secret_key,
                "address": [address],
                "peers": [{
                    "publicKey": peer.public_key,
                    "endpoint": format!("{}:{}", server.address, server.port),
                    "allowedIPs": ["0.0.0.0/0", "::/0"]
                }]
            });
            if let Some(mtu) = peer.mtu {
                settings["mtu"] = json!(mtu);
            }
            if !peer.reserved.is_empty() {
                settings["reserved"] = json!(peer.reserved);
            }
            json!({"protocol": "wireguard", "settings": settings})
}
