use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fragment {
    pub length: String,
    pub interval: String,
    pub packets: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_split: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Noise {
    #[serde(rename = "type")]
    pub kind: String,
    pub packet: String,
    pub delay: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MuxSettings {
    pub enabled: bool,
    pub tcp_connections: u16,
    pub xudp_connections: u16,
    pub quic: bool,
}

impl Default for MuxSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            tcp_connections: 8,
            xudp_connections: 16,
            quic: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealitySettings {
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Security {
    None,
    Tls(TlsSettings),
    Reality(RealitySettings),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transport {
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            network: "tcp".into(),
            path: None,
            host: None,
            service_name: None,
            header_type: None,
            mode: None,
            authority: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub secret_key: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reserved: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum Protocol {
    Vless {
        uuid: String,
        encryption: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flow: Option<String>,
        transport: Transport,
        security: Security,
    },
    Vmess {
        uuid: String,
        alter_id: u16,
        security: String,
        transport: Transport,
        tls: Option<TlsSettings>,
    },
    Trojan {
        password: String,
        transport: Transport,
        tls: TlsSettings,
    },
    Shadowsocks {
        method: String,
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plugin: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plugin_opts: Option<String>,
    },
    Socks {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },
    Hysteria2 {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni: Option<String>,
        #[serde(default)]
        insecure: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs_password: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alpn: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin_sha256: Option<String>,
    },
    Wireguard(WireGuardPeer),
    /// Full Xray document from a JSON subscription. Outbounds are not rewritten.
    Json {
        raw: String,
    },
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Vless { .. } => "VLESS",
            Self::Vmess { .. } => "VMess",
            Self::Trojan { .. } => "Trojan",
            Self::Shadowsocks { .. } => "Shadowsocks",
            Self::Socks { .. } => "SOCKS5",
            Self::Hysteria2 { .. } => "Hysteria2",
            Self::Wireguard(_) => "WireGuard",
            Self::Json { .. } => "JSON",
        }
    }
}
