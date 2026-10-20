use serde::de::Deserializer;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;

/// Теги outbound, которые пишут и маршрут, и конфиг Xray.
pub const OUTBOUND_PROXY: &str = "proxy";
pub const OUTBOUND_DIRECT: &str = "direct";
pub const OUTBOUND_BLOCK: &str = "block";

/// Стратегия домена Xray. Неизвестная строка читается как `AsIs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainStrategy {
    #[default]
    AsIs,
    IpIfNonMatch,
    IpOnDemand,
}

impl DomainStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AsIs => "AsIs",
            Self::IpIfNonMatch => "IPIfNonMatch",
            Self::IpOnDemand => "IPOnDemand",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "ipifnonmatch" | "ip-if-non-match" | "ip_if_non_match" => Self::IpIfNonMatch,
            "ipondemand" | "ip-on-demand" | "ip_on_demand" => Self::IpOnDemand,
            _ => Self::AsIs,
        }
    }
}

impl Serialize for DomainStrategy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DomainStrategy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingProfile {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub global_proxy: bool,
    #[serde(default)]
    pub remote_dns: String,
    #[serde(default)]
    pub domestic_dns: String,
    #[serde(default)]
    pub geoip_url: String,
    #[serde(default)]
    pub geosite_url: String,
    #[serde(default)]
    pub dns_hosts: BTreeMap<String, String>,
    #[serde(default)]
    pub direct_sites: Vec<String>,
    #[serde(default)]
    pub direct_ip: Vec<String>,
    #[serde(default)]
    pub proxy_sites: Vec<String>,
    #[serde(default)]
    pub proxy_ip: Vec<String>,
    #[serde(default)]
    pub block_sites: Vec<String>,
    #[serde(default)]
    pub block_ip: Vec<String>,
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingCommand {
    Add { activate: bool, profile_b64: String },
    Off,
}
