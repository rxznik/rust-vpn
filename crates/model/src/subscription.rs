use serde::de::Deserializer;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::BTreeMap;

use crate::protocol::{Fragment, MuxSettings, Noise};
use crate::settings::{AuthMode, AutoConnectType, PerAppMode, PingType, SortType};

pub const LOCAL_SUBSCRIPTION_ID: &str = "local";

/// Как показывать задержку. Всё, кроме `icon`, показывается числом миллисекунд.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PingStyle {
    #[default]
    Time,
    Icon,
}

impl PingStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::Icon => "icon",
        }
    }

    pub fn parse(value: &str) -> Self {
        if value.trim().eq_ignore_ascii_case("icon") {
            Self::Icon
        } else {
            Self::Time
        }
    }
}

impl Serialize for PingStyle {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PingStyle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionKind {
    Links,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserInfo {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire: Option<i64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_interval_hours: Option<u32>,
    #[serde(default = "default_true")]
    pub routing_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_page_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_auth_mode: Option<AuthMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_auth_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_auth_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_auth_mode: Option<AuthMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_auth_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_auth_password: Option<String>,
    #[serde(default)]
    pub no_limit: bool,
    #[serde(default)]
    pub no_limit_xhttp: bool,
    #[serde(default)]
    pub always_hwid: bool,
    #[serde(default)]
    pub notify_expire: bool,
    #[serde(default)]
    pub hide_settings: bool,
    #[serde(default)]
    pub resolve_enable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_dns_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_dns_ip: Option<String>,
    #[serde(default)]
    pub autoconnect: bool,
    #[serde(default)]
    pub autoconnect_type: AutoConnectType,
    #[serde(default)]
    pub ping_on_open: bool,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default)]
    pub auto_update_on_open: bool,
    #[serde(default)]
    pub fragmentation_enable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragmentation: Option<Fragment>,
    #[serde(default)]
    pub noises_enable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise: Option<Noise>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_type: Option<PingType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_app_mode: Option<PerAppMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_app_list: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<bool>,
    #[serde(default)]
    pub collapse: bool,
    #[serde(default)]
    pub expand_now: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_result: Option<PingStyle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<MuxSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun_enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_routes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_all_networks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_local_networks: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_apns: Option<bool>,
    #[serde(default)]
    pub dont_use_filter: bool,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub manual_block_ua: bool,
    #[serde(default)]
    pub sort_type: SortType,
    #[serde(default)]
    pub dns_from_json: bool,
    #[serde(default)]
    pub hide_vpn_icon: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_http: Option<bool>,
    #[serde(default)]
    pub xray_tun: bool,
    #[serde(default)]
    pub block_bind_to_tunnel: bool,
    #[serde(default)]
    pub alternative_hwid: bool,
    #[serde(default)]
    pub sub_expire: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_expire_button_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_info_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_info_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_info_button_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_info_button_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_tunnel_config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_domain: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl Default for SubscriptionMeta {
    fn default() -> Self {
        Self {
            update_interval_hours: None,
            routing_enabled: true,
            fallback_url: None,
            announce: None,
            support_url: None,
            web_page_url: None,
            socks_auth_mode: None,
            socks_auth_user: None,
            socks_auth_password: None,
            http_auth_mode: None,
            http_auth_user: None,
            http_auth_password: None,
            no_limit: false,
            no_limit_xhttp: false,
            always_hwid: false,
            notify_expire: false,
            hide_settings: false,
            resolve_enable: false,
            resolve_dns_domain: None,
            resolve_dns_ip: None,
            autoconnect: false,
            autoconnect_type: AutoConnectType::LastUsed,
            ping_on_open: false,
            auto_update: false,
            auto_update_on_open: false,
            fragmentation_enable: false,
            fragmentation: None,
            noises_enable: false,
            noise: None,
            ping_type: None,
            check_url: None,
            user_agent: None,
            autostart: None,
            per_app_mode: None,
            per_app_list: Vec::new(),
            sniffing: None,
            collapse: false,
            expand_now: false,
            ping_result: None,
            mux: None,
            proxy_enable: None,
            tun_enable: None,
            tun_mode: None,
            tun_type: None,
            exclude_routes: Vec::new(),
            color_profile: None,
            include_all_networks: None,
            exclude_local_networks: None,
            exclude_apns: None,
            dont_use_filter: false,
            pinned: false,
            manual_block_ua: false,
            sort_type: SortType::Without,
            dns_from_json: false,
            hide_vpn_icon: false,
            inbound_http: None,
            xray_tun: false,
            block_bind_to_tunnel: false,
            alternative_hwid: false,
            sub_expire: false,
            sub_expire_button_link: None,
            sub_info_color: None,
            sub_info_text: None,
            sub_info_button_text: None,
            sub_info_button_link: None,
            custom_tunnel_config: None,
            new_url: None,
            new_domain: None,
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub kind: SubscriptionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo: Option<UserInfo>,
    #[serde(default)]
    pub meta: SubscriptionMeta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    /// Profile selected in the UI. Takes effect on the next connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_profile_id: Option<String>,
    /// Profile last copied into a running config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_profile_id: Option<String>,
    #[serde(default = "default_true")]
    pub draft_routing_enabled: bool,
    #[serde(default = "default_true")]
    pub applied_routing_enabled: bool,
    pub created_at: i64,
}

pub fn group_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 80 || value.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(value.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerGroup {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
    pub created_at: i64,
}

impl Subscription {
    pub fn local(now: i64) -> Self {
        Self {
            id: LOCAL_SUBSCRIPTION_ID.into(),
            name: "Server list".into(),
            url: None,
            kind: SubscriptionKind::Links,
            raw_json: None,
            userinfo: None,
            meta: SubscriptionMeta::default(),
            updated_at: None,
            draft_profile_id: None,
            applied_profile_id: None,
            draft_routing_enabled: true,
            applied_routing_enabled: true,
            created_at: now,
        }
    }
}
