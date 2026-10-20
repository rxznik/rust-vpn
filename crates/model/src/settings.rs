use serde::de::Deserializer;
use serde::{Deserialize, Serialize, Serializer};

use crate::protocol::{Fragment, MuxSettings, Noise};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Auto,
    Manual,
    FromJson,
    Disable,
}

impl Default for AuthMode {
    fn default() -> Self {
        Self::Auto
    }
}

impl<'de> Deserialize<'de> for AuthMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "auto" => Self::Auto,
            "manual" => Self::Manual,
            "from_json" => Self::FromJson,
            "disable" => Self::Disable,
            _ => Self::default(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PingType {
    Tcp,
    Icmp,
    Proxy,
    ProxyHead,
}

impl Default for PingType {
    fn default() -> Self {
        Self::Tcp
    }
}

impl<'de> Deserialize<'de> for PingType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "tcp" => Self::Tcp,
            "icmp" => Self::Icmp,
            "proxy" => Self::Proxy,
            "proxy-head" => Self::ProxyHead,
            _ => Self::default(),
        })
    }
}

impl PingType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "tcp" => Some(Self::Tcp),
            "icmp" => Some(Self::Icmp),
            "proxy" => Some(Self::Proxy),
            "proxy-head" => Some(Self::ProxyHead),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoConnectType {
    LastUsed,
    LowestDelay,
    Random,
}

impl Default for AutoConnectType {
    fn default() -> Self {
        Self::LastUsed
    }
}

impl<'de> Deserialize<'de> for AutoConnectType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "lastused" => Self::LastUsed,
            "lowestdelay" => Self::LowestDelay,
            "random" => Self::Random,
            _ => Self::default(),
        })
    }
}

impl AutoConnectType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "lastused" | "last-used" | "last_used" => Some(Self::LastUsed),
            "lowestdelay" | "lowest-delay" | "lowest_delay" => Some(Self::LowestDelay),
            "random" => Some(Self::Random),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortType {
    Without,
    Ping,
    Alphabet,
}

impl Default for SortType {
    fn default() -> Self {
        Self::Without
    }
}

impl<'de> Deserialize<'de> for SortType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "without" => Self::Without,
            "ping" => Self::Ping,
            "alphabet" => Self::Alphabet,
            _ => Self::default(),
        })
    }
}

impl SortType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "without" => Some(Self::Without),
            "ping" => Some(Self::Ping),
            "alphabet" => Some(Self::Alphabet),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PerAppMode {
    Off,
    On,
    Bypass,
}

impl Default for PerAppMode {
    fn default() -> Self {
        Self::Off
    }
}

impl<'de> Deserialize<'de> for PerAppMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "off" => Self::Off,
            "on" => Self::On,
            "bypass" => Self::Bypass,
            _ => Self::default(),
        })
    }
}

impl PerAppMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "on" => Some(Self::On),
            "bypass" => Some(Self::Bypass),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::Bypass => "bypass",
        }
    }
}

/// Уровень журнала Xray. Неизвестное значение читается как `warning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Debug,
    Info,
    #[default]
    Warning,
    Error,
    None,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::None => "none",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "debug" => Self::Debug,
            "info" => Self::Info,
            "error" => Self::Error,
            "none" => Self::None,
            _ => Self::Warning,
        }
    }
}

impl Serialize for LogLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

/// Порты, туннель, прокси, пинг и автозапуск. Эти поля читает сессия и Xray.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreSettings {
    pub socks_port: u16,
    pub http_port: u16,
    pub api_port: u16,
    pub http_enabled: bool,
    pub socks_auth_mode: AuthMode,
    pub http_auth_mode: AuthMode,
    pub socks_user: String,
    pub socks_password: String,
    pub http_user: String,
    pub http_password: String,
    pub tun_enable: bool,
    pub proxy_enable: bool,
    pub tun_mtu: u16,
    pub sniffing: bool,
    pub mux: MuxSettings,
    pub fragmentation_enable: bool,
    pub fragmentation: Fragment,
    pub noises_enable: bool,
    pub noise: Noise,
    pub ping_type: PingType,
    pub check_url: String,
    pub autoconnect: bool,
    pub autoconnect_type: AutoConnectType,
    pub autostart: bool,
    pub exclude_routes: Vec<String>,
    pub per_app_mode: PerAppMode,
    pub per_app_list: Vec<String>,
    #[serde(default)]
    pub log_level: LogLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_server_id: Option<String>,
    pub sort_type: SortType,
    pub no_limit: bool,
}

impl Default for CoreSettings {
    fn default() -> Self {
        Self {
            socks_port: 10808,
            http_port: 10809,
            api_port: 10085,
            http_enabled: false,
            socks_auth_mode: AuthMode::Auto,
            http_auth_mode: AuthMode::Auto,
            socks_user: String::new(),
            socks_password: String::new(),
            http_user: String::new(),
            http_password: String::new(),
            tun_enable: false,
            proxy_enable: true,
            tun_mtu: 1500,
            sniffing: true,
            mux: MuxSettings::default(),
            fragmentation_enable: false,
            fragmentation: Fragment {
                length: "50-100".into(),
                interval: "10-20".into(),
                packets: "tlshello".into(),
                max_split: None,
            },
            noises_enable: false,
            noise: Noise {
                kind: "rand".into(),
                packet: "10-20".into(),
                delay: "10-16".into(),
                apply_to: None,
            },
            ping_type: PingType::Tcp,
            check_url: "https://www.gstatic.com/generate_204".into(),
            autoconnect: false,
            autoconnect_type: AutoConnectType::LastUsed,
            autostart: false,
            exclude_routes: Vec::new(),
            per_app_mode: PerAppMode::Off,
            per_app_list: Vec::new(),
            log_level: LogLevel::Warning,
            last_server_id: None,
            sort_type: SortType::Without,
            no_limit: false,
        }
    }
}

fn default_font_size() -> u8 {
    12
}

fn default_ui_zoom() -> u16 {
    100
}

const FONT_SIZES: [u8; 5] = [12, 14, 16, 18, 20];
const UI_ZOOMS: [u16; 7] = [50, 75, 100, 125, 150, 175, 200];

pub fn font_size_step(value: u8) -> u8 {
    if FONT_SIZES.contains(&value) { value } else { default_font_size() }
}

pub fn nearest_zoom(value: u16) -> u16 {
    UI_ZOOMS.iter().copied().min_by_key(|step| step.abs_diff(value)).unwrap_or(default_ui_zoom())
}

pub fn step_zoom(current: u16, up: bool) -> u16 {
    let current = nearest_zoom(current);
    if up {
        UI_ZOOMS.iter().copied().find(|step| *step > current).unwrap_or(*UI_ZOOMS.last().unwrap_or(&200))
    } else {
        UI_ZOOMS.iter().rev().copied().find(|step| *step < current).unwrap_or(UI_ZOOMS[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_field(key: &str, value: &str) -> CoreSettings {
        let mut raw = serde_json::to_value(CoreSettings::default()).unwrap();
        raw[key] = serde_json::json!(value);
        serde_json::from_value(raw).unwrap()
    }

    #[test]
    fn unknown_setting_enum_falls_back_and_known_value_round_trips() {
        let loaded = with_field("ping_type", "not-a-ping");
        assert_eq!(loaded.ping_type, PingType::default());
        assert_eq!(loaded.socks_port, CoreSettings::default().socks_port);
        assert_eq!(with_field("socks_auth_mode", "nope").socks_auth_mode, AuthMode::Auto);
        assert_eq!(with_field("autoconnect_type", "nope").autoconnect_type, AutoConnectType::LastUsed);
        assert_eq!(with_field("sort_type", "nope").sort_type, SortType::Without);
        assert_eq!(with_field("per_app_mode", "nope").per_app_mode, PerAppMode::Off);

        let ping = with_field("ping_type", "proxy-head");
        assert_eq!(ping.ping_type, PingType::ProxyHead);
        assert_eq!(serde_json::to_value(&ping).unwrap()["ping_type"], "proxy-head");
        assert_eq!(serde_json::to_value(&with_field("socks_auth_mode", "from_json")).unwrap()["socks_auth_mode"], "from_json");
        assert_eq!(serde_json::to_value(&with_field("autoconnect_type", "lowestdelay")).unwrap()["autoconnect_type"], "lowestdelay");
        assert_eq!(serde_json::to_value(&with_field("sort_type", "alphabet")).unwrap()["sort_type"], "alphabet");
        assert_eq!(serde_json::to_value(&with_field("per_app_mode", "bypass")).unwrap()["per_app_mode"], "bypass");
    }
}

pub fn font_family_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.chars().count() > 80 || value.chars().any(|ch| ch.is_control()) {
        return None;
    }
    Some(value.to_string())
}
