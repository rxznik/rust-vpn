//! Доменные типы клиента: сервер, подписка, маршрут, настройки.
//!
//! Сериализация — JSON. Новые поля имеют serde default, старые документы открываются.
//! Неизвестный тег `protocol` или `kind` не десериализуется.
//! `APP_USER_AGENT` равен `rustvpn/0.1`.
//! `LOCAL_SUBSCRIPTION_ID` равен `local` и не удаляется хранилищем.
//! Черновик маршрута (`draft_profile_id`, `draft_routing_enabled`) применяется к процессу
//! только после commit в `applied_profile_id` и `applied_routing_enabled`.
//!
//! `overlay_settings` в `rvpn-app` копирует в сессию из `SubscriptionMeta`, когда мета их задаёт:
//! `proxy_enable`, `tun_enable`, `sniffing`, `inbound_http` → `http_enabled`,
//! `socks_auth_mode`, `socks_auth_user`, `socks_auth_password`,
//! `http_auth_mode`, `http_auth_user`, `http_auth_password`,
//! `per_app_mode`, непустой `per_app_list`, непустой `exclude_routes`,
//! `no_limit` и `no_limit_xhttp` → `no_limit`, `mux`, `ping_type`, `check_url`,
//! `fragmentation_enable` и при нём `fragmentation`, `noises_enable` и при нём `noise`, `autostart`.
//! Остальные поля меты на работающий процесс не влияют.
//! Окно хранит свою тему, шрифт и зум отдельно. Сортировка списка живёт в `CoreSettings`.
//!
//! `PingType`: `tcp`, `icmp`, `proxy`, `proxy-head`.
//! `AuthMode`: `auto`, `manual`, `from_json`, `disable`.
//! `Protocol::Json` хранит сырой документ. Компилятор ссылок его outbound не переписывает;
//! сессия отдаёт документ в `prepare_passthrough`.
//! Лестница зума: 50, 75, 100, 125, 150, 175, 200. Размер шрифта: 12, 14, 16, 18, 20.

use serde::{Deserialize, Serialize};

mod protocol;
mod routing;
mod settings;
mod subscription;

pub use protocol::*;
pub use routing::*;
pub use settings::*;
pub use subscription::*;

pub const APP_USER_AGENT: &str = "rustvpn/0.1";

/// Границы тона задержки: меньше 150 мс — хорошо, меньше 400 мс — средне.
pub const DELAY_GOOD_MS: u32 = 150;
pub const DELAY_FAIR_MS: u32 = 400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<Fragment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise: Option<Noise>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u32>,
}

impl Server {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    pub fn subtitle(&self) -> String {
        self.description
            .clone()
            .unwrap_or_else(|| self.protocol.label().to_string())
    }
}

/// Колонки списка. Тело протокола здесь не разбирается.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSummary {
    pub id: String,
    pub subscription_id: Option<String>,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub delay_ms: Option<u32>,
    pub subtitle: String,
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn traffic_line(info: &UserInfo) -> String {
    let used = info.upload.saturating_add(info.download);
    if info.total == 0 {
        format_bytes(used)
    } else {
        format!("{} / {}", format_bytes(used), format_bytes(info.total))
    }
}

/// Happ treats `true` and `1` as enabled. Any other non-empty value disables.
pub fn parse_flag(value: &str) -> Option<bool> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value == "1" || value.eq_ignore_ascii_case("true"))
}

pub fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_values_match_happ() {
        assert_eq!(parse_flag("1"), Some(true));
        assert_eq!(parse_flag("true"), Some(true));
        assert_eq!(parse_flag("TRUE"), Some(true));
        assert_eq!(parse_flag("0"), Some(false));
        assert_eq!(parse_flag("false"), Some(false));
        assert_eq!(parse_flag(""), None);
    }

    #[test]
    fn traffic_line_shows_used_and_total() {
        let info = UserInfo {
            upload: 0,
            download: 1024,
            total: 2048,
            expire: None,
        };
        assert_eq!(traffic_line(&info), "1.0 KB / 2.0 KB");
    }

    #[test]
    fn old_settings_open_without_layout_fields() {
        let mut value = serde_json::to_value(CoreSettings::default()).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.insert("layout_json".into(), serde_json::json!("1,2,3"));
        obj.insert("sandbox".into(), serde_json::json!(true));
        obj.insert("theme".into(), serde_json::json!("day"));
        let settings: CoreSettings = serde_json::from_value(value).unwrap();
        assert_eq!(settings.socks_port, 10808);
    }

    #[test]
    fn zoom_steps_stay_on_the_ladder() {
        assert_eq!(step_zoom(100, true), 125);
        assert_eq!(step_zoom(100, false), 75);
        assert_eq!(step_zoom(200, true), 200);
        assert_eq!(step_zoom(50, false), 50);
        assert_eq!(nearest_zoom(110), 100);
    }

    #[test]
    fn font_family_rejects_long_and_control_names() {
        assert_eq!(font_family_name("  Ubuntu  ").as_deref(), Some("Ubuntu"));
        assert_eq!(font_family_name("").as_deref(), Some(""));
        assert!(font_family_name("bad\nname").is_none());
        assert!(font_family_name(&"а".repeat(81)).is_none());
        assert_eq!(font_size_step(15), 12);
        assert_eq!(font_size_step(18), 18);
    }

    #[test]
    fn group_name_label_and_mode_parse() {
        assert_eq!(group_name("  Дом  ").as_deref(), Some("Дом"));
        assert!(group_name("").is_none());
        assert!(group_name("bad\nname").is_none());
        assert!(group_name(&"а".repeat(81)).is_none());
        assert_eq!(Protocol::Socks { username: None, password: None }.label(), "SOCKS5");
        assert_eq!(PingType::parse("proxy-head"), Some(PingType::ProxyHead));
        assert_eq!(AutoConnectType::parse("last_used"), Some(AutoConnectType::LastUsed));
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert!(serde_json::from_str::<Protocol>(r#"{"protocol":"nope"}"#).is_err());
        assert!(unix_now() >= 0);
    }
}
