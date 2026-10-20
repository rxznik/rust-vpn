//! Настройки окна. Ядро сессии их не читает.
//!
//! JSON лежит в `ui_settings` с ключом `desktop`. Поля мобильного клиента туда не входят.

use rvpn_app::Client;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize, Serializer};

pub const SURFACE: &str = "desktop";

/// Идентификатор темы окна. Неизвестная строка читается как `night`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeId {
    #[default]
    Night,
    Graphite,
    Paper,
    Sand,
    Glass,
    Custom,
}

impl ThemeId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Night => "night",
            Self::Graphite => "graphite",
            Self::Paper => "paper",
            Self::Sand => "sand",
            Self::Glass => "glass",
            Self::Custom => "custom",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "graphite" => Self::Graphite,
            "paper" => Self::Paper,
            "sand" => Self::Sand,
            "glass" => Self::Glass,
            "custom" => Self::Custom,
            _ => Self::Night,
        }
    }
}

impl Serialize for ThemeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ThemeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

/// Плотность подписей на боковой панели.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Density {
    #[default]
    Standard,
    Compact,
}

impl Density {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Compact => "compact",
        }
    }

    pub fn parse(value: &str) -> Self {
        if value.trim() == "compact" {
            Self::Compact
        } else {
            Self::Standard
        }
    }
}

impl Serialize for Density {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Density {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSettings {
    #[serde(default)]
    pub theme: ThemeId,
    #[serde(default)]
    pub toolbar_density: Density,
    #[serde(default = "default_animations")]
    pub animations: bool,
    #[serde(default)]
    pub clear_background: bool,
    #[serde(default = "default_custom_opacity")]
    pub custom_opacity: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_surface_opacity: Option<u8>,
    #[serde(default = "default_custom_background")]
    pub custom_background: String,
    #[serde(default = "default_custom_surface")]
    pub custom_surface: String,
    #[serde(default = "default_custom_text")]
    pub custom_text: String,
    #[serde(default = "default_custom_muted")]
    pub custom_muted: String,
    #[serde(default = "default_custom_accent")]
    pub custom_accent: String,
    #[serde(default = "default_custom_on_accent")]
    pub custom_on_accent: String,
    #[serde(default = "default_font_size")]
    pub font_size: u8,
    #[serde(default)]
    pub font_family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub font_path: Option<String>,
    #[serde(default = "default_ui_zoom")]
    pub ui_zoom: u16,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            theme: ThemeId::Night,
            toolbar_density: Density::Standard,
            animations: default_animations(),
            clear_background: false,
            custom_opacity: default_custom_opacity(),
            custom_surface_opacity: None,
            custom_background: default_custom_background(),
            custom_surface: default_custom_surface(),
            custom_text: default_custom_text(),
            custom_muted: default_custom_muted(),
            custom_accent: default_custom_accent(),
            custom_on_accent: default_custom_on_accent(),
            font_size: default_font_size(),
            font_family: String::new(),
            font_path: None,
            ui_zoom: default_ui_zoom(),
        }
    }
}

impl DesktopSettings {
    pub fn surface_opacity(&self) -> u8 {
        self.custom_surface_opacity.unwrap_or(self.custom_opacity)
    }
}

pub fn load(client: &Client) -> DesktopSettings {
    match client.ui_blob(SURFACE) {
        Ok(Some(body)) => serde_json::from_str(&body).unwrap_or_default(),
        _ => DesktopSettings::default(),
    }
}

pub fn edit(client: &Client, change: impl FnOnce(&mut DesktopSettings)) -> DesktopSettings {
    let mut settings = load(client);
    change(&mut settings);
    if let Ok(body) = serde_json::to_string(&settings) {
        let _ = client.save_ui_blob(SURFACE, &body);
    }
    settings
}

fn default_animations() -> bool {
    true
}

fn default_custom_opacity() -> u8 {
    100
}

fn default_custom_background() -> String {
    "#070B14".into()
}

fn default_custom_surface() -> String {
    "#10182C".into()
}

fn default_custom_text() -> String {
    "#F7F9FC".into()
}

fn default_custom_muted() -> String {
    "#93A0B8".into()
}

fn default_custom_accent() -> String {
    "#8EABFF".into()
}

fn default_custom_on_accent() -> String {
    "#08101C".into()
}

fn default_font_size() -> u8 {
    12
}

fn default_ui_zoom() -> u16 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_visual_keys_use_defaults() {
        let settings: DesktopSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(settings.theme, ThemeId::Night);
        assert_eq!(settings.toolbar_density, Density::Standard);
        assert!(settings.animations);
        assert!(!settings.clear_background);
        assert_eq!(settings.custom_opacity, 100);
        assert!(settings.custom_surface_opacity.is_none());
        assert_eq!(settings.surface_opacity(), settings.custom_opacity);
        assert_eq!(settings.custom_background, "#070B14");
        assert_eq!(settings.custom_on_accent, "#08101C");
        assert_eq!(settings.font_size, 12);
        assert!(settings.font_family.is_empty());
        assert!(settings.font_path.is_none());
        assert_eq!(settings.ui_zoom, 100);
    }
}
