//! Цвета темы: разбор hex и бумага ночного режима.

use slint::Color;

/// Слот цвета своей темы. Строки приходят из полей окна.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorSlot {
    Background,
    Surface,
    Text,
    Muted,
    Accent,
    Ink,
}

impl ColorSlot {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "background" => Some(Self::Background),
            "surface" => Some(Self::Surface),
            "text" => Some(Self::Text),
            "muted" => Some(Self::Muted),
            "accent" => Some(Self::Accent),
            "ink" => Some(Self::Ink),
            _ => None,
        }
    }
}

pub fn parse_hex(input: &str) -> Option<(String, Color)> {
    let hex = input.trim().strip_prefix('#')?;
    if hex.len() != 6 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    let color = Color::from_rgb_u8(((n >> 16) & 0xff) as u8, ((n >> 8) & 0xff) as u8, (n & 0xff) as u8);
    Some((format!("#{n:06X}"), color))
}

pub fn clamp_opacity(value: f32) -> u8 {
    if !value.is_finite() {
        return 100;
    }
    value.round().clamp(0.0, 100.0) as u8
}

pub fn with_opacity(color: Color, opacity: u8) -> Color {
    let alpha = (u16::from(opacity) * 255 / 100) as u8;
    Color::from_argb_u8(alpha, color.red(), color.green(), color.blue())
}

pub fn is_dark(color: Color) -> bool {
    let luma = u16::from(color.red()) * 30 + u16::from(color.green()) * 59 + u16::from(color.blue()) * 11;
    luma / 100 < 160
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_rejects_short_and_invalid_and_normalizes() {
        assert!(parse_hex("#12").is_none());
        assert!(parse_hex("070B14").is_none());
        assert!(parse_hex("#070B1G").is_none());
        let (text, color) = parse_hex("  #070b14 ").unwrap();
        assert_eq!(text, "#070B14");
        assert_eq!(color.red(), 7);
        assert_eq!(color.green(), 11);
        assert_eq!(color.blue(), 20);
    }

    #[test]
    fn opacity_stays_inside_zero_to_hundred() {
        assert_eq!(clamp_opacity(-12.0), 0);
        assert_eq!(clamp_opacity(40.4), 40);
        assert_eq!(clamp_opacity(140.0), 100);
        assert_eq!(clamp_opacity(f32::NAN), 100);
        let faded = with_opacity(Color::from_rgb_u8(16, 24, 44), 50);
        assert_eq!(faded.alpha(), 127);
        assert_eq!(faded.red(), 16);
        let solid = with_opacity(Color::from_rgb_u8(247, 249, 252), 100);
        assert_eq!(solid.alpha(), 255);
    }

    #[test]
    fn night_background_is_dark_and_paper_is_light() {
        assert!(is_dark(Color::from_rgb_u8(7, 11, 20)));
        assert!(!is_dark(Color::from_rgb_u8(243, 246, 251)));
    }
}
