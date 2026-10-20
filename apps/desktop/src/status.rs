//! Тон задержки, страницы окна и фаза подключения.

use rvpn_model::{DELAY_FAIR_MS, DELAY_GOOD_MS};

/// Вкладки бокового меню. Числа совпадают со свойством `page` окна.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Page {
    Servers = 0,
    Lists = 1,
    Settings = 2,
    Logs = 3,
}

impl Page {
    pub fn is(self, value: i32) -> bool {
        value == self as i32
    }

    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Servers,
            1 => Self::Lists,
            2 => Self::Settings,
            3 => Self::Logs,
            _ => return None,
        })
    }
}

/// Фаза кнопки подключения. Числа совпадают со свойством `phase` окна.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Phase {
    Idle = 0,
    Connecting = 1,
    Connected = 2,
    Error = 3,
}

impl Phase {
    pub fn code(self) -> i32 {
        self as i32
    }

    pub fn is(self, value: i32) -> bool {
        value == self as i32
    }
}

#[derive(Clone, Copy)]
#[repr(i32)]
enum DelayTone {
    None = 0,
    Good = 1,
    Fair = 2,
    Slow = 3,
}

pub fn delay_tone(delay: &str) -> i32 {
    let token = delay.split_whitespace().next().unwrap_or("").trim();
    let tone = match token.to_ascii_lowercase().as_str() {
        "good" => DelayTone::Good,
        "fair" => DelayTone::Fair,
        "slow" => DelayTone::Slow,
        "" | "—" | "-" => DelayTone::None,
        _ => {
            let Ok(value) = token.parse::<u32>() else {
                return DelayTone::None as i32;
            };
            if value < DELAY_GOOD_MS {
                DelayTone::Good
            } else if value < DELAY_FAIR_MS {
                DelayTone::Fair
            } else {
                DelayTone::Slow
            }
        }
    };
    tone as i32
}

/// «Ответили N из M», если ответили не все. Полная пачка возвращает `None`, и вызывающий оставляет статус `finish`.
pub fn ping_reply_status(answered: usize, asked: usize) -> Option<String> {
    if answered < asked {
        Some(format!("Ответили {answered} из {asked}"))
    } else {
        None
    }
}

pub fn automatic_status(current: &str) -> bool {
    matches!(
        current,
        "" | "Не в сети"
            | "В сети"
            | "Подключение"
            | "Отключение"
            | "Сохранено"
            | "Импорт"
            | "Обновление"
            | "Вставьте ссылку"
            | "Буфер обмена пуст"
            | "Нет серверов"
            | "Неверный цвет"
            | "У подписки нет ссылки поддержки"
    )
}

/// «Не в сети» после обрыва, если текущая строка служебная. Ручной текст остаётся.
pub fn offline_status(current: &str) -> Option<&'static str> {
    if automatic_status(current) {
        Some("Не в сети")
    } else {
        None
    }
}

pub fn https_support_url(url: &str) -> bool {
    let Some(rest) = url.trim().strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty() && !rest.chars().any(char::is_whitespace)
}

pub fn traffic_label(known: bool, bytes: u64) -> String {
    if known {
        rvpn_model::format_bytes(bytes)
    } else {
        "—".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_tone_reads_milliseconds_and_words() {
        assert_eq!(delay_tone("42 ms"), 1);
        assert_eq!(delay_tone("150 ms"), 2);
        assert_eq!(delay_tone("999 ms"), 3);
        assert_eq!(delay_tone("good"), 1);
        assert_eq!(delay_tone("fair"), 2);
        assert_eq!(delay_tone("slow"), 3);
        assert_eq!(delay_tone("—"), 0);
    }

    #[test]
    fn ping_reply_status_names_a_partial_batch() {
        assert_eq!(ping_reply_status(2, 5).as_deref(), Some("Ответили 2 из 5"));
        assert_eq!(ping_reply_status(5, 5), None);
        assert!(!automatic_status("Ответили 2 из 5"));
    }

    #[test]
    fn automatic_status_keeps_manual_messages() {
        assert!(automatic_status(""));
        assert!(automatic_status("В сети"));
        assert!(automatic_status("Вставьте ссылку"));
        assert!(automatic_status("Буфер обмена пуст"));
        assert!(automatic_status("Нет серверов"));
        assert!(automatic_status("Неверный цвет"));
        assert!(automatic_status("У подписки нет ссылки поддержки"));
        assert!(!automatic_status("Отменено"));
        assert!(!automatic_status("Проверка задержки"));
        assert!(!automatic_status("Выбран самый быстрый"));
    }

    #[test]
    fn offline_status_replaces_only_automatic_text() {
        assert_eq!(offline_status("В сети"), Some("Не в сети"));
        assert_eq!(offline_status("Подключение"), Some("Не в сети"));
        assert_eq!(offline_status(""), Some("Не в сети"));
        assert_eq!(offline_status("Отменено"), None);
        assert_eq!(offline_status("Проверка задержки"), None);
        assert_eq!(offline_status("QR-код не найден"), None);
        assert_eq!(offline_status("Не удалось прочитать QR-код"), None);
    }

    #[test]
    fn support_link_must_be_https() {
        assert!(https_support_url("https://example.com/help"));
        assert!(!https_support_url("http://example.com/help"));
        assert!(!https_support_url("file:///tmp/help"));
        assert!(!https_support_url("https://"));
    }
}
