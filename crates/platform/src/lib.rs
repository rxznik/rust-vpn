//! Хуки ОС: системный прокси, автозапуск, уведомление, HWID.
//!
//! `HostPlatform` на Linux пишет org.gnome.system.proxy и снимок в proxy-snapshot.
//! Поддержка Linux — GNOME через `gsettings`.
//! Если `gsettings` нет, установка прокси возвращает ошибку, файл снимка не трогается.
//! macOS использует networksetup, Windows — Internet Settings в HKCU.
//! HWID — 32 hex-символа в файле каталога данных. Если машинного зерна нет, пишутся случайные 16 байт.
//! Повторный снимок прокси не затирает уже записанный файл.
//! На ОС вне linux/macos/windows системный прокси возвращает ошибку.
//! Имена ОС, версия и модель кэшируются в `HostPlatform::new`.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod other;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(target_os = "windows")]
use windows as os;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use other as os;


#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PlatformError(pub String);

/// Режим системного прокси GNOME. Неизвестная строка снимка читается как `none`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    #[default]
    None,
    Manual,
    Auto,
}

impl ProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Manual => "manual",
            Self::Auto => "auto",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "manual" => Self::Manual,
            "auto" => Self::Auto,
            _ => Self::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
}

/// OS hooks used by the session. Tests and mobile shells supply their own type.
pub trait Platform: Send + Sync {
    fn set_system_proxy(&self, http: Option<&ProxyEndpoint>, socks: Option<&ProxyEndpoint>) -> Result<(), PlatformError>;
    fn restore_captured_proxy(&self) -> Result<(), PlatformError>;
    fn set_autostart(&self, enabled: bool, command: &Path) -> Result<(), PlatformError>;
    fn notify(&self, title: &str, body: &str);
    fn device_hwid(&self) -> String;
    fn alternative_hwid(&self) -> String;
    fn os_name(&self) -> String;
    fn os_version(&self) -> String;
    fn device_model(&self) -> String;
}

pub struct HostPlatform {
    data_dir: PathBuf,
    os_name: String,
    os_version: String,
    device_model: String,
    hwid: String,
    alt_hwid: String,
}

impl HostPlatform {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        Self {
            os_name: std::env::consts::OS.to_string(),
            os_version: os::os_version(),
            device_model: std::env::consts::ARCH.to_string(),
            hwid: stored_id(&data_dir, "hwid"),
            alt_hwid: stored_id(&data_dir, "hwid-alt"),
            data_dir,
        }
    }
}

impl Platform for HostPlatform {
    fn set_system_proxy(&self, http: Option<&ProxyEndpoint>, socks: Option<&ProxyEndpoint>) -> Result<(), PlatformError> {
        os::set_system_proxy(&self.data_dir, http, socks)
    }

    fn restore_captured_proxy(&self) -> Result<(), PlatformError> {
        restore_captured_proxy(&self.data_dir)
    }

    fn set_autostart(&self, enabled: bool, command: &Path) -> Result<(), PlatformError> {
        os::set_autostart(enabled, command)
    }

    fn notify(&self, title: &str, body: &str) {
        os::notify(title, body);
    }

    fn device_hwid(&self) -> String {
        self.hwid.clone()
    }

    fn alternative_hwid(&self) -> String {
        self.alt_hwid.clone()
    }

    fn os_name(&self) -> String {
        self.os_name.clone()
    }

    fn os_version(&self) -> String {
        self.os_version.clone()
    }

    fn device_model(&self) -> String {
        self.device_model.clone()
    }
}

pub fn stored_id(data_dir: &Path, name: &str) -> String {
    let path = data_dir.join(name);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let existing = existing.trim().to_string();
        if !existing.is_empty() {
            return existing;
        }
    }
    let _ = std::fs::create_dir_all(data_dir);
    let seed = os::machine_seed().unwrap_or_else(random_seed);
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let id = hex_encode(&digest[..16]);
    let _ = std::fs::write(&path, &id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    id
}

fn random_seed() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        if file.read_exact(&mut bytes).is_ok() {
            return hex_encode(&bytes);
        }
    }
    hex_encode(&std::process::id().to_ne_bytes())
}
fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join("proxy-snapshot")
}

fn capture_proxy(dir: &Path) -> Result<(), PlatformError> {
    let path = snapshot_path(dir);
    if path.is_file() {
        return Ok(());
    }
    let body = os::read_proxy_snapshot()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PlatformError(e.to_string()))?;
    }
    std::fs::write(&path, body).map_err(|e| PlatformError(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn restore_captured_proxy(dir: &Path) -> Result<(), PlatformError> {
    let path = snapshot_path(dir);
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    os::write_proxy_snapshot(&body)?;
    let _ = std::fs::remove_file(path);
    Ok(())
}
fn snapshot_map(body: &str) -> std::collections::BTreeMap<String, String> {
    body.lines().filter_map(|line| line.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}
fn dirs_config() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| dirs_home().join(".config"))
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwid_stays_stable() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/hwid");
        let _ = std::fs::remove_dir_all(&dir);
        let a = stored_id(&dir, "hwid");
        let b = stored_id(&dir, "hwid");
        assert_eq!(a, b);
        assert_ne!(a, stored_id(&dir, "hwid-alt"));
        std::fs::write(dir.join("hwid"), "\n").unwrap();
        let rewritten = stored_id(&dir, "hwid");
        assert_eq!(rewritten, stored_id(&dir, "hwid"));
        assert_ne!(rewritten, "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_text_parses_and_existing_file_is_kept() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/platform-snapshot");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let body = "mode=none\nhttp-host=127.0.0.1\nhttp-port=8080\n";
        std::fs::write(dir.join("proxy-snapshot"), body).unwrap();
        capture_proxy(&dir).unwrap();
        let kept = std::fs::read_to_string(dir.join("proxy-snapshot")).unwrap();
        assert_eq!(kept, body);
        let map = snapshot_map(&kept);
        assert_eq!(map.get("mode").map(String::as_str).map(ProxyMode::parse), Some(ProxyMode::None));
        assert_eq!(map.get("http-port").map(String::as_str), Some("8080"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
