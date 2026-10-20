use super::{capture_proxy, restore_captured_proxy, snapshot_map, PlatformError, ProxyEndpoint};
use std::path::Path;
use std::process::Command;

pub(crate) fn machine_seed() -> Option<String> {
    let output = Command::new("reg").args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"]).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    text.split_whitespace().last().map(|s| s.to_string())
}

pub(crate) fn os_version() -> String {
    std::env::consts::OS.to_string()
}

pub(crate) fn notify(_title: &str, _body: &str) {}

pub(crate) fn set_system_proxy(dir: &Path, http: Option<&ProxyEndpoint>, socks: Option<&ProxyEndpoint>) -> Result<(), PlatformError> {
    if http.is_none() && socks.is_none() {
        return restore_captured_proxy(dir);
    }
    capture_proxy(dir)?;
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_SET_VALUE).map_err(|e| PlatformError(e.to_string()))?;
    let mut parts = Vec::new();
    if let Some(http) = http {
        parts.push(format!("http={}:{}", http.host, http.port));
        parts.push(format!("https={}:{}", http.host, http.port));
    }
    if let Some(socks) = socks {
        parts.push(format!("socks={}:{}", socks.host, socks.port));
    }
    key.set_value("ProxyEnable", &1u32).map_err(|e| PlatformError(e.to_string()))?;
    key.set_value("ProxyServer", &parts.join(";")).map_err(|e| PlatformError(e.to_string()))?;
    Ok(())
}

pub(crate) fn read_proxy_snapshot() -> Result<String, PlatformError> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_READ).map_err(|e| PlatformError(e.to_string()))?;
    let enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    let server: String = key.get_value("ProxyServer").unwrap_or_default();
    Ok(format!("enable={enable}\nserver={server}\n"))
}

pub(crate) fn write_proxy_snapshot(body: &str) -> Result<(), PlatformError> {
    use winreg::enums::*;
    use winreg::RegKey;
    let map = snapshot_map(body);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_SET_VALUE).map_err(|e| PlatformError(e.to_string()))?;
    let enable = map.get("enable").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    key.set_value("ProxyEnable", &enable).map_err(|e| PlatformError(e.to_string()))?;
    if let Some(server) = map.get("server") {
        key.set_value("ProxyServer", server).map_err(|e| PlatformError(e.to_string()))?;
    }
    Ok(())
}

pub(crate) fn set_autostart(enabled: bool, command: &Path) -> Result<(), PlatformError> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_SET_VALUE).map_err(|e| PlatformError(e.to_string()))?;
    if enabled {
        key.set_value("rustvpn", &command.display().to_string()).map_err(|e| PlatformError(e.to_string()))?;
    } else {
        let _ = key.delete_value("rustvpn");
    }
    Ok(())
}
