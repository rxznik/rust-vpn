use super::{capture_proxy, dirs_home, restore_captured_proxy, snapshot_map, PlatformError, ProxyEndpoint};
use std::path::Path;
use std::process::Command;

pub(crate) fn machine_seed() -> Option<String> {
    let output = Command::new("ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("\"IOPlatformUUID\" = ").map(|v| v.trim_matches('"').to_string())
    })
}

pub(crate) fn os_version() -> String {
    std::env::consts::OS.to_string()
}

pub(crate) fn notify(title: &str, body: &str) {
    let script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run";
    let _ = Command::new("osascript").args(["-e", script, "--", title, body]).status();
}

pub(crate) fn set_system_proxy(dir: &Path, http: Option<&ProxyEndpoint>, socks: Option<&ProxyEndpoint>) -> Result<(), PlatformError> {
    if http.is_none() && socks.is_none() {
        return restore_captured_proxy(dir);
    }
    capture_proxy(dir)?;
    let service = network_service()?;
    apply_service(&service, "web", http)?;
    apply_service(&service, "secureweb", http)?;
    apply_service(&service, "socksfirewall", socks)?;
    Ok(())
}

pub(crate) fn apply_service(service: &str, kind: &str, endpoint: Option<&ProxyEndpoint>) -> Result<(), PlatformError> {
    if let Some(endpoint) = endpoint {
        networksetup(&[&format!("-set{kind}proxy"), service, &endpoint.host, &endpoint.port.to_string()])?;
        networksetup(&[&format!("-set{kind}proxystate"), service, "on"])?;
    } else {
        networksetup(&[&format!("-set{kind}proxystate"), service, "off"])?;
    }
    Ok(())
}

pub(crate) fn network_service() -> Result<String, PlatformError> {
    let output = Command::new("networksetup").arg("-listallnetworkservices").output().map_err(|e| PlatformError(e.to_string()))?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("An asterisk") && !line.starts_with('*'))
        .map(|s| s.to_string())
        .ok_or_else(|| PlatformError("no network service".into()))
}

pub(crate) fn networksetup(args: &[&str]) -> Result<(), PlatformError> {
    let status = Command::new("networksetup").args(args).status().map_err(|e| PlatformError(e.to_string()))?;
    if status.success() { Ok(()) } else { Err(PlatformError(format!("networksetup {}", args.join(" ")))) }
}

pub(crate) fn read_proxy_snapshot() -> Result<String, PlatformError> {
    let service = network_service()?;
    let mut body = format!("service={service}\n");
    for (name, flag) in [("web", "-getwebproxy"), ("secureweb", "-getsecurewebproxy"), ("socks", "-getsocksfirewallproxy")] {
        let output = Command::new("networksetup").args([flag, &service]).output().map_err(|e| PlatformError(e.to_string()))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let mut enabled = "off".to_string();
        let mut host = String::new();
        let mut port = "0".to_string();
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("Enabled:") {
                enabled = if value.trim().eq_ignore_ascii_case("yes") { "on" } else { "off" }.to_string();
            } else if let Some(value) = line.strip_prefix("Server:") {
                host = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Port:") {
                port = value.trim().to_string();
            }
        }
        body.push_str(&format!("{name}-enabled={enabled}\n{name}-host={host}\n{name}-port={port}\n"));
    }
    Ok(body)
}

pub(crate) fn write_proxy_snapshot(body: &str) -> Result<(), PlatformError> {
    let map = snapshot_map(body);
    let Some(service) = map.get("service") else {
        return Ok(());
    };
    for (name, kind) in [("web", "web"), ("secureweb", "secureweb"), ("socks", "socksfirewall")] {
        let enabled = map.get(&format!("{name}-enabled")).map(String::as_str).unwrap_or("off");
        if enabled == "on" {
            let host = map.get(&format!("{name}-host")).map(String::as_str).unwrap_or("");
            let port = map.get(&format!("{name}-port")).map(String::as_str).unwrap_or("0");
            networksetup(&[&format!("-set{kind}proxy"), service, host, port])?;
        }
        networksetup(&[&format!("-set{kind}proxystate"), service, enabled])?;
    }
    Ok(())
}

pub(crate) fn set_autostart(enabled: bool, command: &Path) -> Result<(), PlatformError> {
    let dir = dirs_home().join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir).map_err(|e| PlatformError(e.to_string()))?;
    let path = dir.join("com.rustvpn.client.plist");
    if !enabled {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let body = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.rustvpn.client</string>
<key>ProgramArguments</key><array><string>{}</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>"#, command.display());
    std::fs::write(path, body).map_err(|e| PlatformError(e.to_string()))
}
