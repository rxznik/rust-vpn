use super::{capture_proxy, dirs_config, restore_captured_proxy, snapshot_map, PlatformError, ProxyEndpoint, ProxyMode};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PROXY_ENV: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "socks_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "FTP_PROXY",
    "ALL_PROXY",
    "SOCKS_PROXY",
    "no_proxy",
    "NO_PROXY",
];

pub(crate) fn machine_seed() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub(crate) fn os_version() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| text.lines().find_map(|line| line.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string())))
        .unwrap_or_else(|| "linux".into())
}

pub(crate) fn notify(title: &str, body: &str) {
    let _ = Command::new("notify-send").args([title, body]).status();
}

pub(crate) fn set_system_proxy(dir: &Path, http: Option<&ProxyEndpoint>, socks: Option<&ProxyEndpoint>) -> Result<(), PlatformError> {
    if http.is_none() && socks.is_none() {
        return restore_captured_proxy(dir);
    }
    capture_proxy(dir)?;
    if let Err(err) = dconf_load(&proxy_dconf_document(http, socks)) {
        restore_captured_proxy(dir)?;
        return Err(err);
    }
    Ok(())
}

fn proxy_dconf_document(http: Option<&ProxyEndpoint>, socks: Option<&ProxyEndpoint>) -> String {
    let mut body = format!("[org/gnome/system/proxy]\nmode={}\n", gvariant_string(ProxyMode::Manual.as_str()));
    if let Some(http) = http {
        body.push_str(&endpoint_group("org/gnome/system/proxy/http", http));
        body.push_str(&endpoint_group("org/gnome/system/proxy/https", http));
    }
    if let Some(socks) = socks {
        body.push_str(&endpoint_group("org/gnome/system/proxy/socks", socks));
    }
    body
}

fn endpoint_group(path: &str, endpoint: &ProxyEndpoint) -> String {
    format!("\n[{path}]\nhost={}\nport={}\n", gvariant_string(&endpoint.host), endpoint.port)
}

fn gvariant_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn dconf_load(document: &str) -> Result<(), PlatformError> {
    let mut command = Command::new("dconf");
    command.args(["load", "/"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped());
    for key in PROXY_ENV {
        command.env_remove(key);
    }
    let mut child = command.spawn().map_err(|e| PlatformError(e.to_string()))?;
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(document.as_bytes()),
        None => Err(std::io::Error::other("dconf stdin")),
    };
    let output = child.wait_with_output().map_err(|e| PlatformError(e.to_string()))?;
    if !output.status.success() {
        return Err(PlatformError("dconf load /".into()));
    }
    write_result.map_err(|e| PlatformError(e.to_string()))
}

pub(crate) fn gsettings(args: &[&str]) -> Result<(), PlatformError> {
    let status = Command::new("gsettings").args(args).status().map_err(|e| PlatformError(e.to_string()))?;
    if status.success() {
        Ok(())
    } else {
        Err(PlatformError(format!("gsettings {}", args.join(" "))))
    }
}

pub(crate) fn read_proxy_snapshot() -> Result<String, PlatformError> {
    let mut body = String::new();
    for (name, key) in [
        ("mode", "org.gnome.system.proxy mode"),
        ("http-host", "org.gnome.system.proxy.http host"),
        ("http-port", "org.gnome.system.proxy.http port"),
        ("https-host", "org.gnome.system.proxy.https host"),
        ("https-port", "org.gnome.system.proxy.https port"),
        ("socks-host", "org.gnome.system.proxy.socks host"),
        ("socks-port", "org.gnome.system.proxy.socks port"),
    ] {
        let mut parts = key.split(' ');
        let schema = parts.next().unwrap_or_default();
        let field = parts.next().unwrap_or_default();
        let output = Command::new("gsettings").args(["get", schema, field]).output().map_err(|e| PlatformError(e.to_string()))?;
        if !output.status.success() {
            return Err(PlatformError("gsettings get".into()));
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().trim_matches('\'').replace(['\n', '\r'], "");
        body.push_str(name);
        body.push('=');
        body.push_str(&value);
        body.push('\n');
    }
    Ok(body)
}

pub(crate) fn write_proxy_snapshot(body: &str) -> Result<(), PlatformError> {
    let map = snapshot_map(body);
    let mode = map.get("mode").map(String::as_str).map(ProxyMode::parse).unwrap_or_default();
    gsettings(&["set", "org.gnome.system.proxy", "mode", mode.as_str()])?;
    if let (Some(host), Some(port)) = (map.get("http-host"), map.get("http-port")) {
        gsettings(&["set", "org.gnome.system.proxy.http", "host", host])?;
        gsettings(&["set", "org.gnome.system.proxy.http", "port", port])?;
    }
    if let (Some(host), Some(port)) = (map.get("https-host"), map.get("https-port")) {
        gsettings(&["set", "org.gnome.system.proxy.https", "host", host])?;
        gsettings(&["set", "org.gnome.system.proxy.https", "port", port])?;
    }
    if let (Some(host), Some(port)) = (map.get("socks-host"), map.get("socks-port")) {
        gsettings(&["set", "org.gnome.system.proxy.socks", "host", host])?;
        gsettings(&["set", "org.gnome.system.proxy.socks", "port", port])?;
    }
    Ok(())
}

pub(crate) fn set_autostart(enabled: bool, command: &Path) -> Result<(), PlatformError> {
    let dir = dirs_config().join("autostart");
    std::fs::create_dir_all(&dir).map_err(|e| PlatformError(e.to_string()))?;
    let path = dir.join("rustvpn.desktop");
    if !enabled {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let body = format!("[Desktop Entry]\nType=Application\nName=rustvpn\nExec={}\nX-GNOME-Autostart-enabled=true\n", command.display());
    std::fs::write(path, body).map_err(|e| PlatformError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dconf_document_sets_manual_socks_and_optional_http() {
        let socks = ProxyEndpoint { host: "127.0.0.1".into(), port: 10808 };
        let socks_only = proxy_dconf_document(None, Some(&socks));
        assert_eq!(
            socks_only,
            "[org/gnome/system/proxy]\nmode='manual'\n\n[org/gnome/system/proxy/socks]\nhost='127.0.0.1'\nport=10808\n",
        );
        assert!(!socks_only.contains("[org/gnome/system/proxy/http]"));
        assert!(!socks_only.contains("[org/gnome/system/proxy/https]"));

        let http = ProxyEndpoint { host: "127.0.0.1".into(), port: 8080 };
        let with_http = proxy_dconf_document(Some(&http), Some(&socks));
        assert_eq!(
            with_http,
            "\
[org/gnome/system/proxy]
mode='manual'

[org/gnome/system/proxy/http]
host='127.0.0.1'
port=8080

[org/gnome/system/proxy/https]
host='127.0.0.1'
port=8080

[org/gnome/system/proxy/socks]
host='127.0.0.1'
port=10808
"
        );
    }
}
