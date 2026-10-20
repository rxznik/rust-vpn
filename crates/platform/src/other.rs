use super::{PlatformError, ProxyEndpoint};
use std::path::Path;

pub(crate) fn machine_seed() -> Option<String> {
    None
}

pub(crate) fn os_version() -> String {
    std::env::consts::OS.to_string()
}

pub(crate) fn notify(_title: &str, _body: &str) {}

pub(crate) fn set_system_proxy(_dir: &Path, _http: Option<&ProxyEndpoint>, _socks: Option<&ProxyEndpoint>) -> Result<(), PlatformError> {
    Err(PlatformError("system proxy is not implemented on this OS".into()))
}

pub(crate) fn read_proxy_snapshot() -> Result<String, PlatformError> {
    Err(PlatformError("system proxy is not implemented on this OS".into()))
}

pub(crate) fn write_proxy_snapshot(_body: &str) -> Result<(), PlatformError> {
    Err(PlatformError("system proxy is not implemented on this OS".into()))
}

pub(crate) fn set_autostart(_enabled: bool, _command: &Path) -> Result<(), PlatformError> {
    Err(PlatformError("autostart is not implemented on this OS".into()))
}
