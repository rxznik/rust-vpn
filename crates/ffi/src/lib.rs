//! UniFFI-фасад сессии для Android VpnService и iOS packet tunnel.
//!
//! Контракт задают атрибуты uniffi в lib.rs. Файл UDL в поставку биндингов не входит.
//! `stage_session` вызывается до создания TUN.
//! Android передаёт fd через `set_tun_fd`.
//! iOS вызывает `prepare_bridge`, затем `push_packet` и `pop_packet_wait`.
//! Ошибки приходят строкой в `VpnError::Core`.

use rvpn_app::Client;
use rvpn_platform::HostPlatform;
use std::path::PathBuf;
use std::sync::Arc;

uniffi::setup_scaffolding!();

const MISSING_DELAY_MS: i64 = -1;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VpnError {
    #[error("{message}")]
    Core { message: String },
}

/// One server row for a mobile list.
#[derive(uniffi::Record)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    pub subtitle: String,
    pub delay: String,
    pub endpoint: String,
}

/// Delay from `ping_many`. `delay_ms` is [`MISSING_DELAY_MS`] when the probe did not answer.
#[derive(uniffi::Record)]
pub struct DelayView {
    pub id: String,
    pub delay_ms: i64,
}

/// Subscription row exported to mobile shells.
#[derive(uniffi::Record)]
pub struct SubscriptionView {
    pub id: String,
    pub name: String,
    pub url: String,
}

/// Server group. Deleting a group does not delete its servers.
#[derive(uniffi::Record)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub members: Vec<String>,
}

/// Connected session counters. Traffic comes from the background stats snapshot.
#[derive(uniffi::Record)]
pub struct SessionStatus {
    pub connected: bool,
    pub server_id: String,
    pub server_name: String,
    pub upload: u64,
    pub download: u64,
    pub message: String,
}

/// Process-wide session handle. One instance per application data directory.
#[derive(uniffi::Object)]
pub struct VpnCore {
    inner: Client,
}

#[uniffi::export]
impl VpnCore {
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Result<Arc<Self>, VpnError> {
        let platform = Arc::new(HostPlatform::new(&data_dir));
        let inner = Client::open(PathBuf::from(&data_dir), platform).map_err(map_err)?;
        Ok(Arc::new(Self { inner }))
    }

    pub fn import_text(&self, text: String) -> Result<String, VpnError> {
        self.inner.import_text(&text).map_err(map_err)
    }

    pub fn refresh(&self, subscription_id: String) -> Result<u32, VpnError> {
        self.inner.refresh(&subscription_id).map(|n| n as u32).map_err(map_err)
    }

    pub fn servers(&self) -> Result<Vec<ServerView>, VpnError> {
        Ok(self.inner.servers(None).map_err(map_err)?.into_iter().map(|row| ServerView {
            id: row.id,
            name: row.name,
            subtitle: row.subtitle,
            delay: row.delay,
            endpoint: row.endpoint,
        }).collect())
    }

    pub fn stage_session(&self, server_id: String) -> Result<(), VpnError> {
        self.inner.stage_session(&server_id).map_err(map_err)
    }

    pub fn connect(&self, server_id: String) -> Result<(), VpnError> {
        self.inner.connect(&server_id).map_err(map_err)
    }

    pub fn disconnect(&self) -> Result<(), VpnError> {
        self.inner.disconnect().map_err(map_err)
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    pub fn status(&self) -> SessionStatus {
        let status = self.inner.status();
        SessionStatus {
            connected: status.connected,
            server_id: status.server_id.unwrap_or_default(),
            server_name: status.server_name.unwrap_or_default(),
            upload: status.upload,
            download: status.download,
            message: status.message.unwrap_or_default(),
        }
    }

    pub fn hwid(&self) -> String {
        self.inner.hwid()
    }

    pub fn set_tun_fd(&self, fd: i32) {
        self.inner.set_tun_fd(fd);
    }

    pub fn prepare_bridge(&self) {
        let _ = self.inner.prepare_bridge();
    }

    pub fn push_packet(&self, packet: Vec<u8>) -> Result<(), VpnError> {
        self.inner.push_packet(packet).map_err(map_err)
    }

    pub fn pop_packet(&self) -> Vec<u8> {
        self.inner.pop_packet().unwrap_or_default()
    }

    pub fn pop_packet_wait(&self, timeout_ms: u32) -> Vec<u8> {
        self.inner.pop_packet_wait(timeout_ms).unwrap_or_default()
    }

    pub fn ping_many(&self, ids: Vec<String>) -> Vec<DelayView> {
        self.inner.ping_many(&ids).into_iter().map(|(id, delay)| DelayView { id, delay_ms: delay.map(|ms| ms as i64).unwrap_or(MISSING_DELAY_MS) }).collect()
    }

    pub fn cancel_ping(&self) {
        self.inner.cancel_ping();
    }

    pub fn subscriptions(&self) -> Result<Vec<SubscriptionView>, VpnError> {
        Ok(self.inner.subscriptions().map_err(map_err)?.into_iter().map(|sub| SubscriptionView {
            id: sub.id,
            name: sub.name,
            url: sub.url.unwrap_or_default(),
        }).collect())
    }

    pub fn groups(&self) -> Result<Vec<GroupView>, VpnError> {
        Ok(self.inner.groups().map_err(map_err)?.into_iter().map(|group| GroupView {
            id: group.id,
            name: group.name,
            members: group.members,
        }).collect())
    }

    pub fn per_app_mode(&self) -> String {
        self.inner.per_app().0
    }

    pub fn per_app_list(&self) -> Vec<String> {
        self.inner.per_app().1
    }

    pub fn block_bind_to_tunnel(&self) -> bool {
        self.inner.per_app().2
    }

    pub fn tunnel_mtu(&self) -> u16 {
        self.inner.tunnel_prefs().0
    }

    pub fn include_all_networks(&self) -> bool {
        self.inner.tunnel_prefs().1
    }

    pub fn exclude_local_networks(&self) -> bool {
        self.inner.tunnel_prefs().2
    }

    pub fn exclude_apns(&self) -> bool {
        self.inner.tunnel_prefs().3
    }

    pub fn hide_vpn_icon(&self) -> bool {
        self.inner.tunnel_prefs().4
    }

    pub fn put_aes_key(&self, key_id: String, key: String) -> Result<(), VpnError> {
        self.inner.put_aes_key(&key_id, &key).map_err(map_err)
    }

    pub fn autoconnect(&self) -> Result<(), VpnError> {
        self.inner.autoconnect().map_err(map_err)
    }
}

fn map_err(err: rvpn_app::AppError) -> VpnError {
    VpnError::Core { message: err.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_vless_without_starting_xray() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/ffi-test");
        let _ = std::fs::remove_dir_all(&dir);
        let core = VpnCore::new(dir.display().to_string()).unwrap();
        core.import_text("vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#Example".into()).unwrap();
        let servers = core.servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(core.subscriptions().unwrap().iter().any(|sub| sub.id == "local"), true);
        assert!(core.groups().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stage_session_and_prepare_bridge_take_one_ipv4_packet_without_tun_or_xray() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/ffi-bridge-test");
        let _ = std::fs::remove_dir_all(&dir);
        let core = VpnCore::new(dir.display().to_string()).unwrap();
        core.import_text("vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#Example".into()).unwrap();
        let server_id = core.servers().unwrap().into_iter().next().expect("imported server").id;
        core.stage_session(server_id).unwrap();
        core.prepare_bridge();
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        let total = u16::try_from(packet.len()).unwrap().to_be_bytes();
        packet[2] = total[0];
        packet[3] = total[1];
        core.push_packet(packet).unwrap();
        assert!(core.pop_packet().is_empty());
        drop(core);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
