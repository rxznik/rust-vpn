use super::{AppError, Client, Live, Reap, ReapReason, Status};
use rvpn_model::{
    CoreSettings, Protocol, Security, Server, SubscriptionMeta, LOCAL_SUBSCRIPTION_ID,
};
use rvpn_platform::ProxyEndpoint;
use rvpn_routing::xray_routing;
use rvpn_subscription::resolve_ipv4;
use rvpn_tun::{local_bypasses, start, start_bridge, BridgeParts, PacketPump, TunOptions};
use rvpn_xray::{compile, prepare_passthrough, CompileRequest, SpawnSpec, StatsPoller};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use super::policy::{effective_packet_tweaks, ensure_auth, overlay_settings, pick_server};

impl Client {
    pub fn connect(&self, server_id: &str) -> Result<(), AppError> {
        let _session_lock = self.session_guard();
        self.connect_locked(server_id)
    }

    fn connect_locked(&self, server_id: &str) -> Result<(), AppError> {
        if !self.xray.is_file() {
            return Err(AppError::new("xray binary not found; run scripts/fetch_xray.py"));
        }
        let store = self.db();
        let server = store.get_server(server_id)?;
        let sub_id = server.subscription_id.clone().unwrap_or_else(|| LOCAL_SUBSCRIPTION_ID.into());
        drop(store);
        self.db().commit_routing(&sub_id)?;
        let (mut server, sub, mut settings) = {
            let store = self.db();
            let server = store.get_server(server_id)?;
            let sub = store.get_subscription(&sub_id)?;
            let settings = store.settings()?;
            (server, sub, settings)
        };
        let mut session = settings.clone();
        overlay_settings(&mut session, &sub.meta);
        ensure_auth(&mut session);
        let original = server.address.clone();
        if sub.meta.resolve_enable && server.address.parse::<std::net::IpAddr>().is_err() {
            let resolver = sub.meta.resolve_dns_domain.clone().or(sub.meta.resolve_dns_ip.clone()).unwrap_or_else(|| "https://dns.google/resolve".into());
            if let Ok(ip) = resolve_ipv4(&resolver, &server.address) {
                pin_sni(&mut server, &original);
                server.address = ip;
            }
        }
        let profile = sub.applied_profile_id.as_ref().and_then(|id| self.db().get_profile(id).ok());
        let enabled = sub.applied_routing_enabled && sub.meta.routing_enabled;
        let (routing, dns) = match &profile {
            Some(profile) => {
                let (routing, dns) = xray_routing(profile, enabled);
                (Some(routing), dns)
            }
            None => (None, None),
        };
        let asset_dir = profile.as_ref().and_then(rvpn_routing::asset_dir);
        let (fragment, noise) = effective_packet_tweaks(&session, &server, &sub.meta);
        let work = self.data_dir.join("runtime");
        let config = match &server.protocol {
            Protocol::Json { raw } => prepare_passthrough(raw, dns.as_ref(), sub.meta.dns_from_json, &work).map_err(|e| AppError::new(e.to_string()))?,
            _ => serde_json::to_string(&compile(&CompileRequest {
                server: &server,
                settings: &session,
                fragment: fragment.as_ref(),
                noise: noise.as_ref(),
                routing,
                dns,
            })).map_err(|e| AppError::new(e.to_string()))?,
        };
        self.disconnect_locked()?;
        if matches!(&server.protocol, Protocol::Hysteria2 { insecure: true, .. }) {
            self.xray_proc().push_log("Узел Hysteria2 просит отключить проверку сертификата. Проверка остаётся включённой.");
        }
        let config_path = work.join("xray.json");
        if let Err(err) = self.xray_proc().start(&SpawnSpec {
            binary: self.xray.clone(),
            args: vec!["run".into(), "-c".into(), config_path.display().to_string()],
            config_json: config,
            work_dir: work,
            asset_dir,
        }) {
            self.release_tun_fd();
            return Err(err.into());
        }
        let socks = SocketAddr::from(([127, 0, 0, 1], session.socks_port));
        let mut ready = false;
        let mut failure = String::from("локальный прокси не запустился");
        for attempt in 0..25 {
            match rvpn_probe::tunnel_ready(socks, &session.check_url, &session.socks_user, &session.socks_password, Duration::from_secs(12)) {
                Ok(()) => {
                    ready = true;
                    break;
                }
                Err(err) if err.socks_down() && attempt < 24 => std::thread::sleep(Duration::from_millis(40)),
                Err(err) => {
                    failure = err.to_string();
                    break;
                }
            }
        }
        if !ready {
            let _ = self.disconnect_locked();
            self.release_tun_fd();
            return Err(AppError::new(format!("Туннель не открылся: {failure}")));
        }
        if session.proxy_enable {
            if let Err(err) = self.apply_proxy(&session) {
                let _ = self.disconnect_locked();
                self.release_tun_fd();
                return Err(err);
            }
        }
        let fd_ready = self.tun_fd.load(Ordering::SeqCst) >= 0;
        if session.tun_enable || fd_ready {
            if let Err(err) = self.apply_tun(&session, &sub.meta) {
                self.tun_fd.store(-1, Ordering::SeqCst);
                let _ = self.disconnect_locked();
                return Err(err);
            }
        } else {
            self.release_tun_fd();
        }
        settings.last_server_id = Some(server_id.to_string());
        self.db().save_settings(&settings)?;
        self.start_stats(session.api_port);
        let live = Arc::new(live_from(&server, &session, &sub.meta));
        *self.planned_slot() = Some(Arc::clone(&live));
        *self.session() = Some(live);
        Ok(())
    }

    pub fn stage_session(&self, server_id: &str) -> Result<(), AppError> {
        let live = self.plan_for(server_id)?;
        *self.planned_slot() = Some(live);
        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), AppError> {
        let _session_lock = self.session_guard();
        self.disconnect_locked()
    }

    /// Снимает сессию, если ядро уже вышло или мост TUN сообщил ошибку.
    /// Занятый `session_lock` не ждётся: метод возвращает [`Reap::Busy`].
    pub fn reap_dead_session(&self) -> Reap {
        let _session_lock = match self.session_lock.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Reap::Busy,
            Err(std::sync::TryLockError::Poisoned(err)) => err.into_inner(),
        };
        if self.session().is_none() {
            return Reap::Unchanged;
        }
        let running = self.xray_proc().is_running();
        let tun_error = self.tun_slot().as_ref().and_then(rvpn_tun::TunHandle::take_error);
        let reason = if let Some(text) = tun_error {
            ReapReason::Tun(text)
        } else if !running {
            ReapReason::CoreStopped
        } else {
            return Reap::Unchanged;
        };
        let _ = self.disconnect_locked();
        Reap::Done(reason)
    }

    pub(super) fn disconnect_locked(&self) -> Result<(), AppError> {
        if let Some(mut tun) = self.tun_slot().take() {
            tun.stop();
        }
        let _ = self.apply_proxy_off();
        self.xray_proc().stop()?;
        self.stop_stats();
        *self.session() = None;
        *self.planned_slot() = None;
        Ok(())
    }

    pub fn status(&self) -> Status {
        let live = self.session().as_ref().map(Arc::clone);
        let Some(live) = live else {
            return Status::default();
        };
        let stats = self.stats.lock().unwrap_or_else(|err| err.into_inner()).as_ref().and_then(StatsPoller::snapshot);
        Status {
            connected: self.xray_proc().is_running(),
            server_id: Some(live.server_id.clone()),
            server_name: Some(live.server_name.clone()),
            upload: stats.map(|item| item.uplink).unwrap_or(0),
            download: stats.map(|item| item.downlink).unwrap_or(0),
            stats_known: stats.is_some(),
            message: None,
        }
    }

    pub fn recent_log(&self) -> Vec<std::sync::Arc<str>> {
        self.xray_proc().recent_log()
    }

    pub fn autoconnect(&self) -> Result<(), AppError> {
        let settings = self.settings()?;
        let subs = self.subscriptions()?;
        let preferred = subs.iter().find(|s| s.meta.autoconnect).or_else(|| settings.autoconnect.then(|| subs.first()).flatten());
        let Some(sub) = preferred else {
            return Ok(());
        };
        let kind = if sub.meta.autoconnect { sub.meta.autoconnect_type } else { settings.autoconnect_type };
        let servers = self.db().list_summaries(Some(&sub.id))?;
        let Some(server) = pick_server(&servers, kind, settings.last_server_id.as_deref()) else {
            return Ok(());
        };
        let id = server.id.clone();
        drop(servers);
        self.connect(&id)
    }

    pub fn set_tun_fd(&self, fd: i32) {
        self.tun_fd.store(fd, Ordering::SeqCst);
    }

    pub fn prepare_bridge(&self) -> Arc<PacketPump> {
        let parts = BridgeParts::create();
        let pump = parts.pump.clone();
        *self.bridge_slot() = Some(parts);
        *self.pump_slot() = Some(pump.clone());
        pump
    }

    pub fn push_packet(&self, packet: Vec<u8>) -> Result<(), AppError> {
        let pump = self.pump_slot();
        let Some(pump) = pump.as_ref() else {
            return Err(AppError::new("packet bridge is not running"));
        };
        pump.push_from_os(packet)?;
        Ok(())
    }

    pub fn pop_packet(&self) -> Option<Vec<u8>> {
        self.pump_slot().as_ref().and_then(|pump| pump.pop_to_os())
    }

    pub fn pop_packet_wait(&self, timeout_ms: u32) -> Option<Vec<u8>> {
        let timeout = Duration::from_millis(u64::from(timeout_ms));
        self.pump_slot().as_ref().and_then(|pump| pump.pop_to_os_wait(timeout))
    }

    pub fn per_app(&self) -> (String, Vec<String>, bool) {
        let Some(live) = self.current_plan() else {
            return ("off".into(), Vec::new(), false);
        };
        (live.per_app_mode.as_str().into(), live.per_app_list.clone(), live.block_bind)
    }

    pub fn tunnel_prefs(&self) -> (u16, bool, bool, bool, bool) {
        let Some(live) = self.current_plan() else {
            return (1500, false, true, true, false);
        };
        (live.mtu, live.include_all_networks, live.exclude_local_networks, live.exclude_apns, live.hide_vpn_icon)
    }

    fn apply_proxy(&self, settings: &CoreSettings) -> Result<(), AppError> {
        let socks = ProxyEndpoint { host: "127.0.0.1".into(), port: settings.socks_port };
        let http = settings.http_enabled.then(|| ProxyEndpoint { host: "127.0.0.1".into(), port: settings.http_port });
        self.platform.set_system_proxy(http.as_ref(), Some(&socks))?;
        self.proxy_applied.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn apply_proxy_off(&self) -> Result<(), AppError> {
        if !self.proxy_applied.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.platform.set_system_proxy(None, None)?;
        self.proxy_applied.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn apply_tun(&self, settings: &CoreSettings, meta: &SubscriptionMeta) -> Result<(), AppError> {
        let mut bypass = settings.exclude_routes.clone();
        if meta.exclude_local_networks.unwrap_or(true) {
            bypass.extend(local_bypasses());
        }
        let fd = self.tun_fd.load(Ordering::SeqCst);
        let options = TunOptions {
            socks: SocketAddr::from(([127, 0, 0, 1], settings.socks_port)),
            username: settings.socks_user.clone(),
            password: settings.socks_password.clone(),
            mtu: settings.tun_mtu,
            bypass,
            tun_fd: (fd >= 0).then_some(fd),
            setup_routes: fd < 0,
            dns: "1.1.1.1".into(),
        };
        let handle = if let Some(parts) = self.bridge_slot().take() {
            start_bridge(options, parts)?
        } else {
            start(options)?
        };
        *self.tun_slot() = Some(handle);
        if fd >= 0 {
            self.tun_fd.store(-1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn plan_for(&self, server_id: &str) -> Result<Arc<Live>, AppError> {
        let store = self.db();
        let server = store.get_server(server_id)?;
        let sub_id = server.subscription_id.clone().unwrap_or_else(|| LOCAL_SUBSCRIPTION_ID.into());
        let sub = store.get_subscription(&sub_id)?;
        let mut settings = store.settings()?;
        drop(store);
        overlay_settings(&mut settings, &sub.meta);
        Ok(Arc::new(live_from(&server, &settings, &sub.meta)))
    }

    fn current_plan(&self) -> Option<Arc<Live>> {
        self.session().as_ref().map(Arc::clone).or_else(|| self.planned_slot().as_ref().map(Arc::clone))
    }

    fn release_tun_fd(&self) {
        let fd = self.tun_fd.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            close_fd(fd);
        }
    }
}

fn live_from(server: &Server, settings: &CoreSettings, meta: &SubscriptionMeta) -> Live {
    Live {
        server_id: server.id.clone(),
        server_name: server.name.clone(),
        socks_port: settings.socks_port,
        socks_user: settings.socks_user.clone(),
        socks_password: settings.socks_password.clone(),
        block_bind: meta.block_bind_to_tunnel,
        per_app_mode: settings.per_app_mode,
        per_app_list: settings.per_app_list.clone(),
        hide_vpn_icon: meta.hide_vpn_icon,
        include_all_networks: meta.include_all_networks.unwrap_or(true),
        exclude_local_networks: meta.exclude_local_networks.unwrap_or(true),
        exclude_apns: meta.exclude_apns.unwrap_or(true),
        mtu: settings.tun_mtu,
    }
}

pub(crate) fn remove_inside(root: &Path, path: &Path) {
    let Ok(root) = root.canonicalize() else {
        return;
    };
    let Ok(path) = path.canonicalize() else {
        return;
    };
    if path.starts_with(&root) {
        let _ = std::fs::remove_file(path);
    }
}

fn close_fd(fd: i32) {
    #[cfg(unix)]
    unsafe {
        use std::os::unix::io::FromRawFd;
        drop(std::fs::File::from_raw_fd(fd));
    }
    #[cfg(not(unix))]
    let _ = fd;
}

fn pin_sni(server: &mut Server, original: &str) {
    match &mut server.protocol {
        Protocol::Vless { security, .. } => match security {
            Security::Tls(tls) if tls.sni.as_deref().unwrap_or("").is_empty() => tls.sni = Some(original.into()),
            Security::Reality(reality) if reality.server_name.is_empty() => reality.server_name = original.into(),
            _ => {}
        },
        Protocol::Vmess { tls, .. } => {
            if let Some(tls) = tls {
                if tls.sni.as_deref().unwrap_or("").is_empty() {
                    tls.sni = Some(original.into());
                }
            }
        }
        Protocol::Trojan { tls, .. } => {
            if tls.sni.as_deref().unwrap_or("").is_empty() {
                tls.sni = Some(original.into());
            }
        }
        Protocol::Hysteria2 { sni, .. } if sni.is_none() => *sni = Some(original.into()),
        _ => {}
    }
}
