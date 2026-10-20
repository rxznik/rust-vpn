//! Сессия: подписки, Xray, маршрут, пинг и туннель.
//!
//! `connect` коммитит черновик маршрута, пишет конфиг и ждёт локальный SOCKS.
//! Inbound остаётся на 127.0.0.1. Прокси ОС указывает на этот адрес.
//! `session_lock` — внешний замок: его держат `connect`, `disconnect` и обновление, которое заменяет серверы.
//! Замок базы берётся после него и только на короткий вызов.
//! `ping` и `ping_many` `session_lock` не берут. Чтение списка тоже остаётся снаружи.
//! `reap_dead_session` берёт тот же замок через `try_lock` и сразу возвращает [`Reap::Busy`], если замок занят.
//! `set_stats_wanted` разрешает фоновый `statsquery`. Пока флаг выключен, поток спит и не запускает процесс.
//! `stage_session` заполняет план для VpnService до установления TUN.
//! Пинг пачки идёт потоками std. Ширина пачки — число ядер, не больше 16.
//! Задержки пишутся одним проходом. `cancel_ping` обрывает хвост пачки.
//! Заголовки обновления: user-agent, x-hwid, x-device-os, x-ver-os, x-device-model.
//! `overlay_settings` копирует из меты только поля, которые мета задаёт:
//! proxy, tun, sniffing, inbound http, socks/http auth, per-app, exclude routes,
//! no-limit, mux, ping, check url, fragment, noise, autostart.

use rand::RngCore;
use rvpn_model::{PerAppMode, PingStyle, ServerSummary, Subscription, LOCAL_SUBSCRIPTION_ID};
use rvpn_platform::Platform;
use rvpn_routing::RoutingError;
use rvpn_store::Store;
use rvpn_subscription::SubError;
use rvpn_tun::{BridgeParts, PacketPump, TunHandle};
use rvpn_xray::{locate_binary, StatsPoller, Supervisor};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Session error. [`Display`] is the text shown in the UI and in `VpnError`.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Subscription(#[from] SubError),
    #[error(transparent)]
    Store(#[from] rvpn_store::StoreError),
    #[error(transparent)]
    Routing(#[from] RoutingError),
    #[error(transparent)]
    Process(#[from] rvpn_xray::ProcessError),
    #[error(transparent)]
    Tun(#[from] rvpn_tun::TunError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Platform(#[from] rvpn_platform::PlatformError),
}

impl AppError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub connected: bool,
    pub server_id: Option<String>,
    pub server_name: Option<String>,
    pub upload: u64,
    pub download: u64,
    pub stats_known: bool,
    pub message: Option<String>,
}

/// Причина, по которой [`Client::reap_dead_session`] снял живую сессию.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapReason {
    /// Процесс Xray уже не запущен.
    CoreStopped,
    /// Мост TUN вернул эту строку.
    Tun(String),
}

/// Итог неблокирующей проверки сессии.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reap {
    /// `session_lock` занят подключением, отключением или обновлением.
    Busy,
    /// Сессии нет, либо ядро и TUN ещё живы.
    Unchanged,
    /// Сессия снята: TUN остановлен, прокси возвращён, статистика погашена.
    Done(ReapReason),
}

#[derive(Debug, Clone)]
pub struct ServerRow {
    pub id: String,
    pub subscription_id: String,
    pub name: String,
    pub subtitle: String,
    pub delay: String,
    pub endpoint: String,
}

#[derive(Clone)]
struct Live {
    server_id: String,
    server_name: String,
    socks_port: u16,
    socks_user: String,
    socks_password: String,
    block_bind: bool,
    per_app_mode: PerAppMode,
    per_app_list: Vec<String>,
    hide_vpn_icon: bool,
    include_all_networks: bool,
    exclude_local_networks: bool,
    exclude_apns: bool,
    mtu: u16,
}

pub struct Client {
    store: Mutex<Store>,
    platform: Arc<dyn Platform>,
    supervisor: Mutex<Supervisor>,
    tun: Mutex<Option<TunHandle>>,
    bridge: Mutex<Option<BridgeParts>>,
    pump: Mutex<Option<Arc<PacketPump>>>,
    data_dir: PathBuf,
    xray: PathBuf,
    live: Mutex<Option<Arc<Live>>>,
    planned: Mutex<Option<Arc<Live>>>,
    tun_fd: AtomicI32,
    ping_epoch: AtomicU64,
    proxy_applied: AtomicBool,
    shut: AtomicBool,
    server_cache: Mutex<Option<(u64, Arc<Vec<ServerSummary>>)>>,
    stats: Mutex<Option<StatsPoller>>,
    /// Пока false, [`StatsPoller`] спит и не вызывает `xray api statsquery`.
    stats_wanted: Arc<AtomicBool>,
    /// Внешний замок: connect, disconnect и замена серверов подписки.
    session_lock: Mutex<()>,
    #[cfg(test)]
    session_waiters: std::sync::atomic::AtomicUsize,
}

mod groups;
mod import;
mod ping;
mod policy;
mod session;

pub use policy::{announcement_text, pick_server};

impl Client {
    pub fn open(data_dir: PathBuf, platform: Arc<dyn Platform>) -> Result<Self, AppError> {
        std::fs::create_dir_all(&data_dir)?;
        restrict_dir(&data_dir);
        let store = Store::open(&data_dir.join("state.db"))?;
        let xray = locate_binary().unwrap_or_else(|| data_dir.join("xray"));
        let client = Self {
            store: Mutex::new(store),
            platform,
            supervisor: Mutex::new(Supervisor::new()),
            tun: Mutex::new(None),
            bridge: Mutex::new(None),
            pump: Mutex::new(None),
            data_dir,
            xray,
            live: Mutex::new(None),
            planned: Mutex::new(None),
            tun_fd: AtomicI32::new(-1),
            ping_epoch: AtomicU64::new(0),
            proxy_applied: AtomicBool::new(false),
            shut: AtomicBool::new(false),
            server_cache: Mutex::new(None),
            stats: Mutex::new(None),
            stats_wanted: Arc::new(AtomicBool::new(false)),
            session_lock: Mutex::new(()),
            #[cfg(test)]
            session_waiters: std::sync::atomic::AtomicUsize::new(0),
        };
        let _ = client.platform.restore_captured_proxy();
        Ok(client)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn hwid(&self) -> String {
        self.platform.device_hwid()
    }

    pub fn shutdown(&self) {
        if self.shut.swap(true, Ordering::SeqCst) {
            return;
        }
        self.cancel_ping();
        let _session_lock = self.session_guard();
        let _ = self.disconnect_locked();
        // disconnect пропускает снимок, если прокси не отмечен применённым.
        let _ = self.platform.restore_captured_proxy();
    }

    pub fn subscriptions(&self) -> Result<Vec<Subscription>, AppError> {
        let mut list = self.db().list_subscriptions()?;
        list.sort_by(|a, b| {
            b.meta
                .pinned
                .cmp(&a.meta.pinned)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(list)
    }

    pub fn servers(&self, subscription_id: Option<&str>) -> Result<Vec<ServerRow>, AppError> {
        let store = self.db();
        let subs = store.list_subscriptions()?;
        let settings_sort = store
            .settings()
            .map(|settings| settings.sort_type)
            .unwrap_or_default();
        drop(store);
        let servers = self.cached_summaries()?;
        let styles: HashMap<&str, PingStyle> = subs
            .iter()
            .map(|sub| {
                (
                    sub.id.as_str(),
                    sub.meta.ping_result.unwrap_or(PingStyle::Time),
                )
            })
            .collect();
        let mut rows = Vec::new();
        for server in servers.iter().filter(|server| {
            subscription_id.is_none_or(|id| server.subscription_id.as_deref() == Some(id))
        }) {
            let sub_id = server
                .subscription_id
                .clone()
                .unwrap_or_else(|| LOCAL_SUBSCRIPTION_ID.into());
            let style = styles
                .get(sub_id.as_str())
                .copied()
                .unwrap_or(PingStyle::Time);
            rows.push((
                server.delay_ms,
                ServerRow {
                    id: server.id.clone(),
                    subscription_id: sub_id,
                    name: server.name.clone(),
                    subtitle: server.subtitle.clone(),
                    delay: ping::format_delay(server.delay_ms, style),
                    endpoint: format!("{}:{}", server.address, server.port),
                },
            ));
        }
        let sort = if let Some(sub_id) = subscription_id {
            subs.iter()
                .find(|s| s.id == sub_id)
                .map(|s| s.meta.sort_type)
                .unwrap_or_default()
        } else {
            settings_sort
        };
        ping::sort_rows(&mut rows, sort);
        Ok(rows.into_iter().map(|(_, row)| row).collect())
    }

    fn cached_summaries(&self) -> Result<Arc<Vec<ServerSummary>>, AppError> {
        let generation = self.db().generation();
        if let Some((cached, servers)) = self
            .server_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .as_ref()
        {
            if *cached == generation {
                return Ok(Arc::clone(servers));
            }
        }
        let store = self.db();
        let servers = Arc::new(store.list_summaries(None)?);
        let generation = store.generation();
        drop(store);
        *self
            .server_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Some((generation, Arc::clone(&servers)));
        Ok(servers)
    }

    fn start_stats(&self, api_port: u16) {
        *self.stats.lock().unwrap_or_else(|err| err.into_inner()) = Some(StatsPoller::spawn(
            self.xray.clone(),
            api_port,
            Arc::clone(&self.stats_wanted),
        ));
    }

    /// Разрешает или запрещает фоновый `statsquery`. По умолчанию запрещён, пока окно не выставит флаг.
    pub fn set_stats_wanted(&self, wanted: bool) {
        self.stats_wanted.store(wanted, Ordering::Relaxed);
    }

    fn stop_stats(&self) {
        *self.stats.lock().unwrap_or_else(|err| err.into_inner()) = None;
    }

    fn db(&self) -> MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn xray_proc(&self) -> MutexGuard<'_, Supervisor> {
        self.supervisor
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn session(&self) -> MutexGuard<'_, Option<Arc<Live>>> {
        self.live.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn planned_slot(&self) -> MutexGuard<'_, Option<Arc<Live>>> {
        self.planned.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn tun_slot(&self) -> MutexGuard<'_, Option<TunHandle>> {
        self.tun.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn bridge_slot(&self) -> MutexGuard<'_, Option<BridgeParts>> {
        self.bridge.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn pump_slot(&self) -> MutexGuard<'_, Option<Arc<PacketPump>>> {
        self.pump.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn session_guard(&self) -> MutexGuard<'_, ()> {
        #[cfg(test)]
        self.session_waiters.fetch_add(1, Ordering::SeqCst);
        let guard = self
            .session_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        #[cfg(test)]
        self.session_waiters.fetch_sub(1, Ordering::SeqCst);
        guard
    }

    /// Держит замок сессии, пока `body` не вернётся.
    #[cfg(test)]
    fn hold_session<R>(&self, body: impl FnOnce() -> R) -> R {
        let _session_lock = self.session_guard();
        body()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn restrict_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn token() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::ping::sort_rows;
    use super::policy::{effective_packet_tweaks, ensure_auth};
    use super::*;
    use base64::Engine;
    use rvpn_model::{
        AuthMode, AutoConnectType, CoreSettings, Fragment, PerAppMode, PingType, Protocol, Server,
        SortType, SubscriptionMeta, UserInfo,
    };
    use rvpn_platform::HostPlatform;
    use std::sync::atomic::Ordering;

    fn client() -> Client {
        let name = token();
        let dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../.tmp/app-test-{name}"));
        Client::open(
            dir,
            Arc::new(HostPlatform::new(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../../.tmp/app-hwid-{name}")),
            )),
        )
        .unwrap()
    }

    #[test]
    fn import_link_and_reject_foreign_hwid() {
        let client = client();
        let id = client.import_text("vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#Example").unwrap();
        assert_eq!(id, LOCAL_SUBSCRIPTION_ID);
        assert_eq!(
            client.servers(Some(LOCAL_SUBSCRIPTION_ID)).unwrap().len(),
            1
        );
        let err = client
            .import_text("https://example.invalid/sub?hwid=deadbeef")
            .unwrap_err();
        assert!(err.to_string().contains("another device"));
    }

    #[test]
    fn routing_stays_draft_until_commit() {
        let client = client();
        let body = base64::engine::general_purpose::STANDARD
            .encode(br#"{"Name":"draft","GlobalProxy":"false","DirectSites":["example.com"]}"#);
        client
            .import_text(&format!("happ://routing/onadd/{body}"))
            .unwrap();
        let sub = client
            .subscriptions()
            .unwrap()
            .into_iter()
            .find(|s| s.id == LOCAL_SUBSCRIPTION_ID)
            .unwrap();
        assert_eq!(sub.draft_profile_id.is_some(), true);
        assert!(sub.applied_profile_id.is_none());
        client
            .store
            .lock()
            .unwrap()
            .commit_routing(LOCAL_SUBSCRIPTION_ID)
            .unwrap();
        let sub = client
            .store
            .lock()
            .unwrap()
            .get_subscription(LOCAL_SUBSCRIPTION_ID)
            .unwrap();
        assert_eq!(sub.applied_profile_id, sub.draft_profile_id);
    }

    #[test]
    fn ping_sort_orders_by_milliseconds() {
        let row = |name: &str| ServerRow {
            id: name.into(),
            subscription_id: "s".into(),
            name: name.into(),
            subtitle: String::new(),
            delay: String::new(),
            endpoint: String::new(),
        };
        let mut rows = vec![
            (Some(200), row("slow")),
            (None, row("none")),
            (Some(20), row("fast")),
            (Some(20), row("also")),
        ];
        sort_rows(&mut rows, SortType::Ping);
        let names: Vec<_> = rows.iter().map(|(_, item)| item.name.as_str()).collect();
        assert_eq!(names, ["also", "fast", "slow", "none"]);
    }

    #[test]
    fn autoconnect_prefers_lowest_delay() {
        let mut servers = vec![
            sample("a", Some(80)),
            sample("b", Some(20)),
            sample("c", None),
        ];
        let picked = pick_server(&servers, AutoConnectType::LowestDelay, None).unwrap();
        assert_eq!(picked.id, "b");
        servers[0].id = "last".into();
        let picked = pick_server(&servers, AutoConnectType::LastUsed, Some("last")).unwrap();
        assert_eq!(picked.id, "last");
    }

    #[test]
    fn expire_announcement_wins_over_info() {
        let mut sub = Subscription::local(0);
        sub.meta.sub_expire = true;
        sub.meta.sub_info_text = Some("hello".into());
        sub.userinfo = Some(UserInfo {
            upload: 0,
            download: 0,
            total: 0,
            expire: Some(86_400),
        });
        let text = announcement_text(&sub, 0).unwrap();
        assert!(text.contains("expires"));
    }

    #[test]
    fn stage_session_reads_meta_before_connect() {
        let client = client();
        client.import_text("vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#Example").unwrap();
        let row = client.servers(None).unwrap().remove(0);
        let mut sub = client.db().get_subscription(&row.subscription_id).unwrap();
        sub.meta.include_all_networks = Some(true);
        sub.meta.per_app_mode = Some(PerAppMode::On);
        sub.meta.per_app_list = vec!["com.example".into()];
        sub.meta.tun_enable = Some(true);
        client.db().upsert_subscription(&sub).unwrap();
        let before = client.settings().unwrap();
        client.stage_session(&row.id).unwrap();
        let (mode, list, _) = client.per_app();
        assert_eq!(mode, "on");
        assert_eq!(list, vec!["com.example".to_string()]);
        assert!(client.tunnel_prefs().1);
        assert!(!client.settings().unwrap().tun_enable);
        assert_eq!(before.proxy_enable, client.settings().unwrap().proxy_enable);
    }

    #[test]
    fn system_proxy_does_not_invent_a_password() {
        let mut settings = CoreSettings::default();
        assert!(settings.proxy_enable);
        ensure_auth(&mut settings);
        assert_eq!(settings.socks_auth_mode, AuthMode::Disable);
        assert!(settings.socks_user.is_empty());
        settings.proxy_enable = false;
        settings.socks_auth_mode = AuthMode::Auto;
        ensure_auth(&mut settings);
        assert!(!settings.socks_user.is_empty());
        assert!(!settings.socks_password.is_empty());
    }

    #[test]
    fn global_fragment_overrides_the_link() {
        let mut settings = CoreSettings::default();
        settings.fragmentation_enable = true;
        settings.fragmentation.length = "9-9".into();
        let mut server = sample("s", None);
        server.fragment = Some(Fragment {
            length: "1-1".into(),
            interval: "1".into(),
            packets: "tlshello".into(),
            max_split: None,
        });
        let (fragment, _) =
            effective_packet_tweaks(&settings, &server, &SubscriptionMeta::default());
        assert_eq!(fragment.unwrap().length, "9-9");
        settings.fragmentation_enable = false;
        let (fragment, _) =
            effective_packet_tweaks(&settings, &server, &SubscriptionMeta::default());
        assert_eq!(fragment.unwrap().length, "1-1");
    }

    #[test]
    fn group_collects_two_subscriptions_and_refresh_drops_a_member() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/app-groups");
        let _ = std::fs::remove_dir_all(&dir);
        let client = Client::open(
            dir,
            Arc::new(HostPlatform::new(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/app-groups-hwid"),
            )),
        )
        .unwrap();
        let mut first = Subscription::local(1);
        first.id = "alpha".into();
        first.name = "Alpha".into();
        let mut second = Subscription::local(1);
        second.id = "beta".into();
        second.name = "Beta".into();
        client.db().upsert_subscription(&first).unwrap();
        client.db().upsert_subscription(&second).unwrap();
        let mut left = sample("left", Some(40));
        left.subscription_id = Some("alpha".into());
        let mut fast = sample("fast", Some(10));
        fast.subscription_id = Some("beta".into());
        let mut slow = sample("slow", Some(90));
        slow.subscription_id = Some("beta".into());
        let mut quiet = sample("quiet", None);
        quiet.subscription_id = Some("beta".into());
        client.db().upsert_server(&left).unwrap();
        client.db().upsert_server(&fast).unwrap();
        client.db().upsert_server(&slow).unwrap();
        client.db().upsert_server(&quiet).unwrap();
        let seen = client.servers(Some("alpha")).unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].subscription_id, "alpha");
        let group = client.create_group("Дом").unwrap();
        client.add_group_member(&group, "left").unwrap();
        client.add_group_member(&group, "fast").unwrap();
        let mut ids: Vec<_> = client
            .group_servers(&group)
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        ids.sort();
        assert_eq!(ids, vec!["fast".to_string(), "left".to_string()]);
        assert_eq!(
            client
                .lowest_delay_id(&["left".into(), "slow".into()])
                .unwrap()
                .as_deref(),
            Some("left")
        );
        assert_eq!(
            client
                .lowest_delay_id(&["quiet".into(), "slow".into()])
                .unwrap()
                .as_deref(),
            Some("slow")
        );
        assert_eq!(client.fastest_server_id().unwrap().as_deref(), Some("fast"));
        client
            .db()
            .replace_servers("beta", &[slow.clone(), quiet.clone()])
            .unwrap();
        assert_eq!(
            client
                .group_servers(&group)
                .unwrap()
                .into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec!["left".to_string()]
        );
        client.add_group_member(&group, "slow").unwrap();
        client.remove_group_member(&group, "slow").unwrap();
        assert_eq!(
            client
                .group_servers(&group)
                .unwrap()
                .into_iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec!["left".to_string()]
        );
        assert!(client
            .servers(Some("alpha"))
            .unwrap()
            .iter()
            .any(|row| row.id == "left"));
        let err = client.create_group("   ").unwrap_err();
        assert!(err.to_string().contains("80"));
        let err = client.create_group("дом").unwrap_err();
        assert!(err.to_string().contains("уже есть"));
        client.rename_group(&group, "Дом").unwrap();
        let other = client.create_group("Работа").unwrap();
        let err = client.rename_group(&other, "дом").unwrap_err();
        assert!(err.to_string().contains("уже есть"));
        client.delete_group(&group).unwrap();
        assert_eq!(
            client
                .servers(None)
                .unwrap()
                .iter()
                .filter(|row| row.id == "left")
                .count(),
            1
        );
    }

    fn sample(id: &str, delay: Option<u32>) -> Server {
        Server {
            id: id.into(),
            subscription_id: None,
            name: id.into(),
            address: "203.0.113.10".into(),
            port: 443,
            protocol: Protocol::Socks {
                username: None,
                password: None,
            },
            description: None,
            fragment: None,
            noise: None,
            raw_link: None,
            delay_ms: delay,
        }
    }

    #[test]
    fn connect_without_binary_names_the_script() {
        let mut client = client();
        client.xray = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/missing-xray-bin");
        let err = client.connect("absent").unwrap_err();
        assert!(err.to_string().contains("xray binary not found"));
    }

    #[test]
    fn proxy_ping_without_a_session_is_an_error() {
        let client = client();
        client.import_text("vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#Example").unwrap();
        let id = client.servers(None).unwrap().remove(0).id;
        let mut settings = client.settings().unwrap();
        settings.ping_type = PingType::Proxy;
        client.save_settings(&settings).unwrap();
        let err = client.ping(&id).unwrap_err();
        assert!(err.to_string().contains("proxy ping"));
    }

    #[test]
    fn bad_routing_link_keeps_the_imported_server() {
        let client = client();
        let text = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=none#Example\nhapp://routing/nope\n";
        let err = client.import_text(text).unwrap_err();
        assert!(err.to_string().contains("routing"));
        assert_eq!(
            client.servers(Some(LOCAL_SUBSCRIPTION_ID)).unwrap().len(),
            1
        );
    }

    #[test]
    fn refresh_due_skips_a_subscription_that_is_not_due() {
        let client = client();
        client.refresh_due(false).unwrap();
    }

    #[test]
    fn second_refresh_due_waits_for_the_session_lock() {
        let client = Arc::new(client());
        let release = Arc::new(AtomicBool::new(false));
        let held = Arc::new(AtomicBool::new(false));
        struct ReleaseOnDrop(Arc<AtomicBool>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&release));
        let holder = {
            let client = Arc::clone(&client);
            let release = Arc::clone(&release);
            let held = Arc::clone(&held);
            std::thread::spawn(move || {
                client.hold_session(|| {
                    held.store(true, Ordering::SeqCst);
                    let start = std::time::Instant::now();
                    while !release.load(Ordering::SeqCst) {
                        if start.elapsed() > std::time::Duration::from_secs(5) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                });
            })
        };
        wait_until("holder took the session lock", || {
            held.load(Ordering::SeqCst)
        });
        let waiter = {
            let client = Arc::clone(&client);
            std::thread::spawn(move || client.refresh_due(false).unwrap())
        };
        wait_until("refresh_due blocked on the session lock", || {
            client.session_waiters.load(Ordering::SeqCst) >= 1
        });
        assert!(held.load(Ordering::SeqCst));
        assert!(!waiter.is_finished());
        release.store(true, Ordering::SeqCst);
        holder.join().unwrap();
        waiter.join().unwrap();
        assert_eq!(client.session_waiters.load(Ordering::SeqCst), 0);
    }

    fn wait_until(label: &str, pred: impl Fn() -> bool) {
        let start = std::time::Instant::now();
        while !pred() {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(2),
                "timed out: {label}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[test]
    fn cancel_ping_stops_the_batch_before_it_starts() {
        let client = client();
        client.import_text("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:1?encryption=none&security=none#Example").unwrap();
        let id = client.servers(None).unwrap().remove(0).id;
        client.cancel_ping();
        let epoch = client.ping_epoch.load(Ordering::SeqCst);
        client.cancel_ping();
        assert_ne!(client.ping_epoch.load(Ordering::SeqCst), epoch);
        let _ = client.ping_many(&[id]);
    }

    #[test]
    fn stats_query_stays_off_until_the_window_asks() {
        let client = client();
        assert!(!client.stats_wanted.load(Ordering::Relaxed));
        client.set_stats_wanted(true);
        assert!(client.stats_wanted.load(Ordering::Relaxed));
        client.set_stats_wanted(false);
        assert!(!client.stats_wanted.load(Ordering::Relaxed));
    }

    #[test]
    fn servers_take_ping_style_from_the_subscription_map() {
        let client = client();
        let mut sub = Subscription::local(1);
        sub.id = "styled".into();
        sub.name = "Styled".into();
        sub.meta.ping_result = Some(PingStyle::Icon);
        client.db().upsert_subscription(&sub).unwrap();
        let mut server = sample("fast", Some(20));
        server.subscription_id = Some("styled".into());
        client.db().upsert_server(&server).unwrap();
        let row = client.servers(Some("styled")).unwrap().remove(0);
        assert_eq!(row.delay, "good");
    }

    #[test]
    fn reap_reports_a_busy_lock_and_a_stopped_core() {
        let client = Arc::new(client());
        assert_eq!(client.reap_dead_session(), Reap::Unchanged);
        *client.session() = Some(Arc::new(parked("gone")));
        assert_eq!(client.reap_dead_session(), Reap::Done(ReapReason::CoreStopped));
        assert!(client.session().is_none());

        let release = Arc::new(AtomicBool::new(false));
        let held = Arc::new(AtomicBool::new(false));
        struct ReleaseOnDrop(Arc<AtomicBool>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _release_on_drop = ReleaseOnDrop(Arc::clone(&release));
        let holder = {
            let client = Arc::clone(&client);
            let release = Arc::clone(&release);
            let held = Arc::clone(&held);
            std::thread::spawn(move || {
                client.hold_session(|| {
                    held.store(true, Ordering::SeqCst);
                    let start = std::time::Instant::now();
                    while !release.load(Ordering::SeqCst) {
                        if start.elapsed() > std::time::Duration::from_secs(5) {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                });
            })
        };
        wait_until("reap holder took the session lock", || held.load(Ordering::SeqCst));
        assert_eq!(client.reap_dead_session(), Reap::Busy);
        release.store(true, Ordering::SeqCst);
        holder.join().unwrap();
    }

    fn parked(id: &str) -> Live {
        Live {
            server_id: id.into(),
            server_name: id.into(),
            socks_port: 10808,
            socks_user: String::new(),
            socks_password: String::new(),
            block_bind: false,
            per_app_mode: PerAppMode::Off,
            per_app_list: Vec::new(),
            hide_vpn_icon: false,
            include_all_networks: true,
            exclude_local_networks: true,
            exclude_apns: true,
            mtu: 1500,
        }
    }
}
