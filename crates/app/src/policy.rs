use super::{AppError, Client};
use rvpn_model::{
    traffic_line, unix_now, AuthMode, AutoConnectType, CoreSettings, Fragment, Noise, Server, ServerSummary, Subscription, SubscriptionMeta,
};

use super::token;

impl Client {
    pub fn settings(&self) -> Result<CoreSettings, AppError> {
        Ok(self.db().settings()?)
    }

    pub fn save_settings(&self, core: &CoreSettings) -> Result<(), AppError> {
        self.db().save_settings(core)?;
        if let Ok(exe) = std::env::current_exe() {
            self.platform.set_autostart(core.autostart, &exe)?;
        }
        Ok(())
    }

    pub fn ui_blob(&self, surface: &str) -> Result<Option<String>, AppError> {
        Ok(self.db().get_ui(surface)?)
    }

    pub fn save_ui_blob(&self, surface: &str, body: &str) -> Result<(), AppError> {
        self.db().save_ui(surface, body)?;
        Ok(())
    }

    pub fn fastest_server_id(&self) -> Result<Option<String>, AppError> {
        let servers = self.db().list_summaries(None)?;
        Ok(pick_server(&servers, AutoConnectType::LowestDelay, None).map(|server| server.id.clone()))
    }

    pub fn announcement(&self, subscription_id: &str) -> Result<Option<String>, AppError> {
        let sub = self.db().get_subscription(subscription_id)?;
        Ok(announcement_text(&sub, unix_now()))
    }

    pub fn traffic(&self, subscription_id: &str) -> Result<String, AppError> {
        let sub = self.db().get_subscription(subscription_id)?;
        Ok(sub.userinfo.as_ref().map(traffic_line).unwrap_or_default())
    }
}

pub(crate) fn overlay_settings(settings: &mut CoreSettings, meta: &SubscriptionMeta) {
    if let Some(value) = meta.proxy_enable {
        settings.proxy_enable = value;
    }
    if let Some(value) = meta.tun_enable {
        settings.tun_enable = value;
    }
    if let Some(value) = meta.sniffing {
        settings.sniffing = value;
    }
    if let Some(value) = meta.inbound_http {
        settings.http_enabled = value;
    }
    if let Some(mode) = meta.socks_auth_mode {
        settings.socks_auth_mode = mode;
    }
        if let Some(user) = &meta.socks_auth_user {
        if &settings.socks_user != user {
            settings.socks_user.clone_from(user);
        }
    }
    if let Some(password) = &meta.socks_auth_password {
        if &settings.socks_password != password {
            settings.socks_password.clone_from(password);
        }
    }
    if let Some(mode) = meta.http_auth_mode {
        settings.http_auth_mode = mode;
    }
    if let Some(user) = &meta.http_auth_user {
        settings.http_user = user.clone();
    }
    if let Some(password) = &meta.http_auth_password {
        settings.http_password = password.clone();
    }
    if let Some(mode) = meta.per_app_mode {
        settings.per_app_mode = mode;
    }
    if !meta.per_app_list.is_empty() && settings.per_app_list != meta.per_app_list {
        settings.per_app_list.clone_from(&meta.per_app_list);
    }
    if !meta.exclude_routes.is_empty() && settings.exclude_routes != meta.exclude_routes {
        settings.exclude_routes.clone_from(&meta.exclude_routes);
    }
    if meta.no_limit || meta.no_limit_xhttp {
        settings.no_limit = true;
    }
    if let Some(mux) = &meta.mux {
        settings.mux = mux.clone();
    }
    if let Some(kind) = meta.ping_type {
        settings.ping_type = kind;
    }
    if let Some(url) = &meta.check_url {
        settings.check_url = url.clone();
    }
    if meta.fragmentation_enable {
        settings.fragmentation_enable = true;
        if let Some(fragment) = &meta.fragmentation {
            settings.fragmentation = fragment.clone();
        }
    }
    if meta.noises_enable {
        settings.noises_enable = true;
        if let Some(noise) = &meta.noise {
            settings.noise = noise.clone();
        }
    }
    if let Some(autostart) = meta.autostart {
        settings.autostart = autostart;
    }
}

pub(crate) fn ensure_auth(settings: &mut CoreSettings) {
    // GNOME, macOS and Windows system-proxy settings have no password field.
    // A generated password makes the browser fail while a direct ping still succeeds.
    if settings.proxy_enable {
        if settings.socks_user.is_empty() && matches!(settings.socks_auth_mode, AuthMode::Auto | AuthMode::FromJson) {
            settings.socks_auth_mode = AuthMode::Disable;
        }
        if settings.http_user.is_empty() && matches!(settings.http_auth_mode, AuthMode::Auto | AuthMode::FromJson) {
            settings.http_auth_mode = AuthMode::Disable;
        }
        return;
    }
    if matches!(settings.socks_auth_mode, AuthMode::Auto | AuthMode::FromJson) && settings.socks_user.is_empty() {
        settings.socks_user = token();
        settings.socks_password = token();
    }
    if matches!(settings.http_auth_mode, AuthMode::Auto | AuthMode::FromJson) && settings.http_user.is_empty() {
        settings.http_user = token();
        settings.http_password = token();
    }
}

pub(crate) fn effective_packet_tweaks(settings: &CoreSettings, server: &Server, meta: &SubscriptionMeta) -> (Option<Fragment>, Option<Noise>) {
    let global = settings.fragmentation_enable || meta.fragmentation_enable;
    let fragment = if global {
        Some(meta.fragmentation.clone().unwrap_or_else(|| settings.fragmentation.clone()))
    } else {
        server.fragment.clone()
    };
    let noise_global = settings.noises_enable || meta.noises_enable;
    let noise = if noise_global {
        Some(meta.noise.clone().unwrap_or_else(|| settings.noise.clone()))
    } else {
        server.noise.clone()
    };
    (fragment, noise)
}

pub trait Ranked {
    fn rank_id(&self) -> &str;
    fn rank_delay(&self) -> Option<u32>;
}

impl Ranked for Server {
    fn rank_id(&self) -> &str {
        &self.id
    }
    fn rank_delay(&self) -> Option<u32> {
        self.delay_ms
    }
}

impl Ranked for ServerSummary {
    fn rank_id(&self) -> &str {
        &self.id
    }
    fn rank_delay(&self) -> Option<u32> {
        self.delay_ms
    }
}

pub fn pick_server<'a, T: Ranked>(servers: &'a [T], kind: AutoConnectType, last: Option<&str>) -> Option<&'a T> {
    match kind {
        AutoConnectType::LastUsed => last.and_then(|id| servers.iter().find(|server| server.rank_id() == id)).or_else(|| servers.first()),
        AutoConnectType::LowestDelay => {
            servers.iter().filter(|server| server.rank_delay().is_some()).min_by_key(|server| server.rank_delay().unwrap_or(u32::MAX)).or_else(|| servers.first())
        }
        AutoConnectType::Random => {
            if servers.is_empty() {
                None
            } else {
                servers.get((unix_now() as usize).wrapping_mul(17) % servers.len())
            }
        }
    }
}

pub fn announcement_text(sub: &Subscription, now: i64) -> Option<String> {
    if sub.meta.sub_expire {
        if let Some(expire) = sub.userinfo.as_ref().and_then(|info| info.expire) {
            let days = expire.saturating_sub(now) / 86_400;
            if expire <= now {
                return Some("Subscription expired".into());
            }
            if days <= 3 {
                return Some(format!("Subscription expires in {days} days"));
            }
        }
    }
    if let Some(text) = &sub.meta.sub_info_text {
        if !text.is_empty() && text != "0" {
            return Some(text.chars().take(200).collect());
        }
    }
    sub.meta.announce.as_ref().map(|text| text.chars().take(200).collect())
}
