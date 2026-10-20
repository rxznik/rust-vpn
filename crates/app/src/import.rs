use super::{AppError, Client};
use rvpn_links::{parse_server, server_id};
use rvpn_model::{
    group_name, unix_now, Subscription, LOCAL_SUBSCRIPTION_ID,
};
use rvpn_routing::{materialize_geo, parse_routing_link, profile_from_b64};
use rvpn_subscription::{
    apply_url_rewrite, fetch_subscription, hwid_query, key_query, parse_subscription, update_due,
};
use std::path::Path;
use std::sync::Mutex;
use url::Url;

use super::session::remove_inside;

impl Client {
    pub fn import_text(&self, text: &str) -> Result<String, AppError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(AppError::new("nothing to import"));
        }
        if text.starts_with("happ://crypt") {
            return Err(AppError::new("encrypted Happ links need a private key that is not embedded in this client"));
        }
        if text.starts_with("happ://routing/") {
            self.apply_routing(LOCAL_SUBSCRIPTION_ID, text)?;
            return Ok(LOCAL_SUBSCRIPTION_ID.into());
        }
        if let Ok(url) = Url::parse(text) {
            if matches!(url.scheme(), "http" | "https") && text.lines().count() == 1 {
                return self.add_remote_subscription(text);
            }
        }
        self.import_local_body(text)?;
        Ok(LOCAL_SUBSCRIPTION_ID.into())
    }

    pub fn add_remote_subscription(&self, url: &str) -> Result<String, AppError> {
        self.ensure_hwid(url)?;
        let id = server_id("sub", url);
        let mut sub = Subscription::local(unix_now());
        sub.id = id.clone();
        sub.name = url.chars().take(25).collect();
        sub.url = Some(url.to_string());
        self.db().upsert_subscription(&sub)?;
        self.refresh(&id)?;
        Ok(id)
    }

    pub fn refresh(&self, subscription_id: &str) -> Result<usize, AppError> {
        let _session_lock = self.session_guard();
        self.refresh_locked(subscription_id)
    }

    fn refresh_locked(&self, subscription_id: &str) -> Result<usize, AppError> {
        let sub = self.db().get_subscription(subscription_id)?;
        let Some(url) = sub.url.clone() else {
            return Ok(0);
        };
        self.ensure_hwid(&url)?;
        let device = if sub.meta.alternative_hwid { self.platform.alternative_hwid() } else { self.platform.device_hwid() };
        let fetch_url = url.clone();
        let key = self.lookup_key(&fetch_url)?;
        let ua = sub.meta.user_agent.clone().unwrap_or_else(|| rvpn_model::APP_USER_AGENT.into());
        let os = self.platform.os_name();
        let ver = self.platform.os_version();
        let model = self.platform.device_model();
        let header_refs = [
            ("user-agent", ua.as_str()),
            ("x-hwid", device.as_str()),
            ("x-device-os", os.as_str()),
            ("x-ver-os", ver.as_str()),
            ("x-device-model", model.as_str()),
        ];
        let output = fetch_subscription(&fetch_url, sub.meta.fallback_url.as_deref(), &header_refs, key.as_deref())?;
        let parsed = parse_subscription(&output.body, &output.headers, subscription_id)?;
        let geo_dir = self.data_dir.join("geo").join(subscription_id);
        if geo_dir.exists() {
            if let Err(err) = std::fs::remove_dir_all(&geo_dir) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    return Err(err.into());
                }
            }
        }
        let mut warnings = Vec::new();
        for link in &parsed.routing_links {
            if let Err(err) = self.apply_routing(subscription_id, link) {
                warnings.push(err.to_string());
            }
        }
        {
            let store = self.db();
            store.replace_servers(subscription_id, &parsed.servers)?;
            let mut saved = store.get_subscription(subscription_id)?;
            if let Some(name) = parsed.name {
                saved.name = name;
            }
            saved.kind = parsed.kind;
            saved.raw_json = parsed.raw_json;
            saved.userinfo = parsed.userinfo;
            saved.meta = parsed.meta;
            saved.draft_routing_enabled = saved.meta.routing_enabled;
            saved.updated_at = Some(unix_now());
            let rewritten = apply_url_rewrite(&url, &saved.meta);
            saved.url = Some(rewritten);
            if let Some(fallback) = saved.meta.fallback_url.clone() {
                saved.meta.fallback_url = Some(fallback);
            }
            store.upsert_subscription(&saved)?;
        }
        if !warnings.is_empty() {
            return Err(AppError::new(warnings.join("; ")));
        }
        Ok(parsed.servers.len())
    }

    pub fn refresh_due(&self, on_open: bool) -> Result<(), AppError> {
        let _session_lock = self.session_guard();
        self.refresh_due_locked(on_open)
    }

    fn refresh_due_locked(&self, on_open: bool) -> Result<(), AppError> {
        let ids: Vec<String> = self
            .subscriptions()?
            .into_iter()
            .filter(|sub| update_due(sub, unix_now(), on_open))
            .map(|sub| sub.id)
            .collect();
        let mut failure = None;
        for chunk in ids.chunks(4) {
            let errors = Mutex::new(Vec::new());
            std::thread::scope(|scope| {
                for id in chunk {
                    let id = id.clone();
                    let errors = &errors;
                    scope.spawn(move || {
                        if let Err(err) = self.refresh_locked(&id) {
                            errors.lock().unwrap_or_else(|err| err.into_inner()).push(err);
                        }
                    });
                }
            });
            if let Some(err) = errors.into_inner().unwrap_or_else(|err| err.into_inner()).into_iter().next() {
                failure = Some(err);
                break;
            }
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub fn delete_subscription(&self, id: &str) -> Result<(), AppError> {
        if id == LOCAL_SUBSCRIPTION_ID {
            return Ok(());
        }
        let paths = self.db().delete_profile_files_hint(id)?;
        self.db().delete_subscription(id)?;
        let geo_root = self.data_dir.join("geo").join(id);
        for path in paths {
            remove_inside(&geo_root, Path::new(&path));
        }
        let _ = std::fs::remove_dir_all(&geo_root);
        Ok(())
    }

    pub fn rename_subscription(&self, id: &str, name: &str) -> Result<(), AppError> {
        let name = group_name(name).ok_or_else(|| AppError::new("Имя должно быть от 1 до 80 символов"))?;
        let mut sub = self.db().get_subscription(id)?;
        sub.name = name;
        self.db().upsert_subscription(&sub)?;
        Ok(())
    }

    pub fn put_aes_key(&self, key_id: &str, key_b64_or_raw: &str) -> Result<(), AppError> {
        let bytes = if key_b64_or_raw.len() == 16 {
            key_b64_or_raw.as_bytes().to_vec()
        } else {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_b64_or_raw.trim()).map_err(|e| AppError::new(e.to_string()))?
        };
        if bytes.len() != 16 {
            return Err(AppError::new("AES-128 key must be 16 bytes"));
        }
        self.db().put_aes_key(key_id, &bytes)?;
        Ok(())
    }

    fn import_local_body(&self, text: &str) -> Result<(), AppError> {
        let parsed = parse_subscription(text, &Default::default(), LOCAL_SUBSCRIPTION_ID)?;
        let links = parsed.routing_links.clone();
        {
            let store = self.db();
            for server in &parsed.servers {
                store.upsert_server(server)?;
            }
            if parsed.servers.is_empty() {
                if let Ok(server) = parse_server(text, Some(LOCAL_SUBSCRIPTION_ID)) {
                    store.upsert_server(&server)?;
                } else if text.contains("://") && links.is_empty() {
                    return Err(AppError::new("no servers found"));
                }
            }
        }
        for link in links {
            self.apply_routing(LOCAL_SUBSCRIPTION_ID, &link)?;
        }
        Ok(())
    }

    fn apply_routing(&self, subscription_id: &str, link: &str) -> Result<(), AppError> {
        match parse_routing_link(link)? {
            rvpn_model::RoutingCommand::Off => {
                let store = self.db();
                let mut sub = store.get_subscription(subscription_id)?;
                sub.draft_routing_enabled = false;
                sub.meta.routing_enabled = false;
                store.upsert_subscription(&sub)?;
            }
            rvpn_model::RoutingCommand::Add { activate, profile_b64 } => {
                let mut profile = profile_from_b64(subscription_id, &profile_b64)?;
                let dir = self.data_dir.join("geo").join(subscription_id).join(&profile.id);
                let geo = materialize_geo(&mut profile, &dir)?;
                let missing_geo = geo.files_missing;
                let store = self.db();
                store.upsert_profile(&profile)?;
                let mut sub = store.get_subscription(subscription_id)?;
                let first = sub.draft_profile_id.is_none();
                if activate || first {
                    sub.draft_profile_id = Some(profile.id);
                    sub.draft_routing_enabled = true;
                }
                store.upsert_subscription(&sub)?;
                if missing_geo {
                    return Err(AppError::new("geo database was not written"));
                }
            }
        }
        Ok(())
    }

    fn ensure_hwid(&self, url: &str) -> Result<(), AppError> {
        if let Some(expected) = hwid_query(url) {
            let device = self.platform.device_hwid();
            let alt = self.platform.alternative_hwid();
            if !expected.eq_ignore_ascii_case(&device) && !expected.eq_ignore_ascii_case(&alt) {
                return Err(AppError::new("This subscription is locked to another device"));
            }
        }
        Ok(())
    }

    fn lookup_key(&self, url: &str) -> Result<Option<Vec<u8>>, AppError> {
        let explicit = key_query(url);
        let id = explicit.clone().unwrap_or_else(|| "default".into());
        let key = self.db().aes_key(&id)?;
        if key.is_none() && explicit.is_none() {
            return Ok(None);
        }
        Ok(key)
    }
}
