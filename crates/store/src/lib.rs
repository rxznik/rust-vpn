//! SQLite-хранилище сущностей.
//!
//! Файл создаёт вызывающий путь, на Unix каталог 0700 и файл 0600.
//! Протокол сервера остаётся в `body`. Список читает имя, адрес, порт и задержку колонками.
//! Подписка `local` создаётся при открытии и не удаляется.
//! `commit_routing` копирует draft-профиль в applied. Процесс Xray читает applied.
//! `replace_servers` вместе с чисткой групп выполняется одной транзакцией.
//! Старая таблица `documents` переносится один раз и удаляется.
//! AES-ключи лежат в отдельной таблице сырыми байтами.
//! `invalidate` вызывают `delete_subscription`, `upsert_server`, `replace_servers` и `set_delays`.

use rvpn_model::{unix_now, CoreSettings, RoutingProfile, Server, ServerGroup, ServerSummary, Subscription, LOCAL_SUBSCRIPTION_ID};
use std::cell::Cell;
use std::collections::HashSet;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SETTINGS_ID: &str = "global";
const DESKTOP_SURFACE: &str = "desktop";

const UI_KEYS: &[&str] = &[
    "theme",
    "toolbar_density",
    "animations",
    "clear_background",
    "custom_opacity",
    "custom_surface_opacity",
    "custom_background",
    "custom_surface",
    "custom_text",
    "custom_muted",
    "custom_accent",
    "custom_on_accent",
    "font_size",
    "font_family",
    "font_path",
    "ui_zoom",
];

/// Errors from SQLite or from a document body that is not the expected JSON.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("not found")]
    NotFound,
}

pub struct Store {
    conn: Connection,
    generation: Cell<u64>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = path.parent() {
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        let _: i64 = conn.query_row("PRAGMA busy_timeout=5000", [], |row| row.get(0))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT,
                updated_at INTEGER,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                subscription_id TEXT,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                delay_ms INTEGER,
                subtitle TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS servers_by_subscription ON servers(subscription_id);
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                subscription_id TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS profiles_by_subscription ON profiles(subscription_id);
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                members TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS core_settings (
                id TEXT PRIMARY KEY,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ui_settings (
                surface TEXT PRIMARY KEY,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS aes_keys (
                key_id TEXT PRIMARY KEY,
                key_bytes BLOB NOT NULL
            );",
        )?;
        let store = Self { conn, generation: Cell::new(0) };
        store.migrate_documents()?;
        if store.get_subscription(LOCAL_SUBSCRIPTION_ID).is_err() {
            store.upsert_subscription(&Subscription::local(unix_now()))?;
        }
        Ok(store)
    }

    pub fn upsert_subscription(&self, sub: &Subscription) -> Result<(), StoreError> {
        let body = serde_json::to_string(sub)?;
        self.conn.execute(
            "INSERT INTO subscriptions (id, name, url, updated_at, body) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, url = excluded.url, updated_at = excluded.updated_at, body = excluded.body",
            params![sub.id, sub.name, sub.url, sub.updated_at, body],
        )?;
        Ok(())
    }

    pub fn get_subscription(&self, id: &str) -> Result<Subscription, StoreError> {
        let body: Option<String> = self.conn.query_row("SELECT body FROM subscriptions WHERE id = ?1", params![id], |row| row.get(0)).optional()?;
        let Some(body) = body else {
            return Err(StoreError::NotFound);
        };
        Ok(serde_json::from_str(&body)?)
    }

    pub fn list_subscriptions(&self) -> Result<Vec<Subscription>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT body FROM subscriptions ORDER BY id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|body| Ok(serde_json::from_str(&body?)?)).collect()
    }

    /// Deletes a subscription and its servers. The `local` subscription is kept.
    pub fn delete_subscription(&self, id: &str) -> Result<(), StoreError> {
        if id == LOCAL_SUBSCRIPTION_ID {
            return Ok(());
        }
        let mut stmt = self.conn.prepare("SELECT id FROM servers WHERE subscription_id = ?1")?;
        let gone: HashSet<String> = stmt.query_map(params![id], |row| row.get(0))?.collect::<Result<_, _>>()?;
        drop(stmt);
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM servers WHERE subscription_id = ?1", params![id])?;
        tx.execute("DELETE FROM profiles WHERE subscription_id = ?1", params![id])?;
        tx.execute("DELETE FROM subscriptions WHERE id = ?1", params![id])?;
        prune_members_tx(&tx, &gone)?;
        tx.commit()?;
        self.invalidate();
        Ok(())
    }

    pub fn upsert_group(&self, group: &ServerGroup) -> Result<(), StoreError> {
        let members = serde_json::to_string(&group.members)?;
        self.conn.execute(
            "INSERT INTO groups (id, name, created_at, members) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, created_at = excluded.created_at, members = excluded.members",
            params![group.id, group.name, group.created_at, members],
        )?;
        Ok(())
    }

    pub fn get_group(&self, id: &str) -> Result<ServerGroup, StoreError> {
        self.conn
            .query_row("SELECT id, name, created_at, members FROM groups WHERE id = ?1", params![id], group_from_row)
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    pub fn list_groups(&self) -> Result<Vec<ServerGroup>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT id, name, created_at, members FROM groups ORDER BY id")?;
        let rows = stmt.query_map([], group_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
    }

    pub fn delete_group(&self, id: &str) -> Result<(), StoreError> {
        self.conn.execute("DELETE FROM groups WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn upsert_server(&self, server: &Server) -> Result<(), StoreError> {
        insert_server(&self.conn, server)?;
        self.invalidate();
        Ok(())
    }

    pub fn get_server(&self, id: &str) -> Result<Server, StoreError> {
        let body: Option<String> = self.conn.query_row("SELECT body FROM servers WHERE id = ?1", params![id], |row| row.get(0)).optional()?;
        let Some(body) = body else {
            return Err(StoreError::NotFound);
        };
        Ok(serde_json::from_str(&body)?)
    }

    /// List columns for the home screen. The protocol body stays unread.
    pub fn list_summaries(&self, subscription_id: Option<&str>) -> Result<Vec<ServerSummary>, StoreError> {
        let map = |row: &rusqlite::Row<'_>| -> rusqlite::Result<ServerSummary> {
            Ok(ServerSummary {
                id: row.get(0)?,
                subscription_id: row.get(1)?,
                name: row.get(2)?,
                address: row.get(3)?,
                port: row.get(4)?,
                delay_ms: row.get(5)?,
                subtitle: row.get(6)?,
            })
        };
        if let Some(id) = subscription_id {
            let mut stmt = self.conn.prepare("SELECT id, subscription_id, name, address, port, delay_ms, subtitle FROM servers WHERE subscription_id = ?1")?;
            let rows = stmt.query_map(params![id], map)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
        } else {
            let mut stmt = self.conn.prepare("SELECT id, subscription_id, name, address, port, delay_ms, subtitle FROM servers")?;
            let rows = stmt.query_map([], map)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
        }
    }

    /// Generation of the in-memory server list. Callers cache against this value.
    pub fn generation(&self) -> u64 {
        self.generation.get()
    }

    pub fn replace_servers(&self, subscription_id: &str, servers: &[Server]) -> Result<(), StoreError> {
        let mut stmt = self.conn.prepare("SELECT id, delay_ms FROM servers WHERE subscription_id = ?1")?;
        let old: Vec<(String, Option<u32>)> = stmt.query_map(params![subscription_id], |row| Ok((row.get(0)?, row.get(1)?)))?.collect::<Result<_, _>>()?;
        drop(stmt);
        let mut delays = std::collections::HashMap::new();
        for (id, delay) in &old {
            if let Some(delay) = delay {
                delays.insert(id.clone(), *delay);
            }
        }
        let kept: HashSet<&str> = servers.iter().map(|server| server.id.as_str()).collect();
        let gone: HashSet<String> = old.into_iter().filter(|(id, _)| !kept.contains(id.as_str())).map(|(id, _)| id).collect();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM servers WHERE subscription_id = ?1", params![subscription_id])?;
        for server in servers {
            let mut server = server.clone();
            if server.delay_ms.is_none() {
                server.delay_ms = delays.get(&server.id).copied();
            }
            insert_server(&tx, &server)?;
        }
        prune_members_tx(&tx, &gone)?;
        tx.commit()?;
        self.invalidate();
        Ok(())
    }

    pub fn set_delay(&self, server_id: &str, delay_ms: Option<u32>) -> Result<(), StoreError> {
        self.set_delays(&[(server_id.to_string(), delay_ms)])
    }

    /// Writes measured delays in one transaction and refreshes the in-memory list.
    pub fn set_delays(&self, updates: &[(String, Option<u32>)]) -> Result<(), StoreError> {
        if updates.is_empty() {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        for (id, delay) in updates {
            let changed = match delay {
                Some(ms) => tx.execute(
                    "UPDATE servers SET delay_ms = ?1, body = json_set(body, '$.delay_ms', ?1) WHERE id = ?2",
                    params![ms, id],
                )?,
                None => tx.execute(
                    "UPDATE servers SET delay_ms = NULL, body = json_remove(body, '$.delay_ms') WHERE id = ?1",
                    params![id],
                )?,
            };
            if changed == 0 {
                continue;
            }
        }
        tx.commit()?;
        self.invalidate();
        Ok(())
    }

    pub fn upsert_profile(&self, profile: &RoutingProfile) -> Result<(), StoreError> {
        let body = serde_json::to_string(profile)?;
        self.conn.execute(
            "INSERT INTO profiles (id, subscription_id, body) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET subscription_id = excluded.subscription_id, body = excluded.body",
            params![profile.id, profile.subscription_id, body],
        )?;
        Ok(())
    }

    pub fn list_profiles(&self, subscription_id: &str) -> Result<Vec<RoutingProfile>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT body FROM profiles WHERE subscription_id = ?1")?;
        let rows = stmt.query_map(params![subscription_id], |row| row.get::<_, String>(0))?;
        rows.map(|body| Ok(serde_json::from_str(&body?)?)).collect()
    }

    pub fn get_profile(&self, id: &str) -> Result<RoutingProfile, StoreError> {
        let body: Option<String> = self.conn.query_row("SELECT body FROM profiles WHERE id = ?1", params![id], |row| row.get(0)).optional()?;
        let Some(body) = body else {
            return Err(StoreError::NotFound);
        };
        Ok(serde_json::from_str(&body)?)
    }

    pub fn delete_profile_files_hint(&self, subscription_id: &str) -> Result<Vec<String>, StoreError> {
        Ok(self.list_profiles(subscription_id)?.into_iter().filter_map(|p| p.geoip_path.or(p.geosite_path)).collect())
    }

    /// Copy the draft profile into the applied slot. The running tunnel reads the applied slot.
    pub fn commit_routing(&self, subscription_id: &str) -> Result<(), StoreError> {
        let mut sub = self.get_subscription(subscription_id)?;
        sub.applied_profile_id = sub.draft_profile_id.clone();
        sub.applied_routing_enabled = sub.draft_routing_enabled;
        self.upsert_subscription(&sub)
    }

    pub fn settings(&self) -> Result<CoreSettings, StoreError> {
        let body: Option<String> = self.conn.query_row("SELECT body FROM core_settings WHERE id = ?1", params![SETTINGS_ID], |row| row.get(0)).optional()?;
        match body {
            Some(body) => Ok(serde_json::from_str(&body)?),
            None => Ok(CoreSettings::default()),
        }
    }

    pub fn save_settings(&self, settings: &CoreSettings) -> Result<(), StoreError> {
        let body = serde_json::to_string(settings)?;
        self.conn.execute(
            "INSERT INTO core_settings (id, body) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET body = excluded.body",
            params![SETTINGS_ID, body],
        )?;
        Ok(())
    }

    /// Opaque window JSON. The store does not know the fields.
    pub fn get_ui(&self, surface: &str) -> Result<Option<String>, StoreError> {
        Ok(self.conn.query_row("SELECT body FROM ui_settings WHERE surface = ?1", params![surface], |row| row.get(0)).optional()?)
    }

    pub fn save_ui(&self, surface: &str, body: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO ui_settings (surface, body) VALUES (?1, ?2) ON CONFLICT(surface) DO UPDATE SET body = excluded.body",
            params![surface, body],
        )?;
        Ok(())
    }

    pub fn put_aes_key(&self, key_id: &str, key: &[u8]) -> Result<(), StoreError> {
        self.conn.execute("INSERT INTO aes_keys (key_id, key_bytes) VALUES (?1, ?2) ON CONFLICT(key_id) DO UPDATE SET key_bytes = excluded.key_bytes", params![key_id, key])?;
        Ok(())
    }

    pub fn aes_key(&self, key_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.conn.query_row("SELECT key_bytes FROM aes_keys WHERE key_id = ?1", params![key_id], |row| row.get(0)).optional()?)
    }

    fn invalidate(&self) {
        self.generation.set(self.generation.get().wrapping_add(1));
    }

    fn migrate_documents(&self) -> Result<(), StoreError> {
        let present: Option<String> = self
            .conn
            .query_row("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'documents'", [], |row| row.get(0))
            .optional()?;
        if present.is_none() {
            return Ok(());
        }
        let _ = self.conn.execute("ALTER TABLE documents ADD COLUMN delay_ms INTEGER", []);
        let _ = self.conn.execute("ALTER TABLE documents ADD COLUMN name TEXT", []);
        let tx = self.conn.unchecked_transaction()?;
        let mut stmt = tx.prepare("SELECT kind, id, parent, body FROM documents")?;
        let rows: Vec<(String, String, Option<String>, String)> = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?.collect::<Result<_, _>>()?;
        drop(stmt);
        for (kind, id, parent, body) in rows {
            match kind.as_str() {
                "subscription" => {
                    let sub: Subscription = serde_json::from_str(&body)?;
                    tx.execute(
                        "INSERT INTO subscriptions (id, name, url, updated_at, body) VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT(id) DO UPDATE SET name = excluded.name, url = excluded.url, updated_at = excluded.updated_at, body = excluded.body",
                        params![sub.id, sub.name, sub.url, sub.updated_at, body],
                    )?;
                }
                "server" => {
                    let mut server: Server = serde_json::from_str(&body)?;
                    if server.subscription_id.is_none() {
                        server.subscription_id = parent;
                    }
                    insert_server(&tx, &server)?;
                }
                "profile" => {
                    let profile: RoutingProfile = serde_json::from_str(&body)?;
                    tx.execute(
                        "INSERT INTO profiles (id, subscription_id, body) VALUES (?1, ?2, ?3)
                         ON CONFLICT(id) DO UPDATE SET subscription_id = excluded.subscription_id, body = excluded.body",
                        params![profile.id, profile.subscription_id, body],
                    )?;
                }
                "group" => {
                    let group: ServerGroup = serde_json::from_str(&body)?;
                    let members = serde_json::to_string(&group.members)?;
                    tx.execute(
                        "INSERT INTO groups (id, name, created_at, members) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(id) DO UPDATE SET name = excluded.name, created_at = excluded.created_at, members = excluded.members",
                        params![group.id, group.name, group.created_at, members],
                    )?;
                }
                "settings" if id == SETTINGS_ID => {
                    let (core, ui) = split_settings(&body)?;
                    tx.execute(
                        "INSERT INTO core_settings (id, body) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET body = excluded.body",
                        params![SETTINGS_ID, core],
                    )?;
                    tx.execute(
                        "INSERT INTO ui_settings (surface, body) VALUES (?1, ?2) ON CONFLICT(surface) DO UPDATE SET body = excluded.body",
                        params![DESKTOP_SURFACE, ui],
                    )?;
                }
                _ => {}
            }
        }
        tx.execute_batch("DROP TABLE documents")?;
        tx.commit()?;
        Ok(())
    }
}

fn split_settings(body: &str) -> Result<(String, String), StoreError> {
    let mut value: serde_json::Value = serde_json::from_str(body)?;
    let Some(obj) = value.as_object_mut() else {
        return Ok((serde_json::to_string(&CoreSettings::default())?, "{}".into()));
    };
    let mut ui = serde_json::Map::new();
    for key in UI_KEYS {
        if let Some(field) = obj.remove(*key) {
            ui.insert((*key).to_string(), field);
        }
    }
    let core: CoreSettings = serde_json::from_value(serde_json::Value::Object(obj.clone()))?;
    Ok((serde_json::to_string(&core)?, serde_json::Value::Object(ui).to_string()))
}

fn group_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServerGroup> {
    let members: String = row.get(3)?;
    let members = serde_json::from_str(&members).unwrap_or_default();
    Ok(ServerGroup { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)?, members })
}

fn insert_server(conn: &Connection, server: &Server) -> Result<(), StoreError> {
    let body = serde_json::to_string(server)?;
    conn.execute(
        "INSERT INTO servers (id, subscription_id, name, address, port, delay_ms, subtitle, body) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(id) DO UPDATE SET subscription_id = excluded.subscription_id, name = excluded.name, address = excluded.address, port = excluded.port, delay_ms = excluded.delay_ms, subtitle = excluded.subtitle, body = excluded.body",
        params![server.id, server.subscription_id, server.name, server.address, server.port, server.delay_ms, server.subtitle(), body],
    )?;
    Ok(())
}

fn prune_members_tx(tx: &rusqlite::Transaction<'_>, gone: &HashSet<String>) -> Result<(), StoreError> {
    if gone.is_empty() {
        return Ok(());
    }
    let mut stmt = tx.prepare("SELECT id, name, created_at, members FROM groups")?;
    let groups: Vec<ServerGroup> = stmt.query_map([], group_from_row)?.collect::<Result<_, _>>()?;
    drop(stmt);
    for mut group in groups {
        let before = group.members.len();
        group.members.retain(|id| !gone.contains(id));
        if group.members.len() != before {
            let members = serde_json::to_string(&group.members)?;
            tx.execute("UPDATE groups SET members = ?1 WHERE id = ?2", params![members, group.id])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvpn_model::RoutingProfile;

    #[test]
    fn routing_change_waits_for_commit() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/store-test.db");
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        let mut sub = Subscription::local(1);
        sub.draft_profile_id = Some("new".into());
        sub.draft_routing_enabled = false;
        store.upsert_subscription(&sub).unwrap();
        let loaded = store.get_subscription(LOCAL_SUBSCRIPTION_ID).unwrap();
        assert_eq!(loaded.applied_profile_id, None);
        assert!(loaded.applied_routing_enabled);
        store.commit_routing(LOCAL_SUBSCRIPTION_ID).unwrap();
        let loaded = store.get_subscription(LOCAL_SUBSCRIPTION_ID).unwrap();
        assert_eq!(loaded.applied_profile_id.as_deref(), Some("new"));
        assert!(!loaded.applied_routing_enabled);
        let profile = RoutingProfile {
            id: "new".into(),
            subscription_id: LOCAL_SUBSCRIPTION_ID.into(),
            name: "new".into(),
            global_proxy: true,
            remote_dns: String::new(),
            domestic_dns: String::new(),
            geoip_url: String::new(),
            geosite_url: String::new(),
            dns_hosts: Default::default(),
            direct_sites: vec![],
            direct_ip: vec![],
            proxy_sites: vec![],
            proxy_ip: vec![],
            block_sites: vec![],
            block_ip: vec![],
            domain_strategy: rvpn_model::DomainStrategy::AsIs,
            geoip_path: None,
            geosite_path: None,
        };
        store.upsert_profile(&profile).unwrap();
        assert_eq!(store.list_profiles(LOCAL_SUBSCRIPTION_ID).unwrap().len(), 1);
        store.put_aes_key("key02", b"0123456789abcdef").unwrap();
        assert_eq!(store.aes_key("key02").unwrap().unwrap(), b"0123456789abcdef");
        let _ = std::fs::remove_file(&path);
    }

    fn owned(id: &str, parent: &str) -> Server {
        Server {
            id: id.into(),
            subscription_id: Some(parent.into()),
            name: id.into(),
            address: "203.0.113.10".into(),
            port: 443,
            protocol: rvpn_model::Protocol::Socks { username: None, password: None },
            description: None,
            fragment: None,
            noise: None,
            raw_link: None,
            delay_ms: None,
        }
    }

    #[test]
    fn group_keeps_members_until_their_servers_disappear() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/store-groups.db");
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        store.upsert_server(&owned("keep", "remote")).unwrap();
        store.upsert_server(&owned("drop", "remote")).unwrap();
        store.upsert_server(&owned("other", "second")).unwrap();
        store
            .upsert_group(&ServerGroup {
                id: "home".into(),
                name: "Дом".into(),
                members: vec!["keep".into(), "drop".into(), "other".into()],
                created_at: 1,
            })
            .unwrap();
        assert_eq!(store.get_group("home").unwrap().members, vec!["keep".to_string(), "drop".to_string(), "other".to_string()]);
        store
            .upsert_group(&ServerGroup {
                id: "home".into(),
                name: "Дом".into(),
                members: vec!["keep".into(), "other".into()],
                created_at: 1,
            })
            .unwrap();
        assert_eq!(store.get_group("home").unwrap().members, vec!["keep".to_string(), "other".to_string()]);
        store
            .upsert_group(&ServerGroup {
                id: "home".into(),
                name: "Дом".into(),
                members: vec!["keep".into(), "drop".into(), "other".into()],
                created_at: 1,
            })
            .unwrap();
        store.replace_servers("remote", &[owned("keep", "remote")]).unwrap();
        assert_eq!(store.get_group("home").unwrap().members, vec!["keep".to_string(), "other".to_string()]);
        store.delete_subscription("second").unwrap();
        assert_eq!(store.get_group("home").unwrap().members, vec!["keep".to_string()]);
        assert!(store.get_server("keep").is_ok());
        store.delete_group("home").unwrap();
        assert!(store.get_group("home").is_err());
        assert!(store.get_server("keep").is_ok());
        store.delete_subscription(LOCAL_SUBSCRIPTION_ID).unwrap();
        assert!(store.get_subscription(LOCAL_SUBSCRIPTION_ID).is_ok());
        let listed = store.list_summaries(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "keep");
        assert_eq!(listed[0].subtitle, "SOCKS5");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn settings_default_and_bad_json_and_file_mode() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/store-edges.db");
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.settings().unwrap().socks_port, CoreSettings::default().socks_port);
        store
            .conn
            .execute(
                "INSERT INTO servers (id, subscription_id, name, address, port, delay_ms, subtitle, body) VALUES ('bad', 'local', 'bad', '203.0.113.10', 443, NULL, '', '{')",
                [],
            )
            .unwrap();
        assert!(matches!(store.get_server("bad"), Err(StoreError::Json(_))));
        store.set_delays(&[("missing".into(), Some(1))]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn old_documents_move_once() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/store-migrate.db");
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE documents (
                kind TEXT NOT NULL,
                id TEXT NOT NULL,
                parent TEXT,
                body TEXT NOT NULL,
                delay_ms INTEGER,
                name TEXT,
                PRIMARY KEY (kind, id)
            );",
        )
        .unwrap();
        let sub = Subscription {
            id: "remote".into(),
            name: "Blanc".into(),
            url: Some("https://example.invalid/sub".into()),
            kind: rvpn_model::SubscriptionKind::Links,
            raw_json: None,
            userinfo: None,
            meta: Default::default(),
            updated_at: Some(1_700_000_000),
            draft_profile_id: None,
            applied_profile_id: None,
            draft_routing_enabled: true,
            applied_routing_enabled: true,
            created_at: 1,
        };
        let server = owned("one", "remote");
        let group = ServerGroup { id: "home".into(), name: "Дом".into(), members: vec!["one".into()], created_at: 2 };
        let mut flat = serde_json::to_value(CoreSettings::default()).unwrap();
        let obj = flat.as_object_mut().unwrap();
        obj.insert("socks_port".into(), serde_json::json!(20000));
        obj.insert("theme".into(), serde_json::json!("day"));
        obj.insert("font_size".into(), serde_json::json!(18));
        conn.execute("INSERT INTO documents (kind, id, body) VALUES ('subscription', 'remote', ?1)", params![serde_json::to_string(&sub).unwrap()]).unwrap();
        conn.execute("INSERT INTO documents (kind, id, parent, body, name) VALUES ('server', 'one', 'remote', ?1, 'one')", params![serde_json::to_string(&server).unwrap()]).unwrap();
        conn.execute("INSERT INTO documents (kind, id, body) VALUES ('group', 'home', ?1)", params![serde_json::to_string(&group).unwrap()]).unwrap();
        conn.execute("INSERT INTO documents (kind, id, body) VALUES ('settings', 'global', ?1)", params![flat.to_string()]).unwrap();
        drop(conn);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.get_subscription("remote").unwrap().name, "Blanc");
        assert_eq!(store.get_server("one").unwrap().port, 443);
        assert_eq!(store.get_group("home").unwrap().members, vec!["one".to_string()]);
        assert_eq!(store.settings().unwrap().socks_port, 20000);
        let ui = store.get_ui("desktop").unwrap().unwrap();
        assert!(ui.contains("day"));
        assert!(ui.contains("18"));
        assert!(!ui.contains("socks_port"));
        let again = Store::open(&path).unwrap();
        assert_eq!(again.get_server("one").unwrap().name, "one");
        let left: i64 = again.conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'documents'", [], |row| row.get(0)).unwrap();
        assert_eq!(left, 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_delays_keeps_name_and_address() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/store-delays.db");
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        let mode: String = store.conn.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
        assert_eq!(mode, "wal");
        let timeout: i64 = store.conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0)).unwrap();
        assert_eq!(timeout, 5000);

        let mut server = owned("ping-1", "remote");
        server.name = "Distinctive Name".into();
        server.address = "203.0.113.10".into();
        store.upsert_server(&server).unwrap();

        let generation = store.generation();
        store.set_delays(&[]).unwrap();
        assert_eq!(store.generation(), generation);

        store.set_delays(&[("ping-1".into(), Some(42)), ("missing".into(), Some(1))]).unwrap();
        assert_eq!(store.generation(), generation + 1);

        let body: String = store.conn.query_row("SELECT body FROM servers WHERE id = ?1", params!["ping-1"], |row| row.get(0)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["name"], "Distinctive Name");
        assert_eq!(value["address"], "203.0.113.10");
        assert_eq!(value["delay_ms"], 42);
        let column: Option<u32> = store.conn.query_row("SELECT delay_ms FROM servers WHERE id = ?1", params!["ping-1"], |row| row.get(0)).unwrap();
        assert_eq!(column, Some(42));
        let name: String = store.conn.query_row("SELECT name FROM servers WHERE id = ?1", params!["ping-1"], |row| row.get(0)).unwrap();
        let subtitle: String = store.conn.query_row("SELECT subtitle FROM servers WHERE id = ?1", params!["ping-1"], |row| row.get(0)).unwrap();
        assert_eq!(name, "Distinctive Name");
        assert_eq!(subtitle, "SOCKS5");

        store.set_delays(&[("ping-1".into(), None)]).unwrap();
        let body: String = store.conn.query_row("SELECT body FROM servers WHERE id = ?1", params!["ping-1"], |row| row.get(0)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["name"], "Distinctive Name");
        assert_eq!(value["address"], "203.0.113.10");
        assert!(value.get("delay_ms").is_none());
        let column: Option<u32> = store.conn.query_row("SELECT delay_ms FROM servers WHERE id = ?1", params!["ping-1"], |row| row.get(0)).unwrap();
        assert_eq!(column, None);
        assert_eq!(store.get_server("ping-1").unwrap().delay_ms, None);
        let _ = std::fs::remove_file(&path);
    }
}
