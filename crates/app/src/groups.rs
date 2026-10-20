use super::{AppError, Client, ServerRow};
use rvpn_links::server_id;
use rvpn_model::{
    group_name, unix_now, ServerGroup,
};
use std::collections::HashSet;

use super::token;

impl Client {
    pub fn groups(&self) -> Result<Vec<ServerGroup>, AppError> {
        let mut list = self.db().list_groups()?;
        list.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(list)
    }

    pub fn create_group(&self, name: &str) -> Result<String, AppError> {
        let name = group_name(name).ok_or_else(|| AppError::new("Имя должно быть от 1 до 80 символов"))?;
        if group_name_taken(&self.groups()?, &name, None) {
            return Err(AppError::new("Группа с таким именем уже есть"));
        }
        let id = server_id("group", &token());
        self.db().upsert_group(&ServerGroup { id: id.clone(), name, members: Vec::new(), created_at: unix_now() })?;
        Ok(id)
    }

    pub fn rename_group(&self, id: &str, name: &str) -> Result<(), AppError> {
        let name = group_name(name).ok_or_else(|| AppError::new("Имя должно быть от 1 до 80 символов"))?;
        if group_name_taken(&self.groups()?, &name, Some(id)) {
            return Err(AppError::new("Группа с таким именем уже есть"));
        }
        let mut group = self.db().get_group(id).map_err(group_error)?;
        group.name = name;
        self.db().upsert_group(&group)?;
        Ok(())
    }

    pub fn delete_group(&self, id: &str) -> Result<(), AppError> {
        self.db().delete_group(id)?;
        Ok(())
    }

    pub fn add_group_member(&self, group_id: &str, server_id: &str) -> Result<(), AppError> {
        self.db().get_server(server_id).map_err(|_| AppError::new("Сервер не найден"))?;
        let mut group = self.db().get_group(group_id).map_err(group_error)?;
        if !group.members.iter().any(|id| id == server_id) {
            group.members.push(server_id.to_string());
            self.db().upsert_group(&group)?;
        }
        Ok(())
    }

    pub fn remove_group_member(&self, group_id: &str, server_id: &str) -> Result<(), AppError> {
        let mut group = self.db().get_group(group_id).map_err(group_error)?;
        let before = group.members.len();
        group.members.retain(|id| id != server_id);
        if group.members.len() != before {
            self.db().upsert_group(&group)?;
        }
        Ok(())
    }

    pub fn group_servers(&self, group_id: &str) -> Result<Vec<ServerRow>, AppError> {
        let group = self.db().get_group(group_id).map_err(group_error)?;
        let wanted: HashSet<&str> = group.members.iter().map(|id| id.as_str()).collect();
        let mut rows = self.servers(None)?;
        rows.retain(|row| wanted.contains(row.id.as_str()));
        Ok(rows)
    }

    /// Lowest already measured delay among `ids`. Servers outside the set are ignored.
    pub fn lowest_delay_id(&self, ids: &[String]) -> Result<Option<String>, AppError> {
        let wanted: HashSet<&str> = ids.iter().map(|id| id.as_str()).collect();
        let best = self
            .db()
            .list_summaries(None)?
            .into_iter()
            .filter(|server| wanted.contains(server.id.as_str()))
            .filter_map(|server| server.delay_ms.map(|ms| (ms, server.id)))
            .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        Ok(best.map(|(_, id)| id))
    }
}

fn group_name_taken(groups: &[ServerGroup], name: &str, keep: Option<&str>) -> bool {
    let folded = name.to_lowercase();
    groups.iter().any(|group| Some(group.id.as_str()) != keep && group.name.to_lowercase() == folded)
}

fn group_error(err: rvpn_store::StoreError) -> AppError {
    match err {
        rvpn_store::StoreError::NotFound => AppError::new("Группа не найдена"),
        other => AppError::from(other),
    }
}
