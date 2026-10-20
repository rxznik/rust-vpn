//! Присваивание свойств окна Slint. Расчёт секций остаётся в `view`.

use super::*;

pub fn load(ui: &MainWindow, client: &Client, selected: &Mutex<String>) {
    reload(ui, client);
    sync_selection(ui, client, selected);
    apply_status(ui, client, None);
    let core = client.settings().unwrap_or_default();
    let appearance = crate::appearance::load(client);
    ui.set_tun_enabled(core.tun_enable);
    ui.set_proxy_enabled(core.proxy_enable);
    ui.set_socks_port(core.socks_port.to_string().into());
    ui.set_hwid_text(client.hwid().into());
    ui.set_sort_by_ping(core.sort_type == SortType::Ping);
    ui.set_fastest_on(core.autoconnect && core.autoconnect_type == AutoConnectType::LowestDelay);
    ui.set_labeled(appearance.toolbar_density == crate::appearance::Density::Standard);
    ui.set_motion(appearance.animations);
    ui.set_clear_background(appearance.clear_background);
    ui.set_custom_opacity(f32::from(appearance.custom_opacity));
    ui.set_custom_surface_opacity(f32::from(appearance.surface_opacity()));
    push_theme(ui, &appearance);
    apply_type(ui, &appearance);
}

pub fn apply_type(ui: &MainWindow, settings: &crate::appearance::DesktopSettings) {
    let mut family = rvpn_model::font_family_name(&settings.font_family).unwrap_or_default();
    if let Some(path) = settings.font_path.as_deref() {
        if register_font_file(std::path::Path::new(path)).is_err() {
            family.clear();
            ui.set_status_text("Не удалось открыть шрифт".into());
        }
    }
    ui.set_font_size(i32::from(rvpn_model::font_size_step(settings.font_size)));
    ui.set_font_family(family.into());
    ui.set_ui_zoom(i32::from(rvpn_model::nearest_zoom(settings.ui_zoom)));
}

pub fn install_font(data_dir: &std::path::Path, source: &std::path::Path) -> Result<(String, String), String> {
    let bytes = std::fs::read(source).map_err(|_| "Не удалось открыть шрифт".to_string())?;
    let family = register_font_bytes(&bytes)?;
    let family = rvpn_model::font_family_name(&family).filter(|name| !name.is_empty()).ok_or_else(|| "Не удалось открыть шрифт".to_string())?;
    let dest = font_destination(data_dir, source)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "Не удалось открыть шрифт".to_string())?;
        set_private_dir(parent);
    }
    std::fs::write(&dest, &bytes).map_err(|_| "Не удалось открыть шрифт".to_string())?;
    set_private_file(&dest);
    let stored = dest.canonicalize().map_err(|_| "Не удалось открыть шрифт".to_string())?;
    let root = data_dir.join("fonts").canonicalize().map_err(|_| "Не удалось открыть шрифт".to_string())?;
    if !stored.starts_with(&root) {
        let _ = std::fs::remove_file(&dest);
        return Err("Не удалось открыть шрифт".into());
    }
    Ok((stored.to_string_lossy().into_owned(), family))
}

pub fn register_font_file(path: &std::path::Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|_| "Не удалось открыть шрифт".to_string())?;
    register_font_bytes(&bytes)
}

fn register_font_bytes(bytes: &[u8]) -> Result<String, String> {
    let blob = slint::fontique_011::fontique::Blob::new(std::sync::Arc::new(bytes.to_vec()));
    let mut collection = slint::fontique_011::shared_collection();
    let fonts = collection.register_fonts(blob, None);
    let (id, _) = fonts.first().ok_or_else(|| "Не удалось открыть шрифт".to_string())?;
    collection.family_name(*id).map(|name| name.to_string()).ok_or_else(|| "Не удалось открыть шрифт".to_string())
}

fn font_destination(data_dir: &std::path::Path, source: &std::path::Path) -> Result<PathBuf, String> {
    let raw = source.file_name().and_then(|name| name.to_str()).unwrap_or("font.ttf");
    let safe: String = raw.chars().filter(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ')).collect();
    let safe = safe.trim().trim_matches('.').to_string();
    if safe.is_empty() || safe.contains("..") {
        return Err("Не удалось открыть шрифт".into());
    }
    Ok(data_dir.join("fonts").join(safe))
}

fn set_private_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
}

fn set_private_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

pub fn reload(ui: &MainWindow, client: &Client) {
    let rows = client.servers(None).unwrap_or_default();
    let groups = match client.groups() {
        Ok(groups) => groups,
        Err(err) => {
            if status::Page::Lists.is(ui.get_page()) {
                ui.set_list_notice(err.to_string().into());
                ui.set_list_notice_bad(true);
            }
            Vec::new()
        }
    };
    let subs = client.subscriptions().unwrap_or_default();
    let open = open_sections().lock().expect("sections").clone();
    let plan = planned(&subs, &groups, &rows);
    let entries = home_entries(&plan, &open, &rows, &groups);
    let known: HashSet<String> = rows.iter().map(|row| row.id.clone()).collect();
    retain_runs(&known);
    ui.set_server_count(rows.len() as i32);
    put_model(ui.get_home(), entries, |model| ui.set_home(model));
    if status::Page::Lists.is(ui.get_page()) {
        publish_lists(ui, &rows, &groups, &subs);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HomeSnap {
    header: bool,
    section_id: String,
    title: String,
    detail: String,
    open: bool,
    has_url: bool,
    server_id: String,
    server_name: String,
    delay: String,
    tone: i32,
}

#[derive(Debug, PartialEq, Eq)]
struct RowUpdate {
    text: bool,
    name: bool,
    delay: bool,
}

enum DelayPatch {
    Reload,
    Rows(Vec<(usize, RowUpdate)>),
}

fn snap_entry(entry: &HomeEntry) -> HomeSnap {
    HomeSnap {
        header: entry.header,
        section_id: entry.section_id.as_str().to_string(),
        title: entry.title.as_str().to_string(),
        detail: entry.detail.as_str().to_string(),
        open: entry.open,
        has_url: entry.has_url,
        server_id: entry.server.id.as_str().to_string(),
        server_name: entry.server.name.as_str().to_string(),
        delay: entry.server.delay.as_str().to_string(),
        tone: entry.server.tone,
    }
}

/// Same row count, section fields, and server ids can be patched in place.
/// A different count or id needs a full reload. `delay` covers the delay string and tone.
fn delay_patch(current: &[HomeSnap], expected: &[HomeSnap]) -> DelayPatch {
    if current.len() != expected.len() {
        return DelayPatch::Reload;
    }
    let mut updates = Vec::new();
    for (index, (existing, next)) in current.iter().zip(expected).enumerate() {
        if existing.header != next.header || existing.section_id != next.section_id || existing.open != next.open || existing.has_url != next.has_url {
            return DelayPatch::Reload;
        }
        if existing.header {
            if existing.title != next.title || existing.detail != next.detail {
                updates.push((index, RowUpdate { text: true, name: false, delay: false }));
            }
            continue;
        }
        if existing.server_id != next.server_id {
            return DelayPatch::Reload;
        }
        let name = existing.server_name != next.server_name;
        let delay = existing.delay != next.delay || existing.tone != next.tone;
        let text = existing.title != next.title || existing.detail != next.detail;
        if name || delay || text {
            updates.push((index, RowUpdate { text, name, delay }));
        }
    }
    DelayPatch::Rows(updates)
}

fn apply_delay_update(existing: &mut HomeEntry, next: &HomeEntry, update: &RowUpdate) {
    if update.text {
        existing.title = next.title.clone();
        existing.detail = next.detail.clone();
    }
    if existing.header {
        return;
    }
    if update.name {
        existing.server.name = next.server.name.clone();
        existing.server.runs = next.server.runs.clone();
    }
    if update.delay {
        existing.server.delay = next.server.delay.clone();
        existing.server.tone = next.server.tone;
    }
}

fn patch_delays(ui: &MainWindow, client: &Client) -> bool {
    let Ok(rows) = client.servers(None) else {
        return false;
    };
    let Ok(groups) = client.groups() else {
        return false;
    };
    let Ok(subs) = client.subscriptions() else {
        return false;
    };
    let open = open_sections().lock().expect("sections").clone();
    let plan = planned(&subs, &groups, &rows);
    let expected = home_entries(&plan, &open, &rows, &groups);
    let current = ui.get_home();
    if current.row_count() != expected.len() {
        return false;
    }
    let Some(model) = current.as_any().downcast_ref::<VecModel<HomeEntry>>() else {
        return false;
    };
    let mut snaps = Vec::with_capacity(expected.len());
    for index in 0..expected.len() {
        let Some(row) = current.row_data(index) else {
            return false;
        };
        snaps.push(snap_entry(&row));
    }
    let wanted: Vec<HomeSnap> = expected.iter().map(snap_entry).collect();
    let DelayPatch::Rows(updates) = delay_patch(&snaps, &wanted) else {
        return false;
    };
    for (index, update) in updates {
        let Some(mut existing) = current.row_data(index) else {
            return false;
        };
        apply_delay_update(&mut existing, &expected[index], &update);
        model.set_row_data(index, existing);
    }
    true
}

pub fn finish(ui: &MainWindow, client: &Client, selected: &Mutex<String>, err: Option<rvpn_app::AppError>) {
    if !patch_delays(ui, client) {
        reload(ui, client);
    }
    sync_selection(ui, client, selected);
    apply_status(ui, client, err);
    if let Some(sub) = client.subscriptions().ok().and_then(|list| list.into_iter().next()) {
        if let Ok(text) = client.announcement(&sub.id) {
            ui.set_announce_text(text.unwrap_or_default().into());
        }
        if let Ok(text) = client.traffic(&sub.id) {
            ui.set_traffic_text(text.into());
        }
    }
}

pub fn apply_status(ui: &MainWindow, client: &Client, err: Option<rvpn_app::AppError>) {
    ui.set_disconnecting(false);
    let status = client.status();
    if status.connected {
        if let Some(id) = status.server_id.clone() {
            ui.set_live_id(id.into());
        }
        if let Some(name) = status.server_name.clone() {
            set_live_label(ui, &name);
        }
        ui.set_up_text(status::traffic_label(status.stats_known, status.upload).into());
        ui.set_down_text(status::traffic_label(status.stats_known, status.download).into());
    } else {
        ui.set_live_id(SharedString::new());
        clear_live_label(ui);
        ui.set_up_text("—".into());
        ui.set_down_text("—".into());
    }
    if let Some(err) = err {
        ui.set_status_text(err.to_string().into());
        ui.set_phase(if status.connected { status::Phase::Connected.code() } else { status::Phase::Error.code() });
        return;
    }
    if status.connected {
        ui.set_phase(status::Phase::Connected.code());
        ui.set_status_text("В сети".into());
    } else {
        ui.set_phase(status::Phase::Idle.code());
        ui.set_status_text("Не в сети".into());
    }
}

pub fn sync_selection(ui: &MainWindow, client: &Client, selected: &Mutex<String>) {
    let rows = client.servers(None).unwrap_or_default();
    let current = selected.lock().expect("selected").clone();
    let id = if !current.is_empty() && rows.iter().any(|row| row.id == current) {
        current
    } else {
        rows.first().map(|row| row.id.clone()).unwrap_or_default()
    };
    *selected.lock().expect("selected") = id.clone();
    ui.set_selected_id(id.clone().into());
    let name = rows.iter().find(|row| row.id == id).map(|row| row.name.clone()).unwrap_or_default();
    set_selected_label(ui, &name);
}

pub fn publish_log(ui: &MainWindow, client: &Client) {
    let lines = journal_lines(client);
    let text = lines.join("\n");
    if ui.get_log_text() != text {
        ui.set_log_text(text.into());
    }
    if !ui.get_log_table() {
        return;
    }
    let parsed = sorted_journal(&lines, ui.get_log_sort_column(), ui.get_log_sort_ascending());
    apply_log_rows(ui, &parsed);
}

fn apply_log_rows(ui: &MainWindow, parsed: &[logline::LogLine]) {
    let current = ui.get_log_rows();
    if current.row_count() == parsed.len() {
        if let Some(model) = current.as_any().downcast_ref::<VecModel<LogRow>>() {
            if parsed.iter().enumerate().all(|(index, row)| current.row_data(index).is_some_and(|existing| same_log_row(&existing, row))) {
                return;
            }
            for (index, row) in parsed.iter().enumerate() {
                if current.row_data(index).is_none_or(|existing| !same_log_row(&existing, row)) {
                    model.set_row_data(index, log_row(row));
                }
            }
            return;
        }
    }
    ui.set_log_rows(ModelRc::new(VecModel::from(parsed.iter().map(log_row).collect::<Vec<_>>())));
}

fn log_row(row: &logline::LogLine) -> LogRow {
    LogRow {
        stamp: row.stamp.as_str().into(),
        level: row.level.as_str().into(),
        from: row.from.as_str().into(),
        accepted: row.accepted.as_str().into(),
        route: row.route.as_str().into(),
        email: row.email.as_str().into(),
        message: row.message.as_str().into(),
    }
}

fn same_log_row(row: &LogRow, parsed: &logline::LogLine) -> bool {
    row.stamp == parsed.stamp && row.level == parsed.level && row.from == parsed.from && row.accepted == parsed.accepted && row.route == parsed.route && row.email == parsed.email && row.message == parsed.message
}

pub fn clear_live_label(ui: &MainWindow) {
    ui.set_live_name(SharedString::new());
    ui.set_live_runs(ModelRc::new(VecModel::from(Vec::new())));
}

pub fn set_live_label(ui: &MainWindow, name: &str) {
    if ui.get_live_name().as_str() == name {
        return;
    }
    ui.set_live_name(name.into());
    ui.set_live_runs(name_runs(name));
}

pub fn push_theme(ui: &MainWindow, settings: &crate::appearance::DesktopSettings) {
    restore_colors(ui, settings);
    let background = color_or(&settings.custom_background, "#070B14");
    let surface = color_or(&settings.custom_surface, "#10182C");
    let accent = color_or(&settings.custom_accent, "#8EABFF");
    ui.set_custom_bg_color(background);
    ui.set_custom_accent_color(accent);
    ui.set_custom_opacity(f32::from(settings.custom_opacity));
    ui.set_custom_surface_opacity(f32::from(settings.surface_opacity()));
    if settings.theme == crate::appearance::ThemeId::Custom {
        let background_opacity = palette::clamp_opacity(f32::from(settings.custom_opacity));
        let surface_opacity = palette::clamp_opacity(f32::from(settings.surface_opacity()));
        ui.invoke_apply_custom(
            palette::with_opacity(background, background_opacity),
            palette::with_opacity(surface, surface_opacity),
            color_or(&settings.custom_text, "#F7F9FC"),
            color_or(&settings.custom_muted, "#93A0B8"),
            accent,
            color_or(&settings.custom_on_accent, "#08101C"),
            palette::is_dark(background),
        );
        ui.set_custom_bg_color(background);
        ui.set_custom_accent_color(accent);
    } else {
        ui.invoke_apply_theme(settings.theme.as_str().into());
    }
}

fn publish_lists(ui: &MainWindow, rows: &[rvpn_app::ServerRow], groups: &[ServerGroup], subs: &[Subscription]) {
    let mut editor = group_editor().lock().expect("editor");
    if editor.as_ref().is_some_and(|id| groups.iter().all(|group| &group.id != id)) {
        *editor = None;
    }
    let editor_id = editor.clone();
    drop(editor);
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for row in rows {
        *counts.entry(row.subscription_id.as_str()).or_default() += 1;
    }
    let sub_lines = subs
        .iter()
        .filter_map(|sub| {
            let count = counts.get(sub.id.as_str()).copied().unwrap_or(0);
            let name = subscription_list_name(sub, count)?;
            Some(SubLine {
                id: sub.id.clone().into(),
                name: name.into(),
                detail: detail_label(count, sub.updated_at).into(),
                has_url: subscription_has_url(sub),
                can_delete: sub.id != LOCAL_SUBSCRIPTION_ID,
                support: sub.meta.support_url.as_deref().is_some_and(status::https_support_url),
            })
        })
        .collect();
    let known: HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    let group_lines = groups
        .iter()
        .map(|group| {
            let count = group.members.iter().filter(|id| known.contains(id.as_str())).count();
            GroupLine {
                id: group.id.clone().into(),
                name: group.name.clone().into(),
                detail: servers_label(count).into(),
                open: editor_id.as_deref() == Some(group.id.as_str()),
            }
        })
        .collect();
    if editor_id.is_none() {
        ui.set_picker_open(false);
    }
    let members = if let Some(id) = &editor_id {
        let inside: HashSet<&str> = groups.iter().find(|group| &group.id == id).map(|group| group.members.iter().map(|member| member.as_str()).collect()).unwrap_or_default();
        composition_members(rows, &inside)
    } else {
        Vec::new()
    };
    put_model(ui.get_sub_lines(), sub_lines, |model| ui.set_sub_lines(model));
    put_model(ui.get_group_lines(), group_lines, |model| ui.set_group_lines(model));
    put_model(ui.get_member_lines(), members, |model| ui.set_member_lines(model));
    publish_add_list(ui, rows, groups, &editor_id);
}

pub fn refresh_add_list(ui: &MainWindow, client: &Client) {
    let Ok(rows) = client.servers(None) else { return };
    let Ok(groups) = client.groups() else { return };
    let editor = current_editor();
    publish_add_list(ui, &rows, &groups, &editor);
}

pub fn refresh_membership(ui: &MainWindow, client: &Client) {
    let Ok(rows) = client.servers(None) else { return };
    let Ok(groups) = client.groups() else { return };
    let Some(id) = current_editor() else { return };
    let Some(group) = groups.iter().find(|group| group.id == id) else { return };
    let known: HashSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    let inside: HashSet<&str> = group.members.iter().map(|member| member.as_str()).collect();
    let count = group.members.iter().filter(|member| known.contains(member.as_str())).count();
    put_model(ui.get_member_lines(), composition_members(&rows, &inside), |model| ui.set_member_lines(model));
    publish_add_list(ui, &rows, &groups, &Some(id));
    patch_group_detail(ui, group.id.as_str(), &servers_label(count));
}

fn publish_add_list(ui: &MainWindow, rows: &[rvpn_app::ServerRow], groups: &[ServerGroup], editor_id: &Option<String>) {
    if !ui.get_picker_open() {
        put_model(ui.get_candidate_lines(), Vec::new(), |model| ui.set_candidate_lines(model));
        ui.set_add_pages(0);
        ui.set_add_empty(SharedString::new());
        return;
    }
    let Some(id) = editor_id else {
        ui.set_picker_open(false);
        return;
    };
    let inside: HashSet<&str> = groups.iter().find(|group| &group.id == id).map(|group| group.members.iter().map(|member| member.as_str()).collect()).unwrap_or_default();
    let query = add_query().lock().expect("query").clone();
    let (lines, page, pages) = add_candidates(rows, &inside, &query, ui.get_add_page().max(0) as usize, ADD_PAGE_SIZE);
    ui.set_add_page(page as i32);
    ui.set_add_pages(pages as i32);
    let empty = if !lines.is_empty() {
        ""
    } else if query.trim().is_empty() {
        "Больше нечего добавить"
    } else {
        "Ничего не найдено"
    };
    ui.set_add_empty(empty.into());
    put_model(ui.get_candidate_lines(), lines, |model| ui.set_candidate_lines(model));
}

fn patch_group_detail(ui: &MainWindow, id: &str, detail: &str) {
    let current = ui.get_group_lines();
    let Some(model) = current.as_any().downcast_ref::<VecModel<GroupLine>>() else { return };
    for index in 0..current.row_count() {
        let Some(mut row) = current.row_data(index) else { continue };
        if row.id.as_str() != id || row.detail.as_str() == detail {
            continue;
        }
        row.detail = detail.into();
        model.set_row_data(index, row);
        break;
    }
}

fn put_model<T: Clone + 'static>(current: ModelRc<T>, rows: Vec<T>, set: impl FnOnce(ModelRc<T>)) {
    if let Some(model) = current.as_any().downcast_ref::<VecModel<T>>() {
        model.set_vec(rows);
    } else {
        set(ModelRc::new(VecModel::from(rows)));
    }
}

pub fn patch_sub_name(ui: &MainWindow, id: &str, name: &str) {
    patch_model_name(ui.get_sub_lines(), id, name, |row| &mut row.name, |row| row.id.as_str());
}

pub fn patch_group_name(ui: &MainWindow, id: &str, name: &str) {
    patch_model_name(ui.get_group_lines(), id, name, |row| &mut row.name, |row| row.id.as_str());
}

fn patch_model_name<T: Clone + 'static>(current: ModelRc<T>, id: &str, name: &str, name_of: impl Fn(&mut T) -> &mut SharedString, id_of: impl Fn(&T) -> &str) {
    let Some(model) = current.as_any().downcast_ref::<VecModel<T>>() else { return };
    for index in 0..current.row_count() {
        let Some(mut row) = current.row_data(index) else { continue };
        if id_of(&row) != id || name_of(&mut row).as_str() == name {
            continue;
        }
        *name_of(&mut row) = name.into();
        model.set_row_data(index, row);
        break;
    }
}

fn set_selected_label(ui: &MainWindow, name: &str) {
    if ui.get_selected_name().as_str() == name {
        return;
    }
    ui.set_selected_name(name.into());
    ui.set_selected_runs(name_runs(name));
}

fn color_or(value: &str, fallback: &str) -> slint::Color {
    palette::parse_hex(value).or_else(|| palette::parse_hex(fallback)).map(|(_, color)| color).expect("fallback color")
}

pub fn restore_colors(ui: &MainWindow, settings: &crate::appearance::DesktopSettings) {
    assign_text(ui.get_custom_bg_text(), &settings.custom_background, |value| ui.set_custom_bg_text(value));
    assign_text(ui.get_custom_surface_text(), &settings.custom_surface, |value| ui.set_custom_surface_text(value));
    assign_text(ui.get_custom_text_text(), &settings.custom_text, |value| ui.set_custom_text_text(value));
    assign_text(ui.get_custom_muted_text(), &settings.custom_muted, |value| ui.set_custom_muted_text(value));
    assign_text(ui.get_custom_accent_text(), &settings.custom_accent, |value| ui.set_custom_accent_text(value));
    assign_text(ui.get_custom_ink_text(), &settings.custom_on_accent, |value| ui.set_custom_ink_text(value));
}

fn assign_text(current: SharedString, next: &str, set: impl FnOnce(SharedString)) {
    if current != next {
        set(next.into());
    }
}

#[cfg(test)]
mod tests {
    use super::{delay_patch, DelayPatch, HomeSnap, RowUpdate};

    fn header() -> HomeSnap {
        HomeSnap {
            header: true,
            section_id: "all".into(),
            title: "Все серверы".into(),
            detail: "1 сервер".into(),
            open: true,
            has_url: false,
            server_id: String::new(),
            server_name: String::new(),
            delay: String::new(),
            tone: 0,
        }
    }

    fn server(id: &str, delay: &str, tone: i32) -> HomeSnap {
        HomeSnap {
            header: false,
            section_id: "all".into(),
            title: String::new(),
            detail: String::new(),
            open: false,
            has_url: false,
            server_id: id.into(),
            server_name: "Example".into(),
            delay: delay.into(),
            tone,
        }
    }

    #[test]
    fn matching_ids_write_only_delay_and_tone() {
        let current = vec![header(), server("11111111-1111-4111-8111-111111111111", "—", 0)];
        let mut next = current.clone();
        next[1].delay = "42 ms".into();
        next[1].tone = 1;
        let DelayPatch::Rows(updates) = delay_patch(&current, &next) else {
            panic!("matching rows should patch in place");
        };
        assert_eq!(updates, vec![(1, RowUpdate { text: false, name: false, delay: true })]);
    }

    #[test]
    fn count_or_id_change_requires_reload() {
        let current = vec![header(), server("11111111-1111-4111-8111-111111111111", "—", 0)];
        assert!(matches!(delay_patch(&current, &[header()]), DelayPatch::Reload));
        let mut changed_id = current.clone();
        changed_id[1].server_id = "22222222-2222-4222-8222-222222222222".into();
        assert!(matches!(delay_patch(&current, &changed_id), DelayPatch::Reload));
    }
}
