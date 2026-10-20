//! Модели списков. `plan_sections` и `home_entries` считают секции, присваивание свойств Slint отдельно.

use rvpn_app::Client;
use rvpn_model::{AutoConnectType, ServerGroup, SortType, Subscription, LOCAL_SUBSCRIPTION_ID};
use slint::{Model, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use crate::{emoji, logline, palette, status, GroupLine, HomeEntry, LogRow, MainWindow, MemberLine, NameRun, ServerRow, SubLine};

mod present;
pub use present::*;

pub(crate) const SECTION_ALL: &str = "all";
pub(crate) const GROUP_PREFIX: &str = "g:";
pub(crate) const SUBSCRIPTION_PREFIX: &str = "s:";

enum SectionRef<'a> {
    All,
    Group(&'a str),
    Subscription(&'a str),
    Other,
}

fn section_ref(id: &str) -> SectionRef<'_> {
    if id == SECTION_ALL {
        SectionRef::All
    } else if let Some(rest) = id.strip_prefix(GROUP_PREFIX) {
        SectionRef::Group(rest)
    } else if let Some(rest) = id.strip_prefix(SUBSCRIPTION_PREFIX) {
        SectionRef::Subscription(rest)
    } else {
        SectionRef::Other
    }
}

thread_local! {
    static NAME_RUNS: RefCell<HashMap<String, (String, ModelRc<NameRun>)>> = RefCell::new(HashMap::new());
}

pub fn default_data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));
    base.unwrap_or_else(|| PathBuf::from(".")).join("rustvpn")
}

pub struct SectionPlan {
    pub id: String,
    pub title: String,
    pub detail: String,
    pub has_url: bool,
}

pub fn plan_sections(subs: &[Subscription], groups: &[ServerGroup], counts: &HashMap<String, usize>, known: &HashSet<String>, total: usize) -> Vec<SectionPlan> {
    let mut plan = vec![SectionPlan { id: SECTION_ALL.into(), title: "Все серверы".into(), detail: servers_label(total), has_url: false }];
    let mut groups: Vec<&ServerGroup> = groups.iter().collect();
    groups.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    for group in groups {
        let count = group.members.iter().filter(|id| known.contains(*id)).count();
        plan.push(SectionPlan { id: format!("{GROUP_PREFIX}{}", group.id), title: group.name.clone(), detail: servers_label(count), has_url: false });
    }
    let mut subs: Vec<&Subscription> = subs.iter().collect();
    subs.sort_by(|a, b| b.meta.pinned.cmp(&a.meta.pinned).then_with(|| a.name.cmp(&b.name)).then_with(|| a.id.cmp(&b.id)));
    for sub in subs {
        let count = counts.get(&sub.id).copied().unwrap_or(0);
        if sub.id == LOCAL_SUBSCRIPTION_ID && count == 0 {
            continue;
        }
        plan.push(SectionPlan {
            id: format!("{SUBSCRIPTION_PREFIX}{}", sub.id),
            title: subscription_title(sub),
            detail: detail_label(count, sub.updated_at),
            has_url: subscription_has_url(sub),
        });
    }
    plan
}

pub fn toggle_section(id: &str) {
    let mut open = open_sections().lock().expect("sections");
    if !open.remove(id) {
        open.insert(id.to_string());
    }
}

pub fn close_sections() {
    open_sections().lock().expect("sections").clear();
}

pub fn toggle_editor(id: &str) {
    let mut editor = group_editor().lock().expect("editor");
    if editor.as_deref() == Some(id) {
        *editor = None;
    } else {
        *editor = Some(id.to_string());
    }
}

pub fn close_editor() {
    *group_editor().lock().expect("editor") = None;
}

pub fn open_editor(id: &str) {
    *group_editor().lock().expect("editor") = Some(id.to_string());
}

pub fn current_editor() -> Option<String> {
    group_editor().lock().expect("editor").clone()
}

pub fn section_server_ids(client: &Client, section: &str) -> Vec<String> {
    match section_ref(section) {
        SectionRef::All => client.servers(None).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default(),
        SectionRef::Subscription(id) => client.servers(Some(id)).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default(),
        SectionRef::Group(id) => client.group_servers(id).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default(),
        SectionRef::Other => Vec::new(),
    }
}

pub fn journal_lines(client: &Client) -> Vec<String> {
    filtered_journal(client.recent_log())
}

pub fn sorted_journal(lines: &[String], column: i32, ascending: bool) -> Vec<logline::LogLine> {
    let mut rows: Vec<_> = lines.iter().map(|line| logline::parse_line(line)).collect();
    logline::sort_rows(&mut rows, column, ascending);
    rows
}

fn filtered_journal(lines: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    lines.into_iter().map(|line| line.as_ref().to_string()).filter(|line| !share_link_line(line)).collect()
}

fn share_link_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ["vless://", "vmess://", "trojan://", "ss://", "happ://"].iter().any(|scheme| lower.contains(scheme))
}

pub fn decode_qr(path: &std::path::Path) -> Result<String, String> {
    let image = image::open(path).map_err(|e| e.to_string())?.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    let grids = prepared.detect_grids();
    let grid = grids.first().ok_or_else(|| "QR-код не найден".to_string())?;
    grid.decode().map(|(_, text)| text).map_err(|_| "Не удалось прочитать QR-код".to_string())
}

fn open_sections() -> &'static Mutex<HashSet<String>> {
    static OPEN: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    OPEN.get_or_init(|| Mutex::new(HashSet::new()))
}

fn group_editor() -> &'static Mutex<Option<String>> {
    static EDITOR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    EDITOR.get_or_init(|| Mutex::new(None))
}

fn planned(subs: &[Subscription], groups: &[ServerGroup], rows: &[rvpn_app::ServerRow]) -> Vec<SectionPlan> {
    let mut counts = HashMap::new();
    for row in rows {
        *counts.entry(row.subscription_id.clone()).or_default() += 1;
    }
    let known: HashSet<String> = rows.iter().map(|row| row.id.clone()).collect();
    plan_sections(subs, groups, &counts, &known, rows.len())
}

fn home_entries(plan: &[SectionPlan], open: &HashSet<String>, rows: &[rvpn_app::ServerRow], groups: &[ServerGroup]) -> Vec<HomeEntry> {
    let mut entries = Vec::new();
    for section in plan {
        let opened = open.contains(&section.id);
        entries.push(HomeEntry {
            header: true,
            section_id: section.id.clone().into(),
            title: section.title.clone().into(),
            detail: section.detail.clone().into(),
            open: opened,
            has_url: section.has_url,
            server: blank_server(),
        });
        if opened {
            for row in rows_for(&section.id, rows, groups) {
                entries.push(HomeEntry {
                    header: false,
                    section_id: section.id.clone().into(),
                    title: SharedString::new(),
                    detail: SharedString::new(),
                    open: false,
                    has_url: false,
                    server: ServerRow {
                        id: row.id.clone().into(),
                        name: row.name.clone().into(),
                        subtitle: row.subtitle.clone().into(),
                        delay: row.delay.clone().into(),
                        tone: status::delay_tone(&row.delay),
                        runs: cached_runs(&row.id, &row.name),
                    },
                });
            }
        }
    }
    entries
}

fn rows_for<'a>(section: &str, rows: &'a [rvpn_app::ServerRow], groups: &[ServerGroup]) -> Vec<&'a rvpn_app::ServerRow> {
    match section_ref(section) {
        SectionRef::All => rows.iter().collect(),
        SectionRef::Subscription(id) => rows.iter().filter(|row| row.subscription_id == id).collect(),
        SectionRef::Group(id) => {
            let Some(group) = groups.iter().find(|group| group.id == id) else {
                return Vec::new();
            };
            let members: HashSet<&str> = group.members.iter().map(|id| id.as_str()).collect();
            rows.iter().filter(|row| members.contains(row.id.as_str())).collect()
        }
        SectionRef::Other => Vec::new(),
    }
}

const ADD_PAGE_SIZE: usize = 8;

fn add_query() -> &'static Mutex<String> {
    static QUERY: OnceLock<Mutex<String>> = OnceLock::new();
    QUERY.get_or_init(|| Mutex::new(String::new()))
}

pub fn clear_add_query() {
    *add_query().lock().expect("query") = String::new();
}

pub fn store_add_query(query: &str) {
    *add_query().lock().expect("query") = query.to_string();
}

fn composition_members(rows: &[rvpn_app::ServerRow], inside: &HashSet<&str>) -> Vec<MemberLine> {
    rows.iter()
        .filter(|row| inside.contains(row.id.as_str()))
        .map(|row| MemberLine { id: row.id.clone().into(), name: row.name.clone().into(), inside: true })
        .collect()
}

fn add_candidates(rows: &[rvpn_app::ServerRow], inside: &HashSet<&str>, query: &str, page: usize, page_size: usize) -> (Vec<MemberLine>, usize, usize) {
    let needle = query.trim().to_lowercase();
    let filtered: Vec<&rvpn_app::ServerRow> = rows
        .iter()
        .filter(|row| !inside.contains(row.id.as_str()) && (needle.is_empty() || row.name.to_lowercase().contains(&needle)))
        .collect();
    let pages = filtered.len().div_ceil(page_size.max(1)).max(1);
    let page = page.min(pages - 1);
    let lines = filtered
        .into_iter()
        .skip(page * page_size.max(1))
        .take(page_size.max(1))
        .map(|row| MemberLine { id: row.id.clone().into(), name: row.name.clone().into(), inside: false })
        .collect();
    (lines, page, pages)
}

fn blank_server() -> ServerRow {
    ServerRow { id: SharedString::new(), name: SharedString::new(), subtitle: SharedString::new(), delay: SharedString::new(), tone: 0, runs: empty_runs() }
}

fn empty_runs() -> ModelRc<NameRun> {
    thread_local! {
        static EMPTY: std::cell::OnceCell<ModelRc<NameRun>> = std::cell::OnceCell::new();
    }
    EMPTY.with(|cell| cell.get_or_init(|| ModelRc::new(VecModel::from(Vec::new()))).clone())
}

fn cached_runs(id: &str, name: &str) -> ModelRc<NameRun> {
    NAME_RUNS.with(|slot| {
        let mut cache = slot.borrow_mut();
        if let Some((cached, runs)) = cache.get(id) {
            if cached == name {
                return runs.clone();
            }
        }
        let runs = name_runs(name);
        cache.insert(id.to_string(), (name.to_string(), runs.clone()));
        runs
    })
}

fn retain_runs(known: &HashSet<String>) {
    NAME_RUNS.with(|slot| slot.borrow_mut().retain(|id, _| known.contains(id)));
}

fn subscription_list_name(sub: &Subscription, count: usize) -> Option<String> {
    if sub.id == LOCAL_SUBSCRIPTION_ID && count == 0 {
        None
    } else {
        Some(subscription_title(sub))
    }
}

fn subscription_title(sub: &Subscription) -> String {
    if sub.id == LOCAL_SUBSCRIPTION_ID && sub.name == "Server list" {
        "Локальные ссылки".into()
    } else {
        sub.name.clone()
    }
}

fn subscription_has_url(sub: &Subscription) -> bool {
    sub.url.as_deref().is_some_and(|url| !url.is_empty())
}

fn detail_label(count: usize, updated_at: Option<i64>) -> String {
    match updated_at {
        Some(ts) => format!("{} · {}", servers_label(count), stamp(ts)),
        None => servers_label(count),
    }
}

fn servers_label(count: usize) -> String {
    let word = if (11..=14).contains(&(count % 100)) {
        "серверов"
    } else {
        match count % 10 {
            1 => "сервер",
            2..=4 => "сервера",
            _ => "серверов",
        }
    };
    format!("{count} {word}")
}

fn stamp(ts: i64) -> String {
    let (year, month, day) = civil_from_days(ts.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

fn name_runs(name: &str) -> ModelRc<NameRun> {
    ModelRc::new(VecModel::from(
        emoji::name_runs(name)
            .into_iter()
            .map(|run| NameRun { text: run.text.into(), mark: run.image })
            .collect::<Vec<_>>(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{add_candidates, composition_members, filtered_journal, home_entries, plan_sections, stamp, subscription_list_name};
    use rvpn_model::{ServerGroup, Subscription, LOCAL_SUBSCRIPTION_ID};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn journal_hides_share_links_and_keeps_destinations() {
        let text = filtered_journal(["accepted tcp:1.2.3.4:443", "leak vless://secret", "HAPP://token", "plain line"]).join("\n");
        assert_eq!(text, "accepted tcp:1.2.3.4:443\nplain line");
    }

    #[test]
    fn home_sections_start_with_all_and_hide_empty_local() {
        let local = Subscription::local(1);
        let mut pinned = Subscription::local(1);
        pinned.id = "zed".into();
        pinned.name = "Zed".into();
        pinned.url = Some("https://example.invalid/sub".into());
        pinned.updated_at = Some(0);
        pinned.meta.pinned = true;
        let mut other = Subscription::local(1);
        other.id = "alpha".into();
        other.name = "Alpha".into();
        let groups = vec![
            ServerGroup { id: "m".into(), name: "M".into(), members: vec!["x".into()], created_at: 1 },
            ServerGroup { id: "a".into(), name: "A".into(), members: vec!["x".into(), "missing".into()], created_at: 1 },
        ];
        let mut counts = HashMap::new();
        counts.insert(LOCAL_SUBSCRIPTION_ID.into(), 0);
        counts.insert("zed".into(), 2);
        counts.insert("alpha".into(), 0);
        let known = HashSet::from(["x".into()]);
        let plan = plan_sections(&[local, pinned, other], &groups, &counts, &known, 2);
        let ids: Vec<_> = plan.iter().map(|section| section.id.as_str()).collect();
        assert_eq!(ids, ["all", "g:a", "g:m", "s:zed", "s:alpha"]);
        assert_eq!(plan[0].title, "Все серверы");
        assert_eq!(plan[0].detail, "2 сервера");
        assert!(plan.iter().all(|section| section.id != "s:local"));
        assert!(plan[3].has_url);
        assert_eq!(plan[3].detail, format!("2 сервера · {}", stamp(0)));
        assert_eq!(stamp(0), "1970-01-01");
        assert!(plan.iter().all(|section| !section.detail.contains("http") && !section.title.contains("example")));
        assert_eq!(plan[1].detail, "1 сервер");
        let rows = [server("x", "Германия")];
        assert_eq!(home_entries(&plan, &HashSet::new(), &rows, &groups).iter().filter(|entry| !entry.header).count(), 0);
        let mut open = HashSet::new();
        open.insert("g:a".into());
        assert_eq!(home_entries(&plan, &open, &rows, &groups).iter().filter(|entry| !entry.header).count(), 1);
        let local_named = Subscription::local(1);
        assert!(subscription_list_name(&local_named, 0).is_none());
        assert_eq!(subscription_list_name(&local_named, 2).as_deref(), Some("Локальные ссылки"));
    }

    #[test]
    fn composition_lists_members_and_add_page_searches_the_rest() {
        let rows = vec![server("a", "Германия"), server("b", "Финляндия"), server("c", "Нидерланды")];
        let inside = HashSet::from(["a"]);
        let members = composition_members(&rows, &inside);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id.as_str(), "a");
        let (page, index, pages) = add_candidates(&rows, &inside, "", 0, 8);
        assert_eq!(index, 0);
        assert_eq!(pages, 1);
        let ids: Vec<_> = page.iter().map(|line| line.id.as_str()).collect();
        assert_eq!(ids, ["b", "c"]);
        let (page, _, pages) = add_candidates(&rows, &inside, "ФИН", 0, 1);
        assert_eq!(pages, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id.as_str(), "b");
        let (first, index, pages) = add_candidates(&rows, &inside, "", 0, 1);
        assert_eq!(pages, 2);
        assert_eq!(index, 0);
        assert_eq!(first[0].id.as_str(), "b");
        let (second, index, _) = add_candidates(&rows, &inside, "", 1, 1);
        assert_eq!(index, 1);
        assert_eq!(second[0].id.as_str(), "c");
    }

    fn server(id: &str, name: &str) -> rvpn_app::ServerRow {
        rvpn_app::ServerRow { id: id.into(), subscription_id: "s".into(), name: name.into(), subtitle: String::new(), delay: String::new(), endpoint: String::new() }
    }
}
