//! Колбэки окна: подключение, списки, настройки и журнал.

use rvpn_app::Client;
use rvpn_model::{SortType, LOCAL_SUBSCRIPTION_ID};
use slint::{ComponentHandle, SharedString};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::{status, view, MainWindow};

use super::Session;

pub(crate) fn wire_import(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_import_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let text = ui.get_import_text().trim().to_string();
        if text.is_empty() {
            ui.set_status_text("Вставьте ссылку".into());
            return;
        }
        ui.set_status_text("Импорт".into());
        let client = client.clone();
        let selected = selected.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let err = client.import_text(&text).err();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                ui.set_import_text(SharedString::new());
                view::finish(&ui, &client, &selected, err);
            });
        });
    });
}

pub(crate) fn wire_paste(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_paste_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let text = arboard::Clipboard::new().and_then(|mut c| c.get_text()).unwrap_or_default();
        if text.trim().is_empty() {
            ui.set_status_text("Буфер обмена пуст".into());
            return;
        }
        ui.set_import_text(text.trim().to_string().into());
        ui.set_status_text("Импорт".into());
        let text = text.trim().to_string();
        let client = client.clone();
        let selected = selected.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let err = client.import_text(&text).err();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                ui.set_import_text(SharedString::new());
                view::finish(&ui, &client, &selected, err);
            });
        });
    });
}

pub(crate) fn wire_qr(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_qr_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let Some(path) = rfd::FileDialog::new().add_filter("Image", &["png", "jpg", "jpeg"]).pick_file() else { return };
        match view::decode_qr(&path) {
            Ok(text) => {
                ui.set_status_text("Импорт".into());
                let client = client.clone();
                let selected = selected.clone();
                let ui_handle = ui.as_weak();
                std::thread::spawn(move || {
                    let err = client.import_text(&text).err();
                    let _ = ui_handle.upgrade_in_event_loop(move |ui| view::finish(&ui, &client, &selected, err));
                });
            }
            Err(err) => {
                ui.set_status_text(err.into());
            }
        }
    });
}

pub(crate) fn wire_refresh(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_refresh_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        ui.set_status_text("Обновление".into());
        let client = client.clone();
        let selected = selected.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let err = client.refresh_due(true).err();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| view::finish(&ui, &client, &selected, err));
        });
    });
}

pub(crate) fn wire_ping(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let pinging = session.pinging.clone();
    ui.on_ping_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        if pinging.swap(true, Ordering::Relaxed) {
            return;
        }
        let ids: Vec<String> = client.servers(None).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default();
        if ids.is_empty() {
            pinging.store(false, Ordering::Relaxed);
            ui.set_status_text("Нет серверов".into());
            return;
        }
        ui.set_checking(true);
        ui.set_status_text("Проверка задержки".into());
        let client = client.clone();
        let selected = selected.clone();
        let pinging = pinging.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let _ = client.ping_many(&ids);
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                pinging.store(false, Ordering::Relaxed);
                ui.set_checking(false);
                view::finish(&ui, &client, &selected, None);
            });
        });
    });
}

pub(crate) fn wire_sort(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_sort_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let mut settings = client.settings().unwrap_or_default();
        settings.sort_type = if settings.sort_type == SortType::Ping { SortType::Without } else { SortType::Ping };
        ui.set_sort_by_ping(settings.sort_type == SortType::Ping);
        let _ = client.save_settings(&settings);
        view::reload(&ui, &client);
        view::sync_selection(&ui, &client, &selected);
    });
}

pub(crate) fn wire_fastest(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let pinging = session.pinging.clone();
    ui.on_fastest_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        if pinging.swap(true, Ordering::Relaxed) {
            return;
        }
        let ids: Vec<String> = client.servers(None).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default();
        if ids.is_empty() {
            pinging.store(false, Ordering::Relaxed);
            ui.set_status_text("Нет серверов".into());
            return;
        }
        ui.set_checking(true);
        ui.set_status_text("Проверка задержки".into());
        let client = client.clone();
        let selected = selected.clone();
        let pinging = pinging.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let _ = client.ping_many(&ids);
            let picked = client.fastest_server_id().ok().flatten();
            let chosen = picked.is_some();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                pinging.store(false, Ordering::Relaxed);
                ui.set_checking(false);
                if let Some(id) = picked {
                    *selected.lock().expect("selected") = id;
                }
                view::finish(&ui, &client, &selected, None);
                if chosen {
                    ui.set_status_text("Выбран самый быстрый".into());
                }
            });
        });
    });
}

pub(crate) fn wire_select(ui: &MainWindow, session: &Session) {
    let selected = session.selected.clone();
    ui.on_select_server(move |id| {
        *selected.lock().expect("selected") = id.to_string();
    });
}

fn spawn_ping(ui: &MainWindow, client: Arc<Client>, selected: Arc<Mutex<String>>, pinging: Arc<AtomicBool>, attempt_seq: Arc<AtomicU64>, attempt_owner: Arc<AtomicU64>, ids: Vec<String>, connect: bool) {
    if pinging.swap(true, Ordering::Relaxed) {
        return;
    }
    if ids.is_empty() {
        pinging.store(false, Ordering::Relaxed);
        ui.set_status_text("Нет серверов".into());
        return;
    }
    ui.set_checking(true);
    ui.set_status_text("Проверка задержки".into());
    let ui_handle = ui.as_weak();
    std::thread::spawn(move || {
        client.cancel_ping();
        let delays = client.ping_many(&ids);
        let answered = delays.iter().filter(|(_, delay)| delay.is_some()).count();
        let reply = if connect { None } else { status::ping_reply_status(answered, ids.len()) };
        if let Ok(rows) = client.servers(None) {
            crate::emoji::warm(&rows.into_iter().map(|row| row.name).collect::<Vec<_>>());
        }
        let picked = if connect { client.lowest_delay_id(&ids).ok().flatten() } else { None };
        let _ = ui_handle.upgrade_in_event_loop(move |ui| {
            pinging.store(false, Ordering::Relaxed);
            ui.set_checking(false);
            if let Some(id) = picked.clone() {
                *selected.lock().expect("selected") = id;
            }
            view::finish(&ui, &client, &selected, None);
            if connect {
                if let Some(id) = picked {
                    super::connect::start_connect(&ui, client, selected, attempt_seq, attempt_owner, id);
                } else {
                    ui.set_status_text("Нет ответа".into());
                }
            } else if let Some(text) = reply {
                ui.set_status_text(text.into());
            }
        });
    });
}

fn spawn_refresh(ui: &MainWindow, client: Arc<Client>, selected: Arc<Mutex<String>>, id: String) {
    ui.set_status_text("Обновление".into());
    let ui_handle = ui.as_weak();
    std::thread::spawn(move || {
        let err = client.refresh(&id).err();
        let _ = ui_handle.upgrade_in_event_loop(move |ui| view::finish(&ui, &client, &selected, err));
    });
}

pub(crate) fn wire_sections(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_section_toggled(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        view::toggle_section(&id);
        view::reload(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let pinging = session.pinging.clone();
    let attempt_seq = session.attempt_seq.clone();
    let attempt_owner = session.attempt_owner.clone();
    ui.on_section_ping(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let ids = view::section_server_ids(&client, &id);
        spawn_ping(&ui, client.clone(), selected.clone(), pinging.clone(), attempt_seq.clone(), attempt_owner.clone(), ids, false);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let pinging = session.pinging.clone();
    let attempt_seq = session.attempt_seq.clone();
    let attempt_owner = session.attempt_owner.clone();
    ui.on_section_fastest(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let ids = view::section_server_ids(&client, &id);
        spawn_ping(&ui, client.clone(), selected.clone(), pinging.clone(), attempt_seq.clone(), attempt_owner.clone(), ids, true);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_section_refresh(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let Some(id) = id.strip_prefix(view::SUBSCRIPTION_PREFIX) else { return };
        spawn_refresh(&ui, client.clone(), selected.clone(), id.to_string());
    });
}

pub(crate) fn wire_lists(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_sub_refresh(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        spawn_refresh(&ui, client.clone(), selected.clone(), id.to_string());
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let pinging = session.pinging.clone();
    let attempt_seq = session.attempt_seq.clone();
    let attempt_owner = session.attempt_owner.clone();
    ui.on_sub_ping(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let ids = client.servers(Some(&id)).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default();
        spawn_ping(&ui, client.clone(), selected.clone(), pinging.clone(), attempt_seq.clone(), attempt_owner.clone(), ids, false);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let pinging = session.pinging.clone();
    let attempt_seq = session.attempt_seq.clone();
    let attempt_owner = session.attempt_owner.clone();
    ui.on_sub_fastest(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let ids = client.servers(Some(&id)).map(|rows| rows.into_iter().map(|row| row.id).collect()).unwrap_or_default();
        spawn_ping(&ui, client.clone(), selected.clone(), pinging.clone(), attempt_seq.clone(), attempt_owner.clone(), ids, true);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_sub_rename(move |id, name| {
        let ui_handle = ui_handle.clone();
        let client = client.clone();
        let id = id.to_string();
        let name = name.to_string();
        schedule_rename(format!("sub:{id}"), move || {
            let Some(ui) = ui_handle.upgrade() else { return };
            if let Err(err) = client.rename_subscription(&id, &name) {
                list_note(&ui, &err.to_string(), true);
            } else {
                list_note(&ui, "", false);
                view::patch_sub_name(&ui, &id, name.trim());
            }
        });
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_sub_delete(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        if id == LOCAL_SUBSCRIPTION_ID {
            return;
        }
        let key = format!("{}{id}", view::SUBSCRIPTION_PREFIX);
        if ui.get_armed_delete().as_str() != key {
            ui.set_armed_delete(key.into());
            list_note(&ui, "Нажмите «Удалить» ещё раз", true);
            return;
        }
        ui.set_armed_delete(SharedString::new());
        if let Err(err) = client.delete_subscription(&id) {
            list_note(&ui, &err.to_string(), true);
        } else {
            list_note(&ui, "Подписка удалена", false);
        }
        view::reload(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_sub_support(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        match client.subscriptions().ok().and_then(|list| list.into_iter().find(|sub| sub.id == id.as_str()).and_then(|sub| sub.meta.support_url)) {
            Some(url) if status::https_support_url(&url) => {
                let _ = open::that(url);
            }
            Some(_) => ui.set_status_text("Ссылка поддержки должна быть https".into()),
            None => ui.set_status_text("У подписки нет ссылки поддержки".into()),
        }
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_group_create(move |name| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let name = name.trim();
        if name.is_empty() {
            list_note(&ui, "Введите имя группы", true);
            return;
        }
        match client.create_group(name) {
            Ok(id) => {
                ui.set_draft_token(ui.get_draft_token() + 1);
                view::clear_add_query();
                ui.set_picker_open(false);
                view::open_editor(&id);
                list_note(&ui, "Группа создана", false);
            }
            Err(err) => list_note(&ui, &err.to_string(), true),
        }
        view::reload(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_group_rename(move |id, name| {
        let ui_handle = ui_handle.clone();
        let client = client.clone();
        let id = id.to_string();
        let name = name.to_string();
        schedule_rename(format!("group:{id}"), move || {
            let Some(ui) = ui_handle.upgrade() else { return };
            if let Err(err) = client.rename_group(&id, &name) {
                list_note(&ui, &err.to_string(), true);
            } else {
                list_note(&ui, "", false);
                view::patch_group_name(&ui, &id, name.trim());
            }
        });
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_group_delete(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        if view::current_editor().as_deref() == Some(id.as_str()) {
            view::close_editor();
            view::clear_add_query();
            ui.set_picker_open(false);
        }
        if let Err(err) = client.delete_group(&id) {
            list_note(&ui, &err.to_string(), true);
        } else {
            list_note(&ui, "Группа удалена", false);
        }
        view::reload(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_group_toggle(move |id| {
        let Some(ui) = ui_handle.upgrade() else { return };
        view::toggle_editor(&id);
        view::clear_add_query();
        ui.set_picker_open(false);
        ui.set_add_page(0);
        view::reload(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_member_set(move |id, inside| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let Some(group) = view::current_editor() else { return };
        let result = if inside { client.add_group_member(&group, &id) } else { client.remove_group_member(&group, &id) };
        if let Err(err) = result {
            list_note(&ui, &err.to_string(), true);
        }
        view::refresh_membership(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_member_filter(move |query| {
        let Some(ui) = ui_handle.upgrade() else { return };
        view::store_add_query(&query);
        ui.set_add_page(0);
        view::refresh_add_list(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_picker_toggle(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let open = !ui.get_picker_open();
        view::clear_add_query();
        ui.set_add_page(0);
        ui.set_picker_open(open);
        view::refresh_add_list(&ui, &client);
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_add_step(move |delta| {
        let Some(ui) = ui_handle.upgrade() else { return };
        ui.set_add_page((ui.get_add_page() + delta).max(0));
        view::refresh_add_list(&ui, &client);
    });
}

fn list_note(ui: &MainWindow, text: &str, bad: bool) {
    ui.set_list_notice(text.into());
    ui.set_list_notice_bad(bad);
}

const RENAME_QUIET: Duration = Duration::from_millis(400);

struct QuietRename {
    timer: slint::Timer,
    generation: u64,
}

thread_local! {
    static RENAME_QUIET_TIMERS: RefCell<HashMap<String, QuietRename>> = RefCell::new(HashMap::new());
}

fn schedule_rename(key: String, write: impl FnOnce() + 'static) {
    RENAME_QUIET_TIMERS.with(|timers| {
        let mut timers = timers.borrow_mut();
        let slot = timers.entry(key.clone()).or_insert_with(|| QuietRename { timer: slint::Timer::default(), generation: 0 });
        slot.generation = slot.generation.wrapping_add(1);
        let generation = slot.generation;
        let mut write = Some(write);
        slot.timer.start(slint::TimerMode::SingleShot, RENAME_QUIET, move || {
            let still = RENAME_QUIET_TIMERS.with(|timers| timers.borrow().get(&key).is_some_and(|slot| slot.generation == generation));
            if !still {
                return;
            }
            if let Some(write) = write.take() {
                write();
            }
        });
    });
}
