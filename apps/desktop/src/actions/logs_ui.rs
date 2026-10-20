//! Колбэки окна: подключение, списки, настройки и журнал.

use rvpn_app::{Client, Reap, ReapReason};
use slint::{ComponentHandle, SharedString};

use crate::{status, view, MainWindow};

use super::Session;

pub(crate) fn wire_log_sort(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_sort_logs(move |column| {
        let Some(ui) = ui_handle.upgrade() else { return };
        if ui.get_log_sort_column() != column {
            ui.set_log_sort_column(column);
            ui.set_log_sort_ascending(true);
        } else if ui.get_log_sort_ascending() {
            ui.set_log_sort_ascending(false);
        } else {
            ui.set_log_sort_column(-1);
            ui.set_log_sort_ascending(true);
        }
        view::publish_log(&ui, &client);
    });
}

pub(crate) fn wire_log_table(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_open_log_table(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        view::publish_log(&ui, &client);
    });
}

pub(crate) fn wire_page(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_page_changed(move |page| {
        let Some(ui) = ui_handle.upgrade() else { return };
        let page = status::Page::from_i32(page);
        if page != Some(status::Page::Servers) {
            view::close_sections();
        }
        if page != Some(status::Page::Lists) {
            view::close_editor();
            ui.set_list_notice(SharedString::new());
            ui.set_armed_delete(SharedString::new());
            view::clear_add_query();
            ui.set_picker_open(false);
            ui.set_add_page(0);
        }
        view::reload(&ui, &client);
        if page == Some(status::Page::Logs) {
            view::publish_log(&ui, &client);
        }
    });
}

pub(crate) fn wire_timer(ui: &MainWindow, session: &Session) -> slint::Timer {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::Repeated, std::time::Duration::from_secs(2), move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let page = ui.get_page();
        client.set_stats_wanted(status::Page::Servers.is(page) || status::Page::Logs.is(page));
        if status::Page::Logs.is(page) {
            view::publish_log(&ui, &client);
        }
        if ui.get_disconnecting() || status::Phase::Connecting.is(ui.get_phase()) {
            return;
        }
        let session = client.status();
        let current = ui.get_status_text().to_string();
        let automatic = status::automatic_status(&current);
        if session.connected {
            ui.set_phase(status::Phase::Connected.code());
            if let Some(id) = session.server_id.clone() {
                ui.set_live_id(id.into());
            }
            if let Some(name) = session.server_name.clone() {
                view::set_live_label(&ui, &name);
            }
            ui.set_up_text(status::traffic_label(session.stats_known, session.upload).into());
            ui.set_down_text(status::traffic_label(session.stats_known, session.download).into());
            if automatic {
                ui.set_status_text("В сети".into());
            }
        }
        if !status::Phase::Connected.is(ui.get_phase()) {
            return;
        }
        // `reap_dead_session` joins the TUN thread, so it cannot run on this callback.
        ui.set_disconnecting(true);
        let client = client.clone();
        let ui_handle = ui_handle.clone();
        std::thread::spawn(move || {
            let outcome = client.reap_dead_session();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| apply_reap(&ui, &client, outcome));
        });
    });
    timer
}

fn apply_reap(ui: &MainWindow, client: &Client, outcome: Reap) {
    if !ui.get_disconnecting() {
        return;
    }
    ui.set_disconnecting(false);
    match outcome {
        Reap::Busy => {}
        Reap::Done(reason) => {
            let text = match reason {
                ReapReason::CoreStopped => "Ядро остановилось".to_string(),
                ReapReason::Tun(text) => text,
            };
            show_idle(ui);
            ui.set_status_text(text.into());
        }
        Reap::Unchanged => {
            if client.status().connected || !status::Phase::Connected.is(ui.get_phase()) {
                return;
            }
            let current = ui.get_status_text().to_string();
            show_idle(ui);
            if let Some(text) = status::offline_status(&current) {
                ui.set_status_text(text.into());
            }
        }
    }
}

fn show_idle(ui: &MainWindow) {
    ui.set_phase(status::Phase::Idle.code());
    ui.set_live_id(SharedString::new());
    view::clear_live_label(ui);
    ui.set_up_text("—".into());
    ui.set_down_text("—".into());
}
