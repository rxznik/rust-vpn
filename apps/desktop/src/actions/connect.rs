//! Колбэки окна: подключение, списки, настройки и журнал.

use rvpn_app::Client;
use rvpn_model::AutoConnectType;
use slint::{ComponentHandle, SharedString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::{status, view, MainWindow};

use super::Session;

pub(crate) fn wire_fastest_launch(ui: &MainWindow, session: &Session) {
    let client = session.client.clone();
    ui.on_fastest_launch(move |on| {
        let mut settings = client.settings().unwrap_or_default();
        if on {
            settings.autoconnect = true;
            settings.autoconnect_type = AutoConnectType::LowestDelay;
        } else if settings.autoconnect_type == AutoConnectType::LowestDelay {
            settings.autoconnect = false;
        }
        let _ = client.save_settings(&settings);
    });
}

pub(crate) fn wire_connect(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    let attempt_owner = session.attempt_owner.clone();
    let attempt_seq = session.attempt_seq.clone();
    ui.on_connect_selected(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        let id = selected.lock().expect("selected").clone();
        start_connect(&ui, client.clone(), selected.clone(), attempt_seq.clone(), attempt_owner.clone(), id);
    });
}

pub(crate) fn start_connect(ui: &MainWindow, client: Arc<Client>, selected: Arc<Mutex<String>>, attempt_seq: Arc<AtomicU64>, attempt_owner: Arc<AtomicU64>, id: String) {
    if id.is_empty() {
        ui.set_phase(status::Phase::Idle.code());
        ui.set_status_text("Выберите сервер".into());
        return;
    }
    *selected.lock().expect("selected") = id.clone();
    let gen = attempt_seq.fetch_add(1, Ordering::Relaxed) + 1;
    attempt_owner.store(gen, Ordering::Relaxed);
    ui.set_phase(status::Phase::Connecting.code());
    ui.set_status_text("Подключение".into());
    let ui_handle = ui.as_weak();
    std::thread::spawn(move || {
        let err = client.connect(&id).err();
        if attempt_owner.load(Ordering::Relaxed) != gen {
            if attempt_owner.load(Ordering::Relaxed) == 0 {
                let _ = client.disconnect();
            }
            return;
        }
        let attempt_owner = Arc::clone(&attempt_owner);
        let _ = ui_handle.upgrade_in_event_loop(move |ui| {
            let owner = attempt_owner.load(Ordering::Relaxed);
            if owner != gen {
                if owner == 0 {
                    let _ = client.disconnect();
                }
                return;
            }
            view::finish(&ui, &client, &selected, err);
        });
    });
}

pub(crate) fn wire_cancel(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let attempt_owner = session.attempt_owner.clone();
    ui.on_cancel_connect(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        attempt_owner.store(0, Ordering::Relaxed);
        ui.set_phase(status::Phase::Idle.code());
        ui.set_disconnecting(true);
        ui.set_status_text("Отменено".into());
        ui.set_up_text("—".into());
        ui.set_down_text("—".into());
        let client = client.clone();
        let attempt_owner = attempt_owner.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let _ = client.disconnect();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                ui.set_disconnecting(false);
                if attempt_owner.load(Ordering::Relaxed) == 0 {
                    ui.set_phase(status::Phase::Idle.code());
                    ui.set_live_id(SharedString::new());
                    view::clear_live_label(&ui);
                    ui.set_up_text("—".into());
                    ui.set_down_text("—".into());
                    ui.set_status_text("Отменено".into());
                }
            });
        });
    });
}

pub(crate) fn wire_disconnect(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let selected = session.selected.clone();
    ui.on_disconnect(move || {
        let Some(ui) = ui_handle.upgrade() else { return };
        ui.set_disconnecting(true);
        ui.set_status_text("Отключение".into());
        let client = client.clone();
        let selected = selected.clone();
        let ui_handle = ui.as_weak();
        std::thread::spawn(move || {
            let err = client.disconnect().err();
            let _ = ui_handle.upgrade_in_event_loop(move |ui| {
                ui.set_disconnecting(false);
                view::finish(&ui, &client, &selected, err);
            });
        });
    });
}
