//! Колбэки окна: подключение, списки, настройки и журнал.

use rvpn_app::Client;
use rvpn_model::nearest_zoom;
use slint::ComponentHandle;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8};
use std::sync::{Arc, Mutex};

use crate::MainWindow;

struct Session {
    client: Arc<Client>,
    selected: Arc<Mutex<String>>,
    pinging: Arc<AtomicBool>,
    attempt_seq: Arc<AtomicU64>,
    attempt_owner: Arc<AtomicU64>,
}

struct ScaleState {
    os: Arc<AtomicU32>,
    zoom: Arc<AtomicU16>,
    mods: Arc<AtomicU8>,
}

mod connect;
mod lists;
mod logs_ui;
mod settings_ui;

pub fn bind(ui: &MainWindow, client: Arc<Client>, selected: Arc<Mutex<String>>) -> slint::Timer {
    let session = Session {
        client,
        selected,
        pinging: Arc::new(AtomicBool::new(false)),
        attempt_seq: Arc::new(AtomicU64::new(0)),
        attempt_owner: Arc::new(AtomicU64::new(0)),
    };
    let scale = ScaleState {
        os: Arc::new(AtomicU32::new(ui.window().scale_factor().to_bits())),
        zoom: Arc::new(AtomicU16::new(nearest_zoom(
            crate::appearance::load(&session.client).ui_zoom,
        ))),
        mods: Arc::new(AtomicU8::new(0)),
    };
    lists::wire_import(ui, &session);
    lists::wire_paste(ui, &session);
    lists::wire_qr(ui, &session);
    lists::wire_refresh(ui, &session);
    lists::wire_ping(ui, &session);
    lists::wire_sort(ui, &session);
    lists::wire_fastest(ui, &session);
    lists::wire_sections(ui, &session);
    lists::wire_lists(ui, &session);
    connect::wire_fastest_launch(ui, &session);
    settings_ui::wire_theme(ui, &session);
    settings_ui::wire_density(ui, &session);
    settings_ui::wire_motion(ui, &session);
    settings_ui::wire_clear(ui, &session);
    settings_ui::wire_tun(ui, &session);
    settings_ui::wire_proxy(ui, &session);
    settings_ui::wire_background_opacity(ui, &session);
    settings_ui::wire_surface_opacity(ui, &session);
    settings_ui::wire_custom_color(ui, &session);
    lists::wire_select(ui, &session);
    connect::wire_connect(ui, &session);
    connect::wire_cancel(ui, &session);
    connect::wire_disconnect(ui, &session);
    settings_ui::wire_save(ui, &session);
    settings_ui::wire_support(ui, &session);
    logs_ui::wire_page(ui, &session);
    settings_ui::wire_export(ui, &session);
    logs_ui::wire_log_sort(ui, &session);
    logs_ui::wire_log_table(ui, &session);
    settings_ui::wire_type(ui, &session, &scale);
    settings_ui::wire_scale(ui, &session, &scale);
    logs_ui::wire_timer(ui, &session)
}
