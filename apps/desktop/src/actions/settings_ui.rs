//! Колбэки окна: подключение, списки, настройки и журнал.

use rvpn_app::Client;
use rvpn_model::{font_family_name, font_size_step, nearest_zoom, step_zoom};
use slint::winit_030::{winit, EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, SharedString};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use crate::{logline, palette, status, view, MainWindow};

use super::{ScaleState, Session};

pub(crate) fn wire_type(ui: &MainWindow, session: &Session, scale: &ScaleState) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_font_size_picked(move |size| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let size = font_size_step(size as u8);
        crate::appearance::edit(&client, |settings| settings.font_size = size);
        ui.set_font_size(i32::from(size));
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_font_family_edited(move |name| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let Some(clean) = font_family_name(&name) else {
            ui.set_status_text("Неверное имя шрифта".into());
            ui.set_font_family(crate::appearance::load(&client).font_family.into());
            return;
        };
        crate::appearance::edit(&client, |settings| settings.font_family = clean.clone());
        ui.set_font_family(clean.into());
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_font_file_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Шрифт", &["ttf", "otf", "ttc"])
            .pick_file()
        else {
            return;
        };
        match view::install_font(client.data_dir(), &path) {
            Ok((stored, family)) => {
                let family_saved = family.clone();
                crate::appearance::edit(&client, |settings| {
                    settings.font_path = Some(stored);
                    settings.font_family = family_saved;
                });
                ui.set_font_family(family.into());
            }
            Err(message) => ui.set_status_text(message.into()),
        }
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_font_reset_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        crate::appearance::edit(&client, |settings| {
            settings.font_family.clear();
            settings.font_path = None;
        });
        ui.set_font_family(SharedString::new());
    });

    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let scale_zoom = scale.zoom.clone();
    let scale_os = scale.os.clone();
    ui.on_zoom_picked(move |percent| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        store_zoom(
            &ui,
            &client,
            &scale_os,
            &scale_zoom,
            nearest_zoom(percent as u16),
        );
    });
}

pub(crate) fn wire_scale(ui: &MainWindow, session: &Session, scale: &ScaleState) {
    apply_scale(
        ui.window(),
        scale.os.load(Ordering::Relaxed),
        scale.zoom.load(Ordering::Relaxed),
    );
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    let os = scale.os.clone();
    let zoom = scale.zoom.clone();
    let mods = scale.mods.clone();
    ui.window()
        .on_winit_window_event(move |window, event| match event {
            winit::event::WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                os.store((*scale_factor as f32).to_bits(), Ordering::Relaxed);
                let factor = *scale_factor as f32 * f32::from(zoom.load(Ordering::Relaxed)) / 100.0;
                window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
                    scale_factor: factor,
                });
                EventResult::PreventDefault
            }
            winit::event::WindowEvent::ModifiersChanged(modifiers) => {
                let state = modifiers.state();
                let mut bits = 0u8;
                if state.control_key() {
                    bits |= 1;
                }
                if state.alt_key() {
                    bits |= 2;
                }
                if state.super_key() {
                    bits |= 4;
                }
                mods.store(bits, Ordering::Relaxed);
                EventResult::Propagate
            }
            winit::event::WindowEvent::KeyboardInput {
                event,
                is_synthetic,
                ..
            } if !is_synthetic && event.state == winit::event::ElementState::Pressed => {
                let bits = mods.load(Ordering::Relaxed);
                let zoom_key = match &event.logical_key {
                    winit::keyboard::Key::Character(text) if text == "+" || text == "=" => {
                        Some(true)
                    }
                    winit::keyboard::Key::Character(text) if text == "-" || text == "−" => {
                        Some(false)
                    }
                    _ => None,
                };
                if (bits & 1) == 0 || (bits & 6) != 0 {
                    return EventResult::Propagate;
                }
                let Some(up) = zoom_key else {
                    return EventResult::Propagate;
                };
                let Some(ui) = ui_handle.upgrade() else {
                    return EventResult::Propagate;
                };
                let next = step_zoom(zoom.load(Ordering::Relaxed), up);
                store_zoom(&ui, &client, &os, &zoom, next);
                EventResult::PreventDefault
            }
            _ => EventResult::Propagate,
        });
}

fn store_zoom(ui: &MainWindow, client: &Client, os: &AtomicU32, zoom: &AtomicU16, percent: u16) {
    zoom.store(percent, Ordering::Relaxed);
    crate::appearance::edit(client, |settings| settings.ui_zoom = percent);
    ui.set_ui_zoom(i32::from(percent));
    apply_scale(ui.window(), os.load(Ordering::Relaxed), percent);
}

fn apply_scale(window: &slint::Window, os_bits: u32, zoom: u16) {
    let os = f32::from_bits(os_bits);
    if !os.is_finite() || os <= 0.0 {
        return;
    }
    window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
        scale_factor: os * f32::from(zoom) / 100.0,
    });
}

pub(crate) fn wire_theme(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_theme_picked(move |id| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let settings = crate::appearance::edit(&client, |settings| settings.theme = crate::appearance::ThemeId::parse(id.as_str()));
        if settings.theme == crate::appearance::ThemeId::Custom {
            view::push_theme(&ui, &settings);
        }
    });
}

pub(crate) fn wire_density(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_density_picked(move |mode| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let settings = crate::appearance::edit(&client, |settings| {
            settings.toolbar_density = crate::appearance::Density::parse(mode.as_str());
        });
        ui.set_labeled(settings.toolbar_density == crate::appearance::Density::Standard);
    });
}

pub(crate) fn wire_motion(ui: &MainWindow, session: &Session) {
    let client = session.client.clone();
    ui.on_animations_picked(move |on| {
        crate::appearance::edit(&client, |settings| settings.animations = on);
    });
}

pub(crate) fn wire_clear(ui: &MainWindow, session: &Session) {
    let client = session.client.clone();
    ui.on_clear_picked(move |on| {
        crate::appearance::edit(&client, |settings| settings.clear_background = on);
    });
}

pub(crate) fn wire_tun(ui: &MainWindow, session: &Session) {
    let client = session.client.clone();
    ui.on_tun_picked(move |on| {
        let mut settings = client.settings().unwrap_or_default();
        settings.tun_enable = on;
        let _ = client.save_settings(&settings);
    });
}

pub(crate) fn wire_proxy(ui: &MainWindow, session: &Session) {
    let client = session.client.clone();
    ui.on_proxy_picked(move |on| {
        let mut settings = client.settings().unwrap_or_default();
        settings.proxy_enable = on;
        let _ = client.save_settings(&settings);
    });
}

pub(crate) fn wire_background_opacity(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_background_opacity_changed(move |value| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let settings = crate::appearance::edit(&client, |settings| {
            settings.custom_opacity = palette::clamp_opacity(value);
            settings.theme = crate::appearance::ThemeId::Custom;
        });
        ui.set_custom_opacity(f32::from(settings.custom_opacity));
        view::push_theme(&ui, &settings);
    });
}

pub(crate) fn wire_surface_opacity(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_surface_opacity_changed(move |value| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let settings = crate::appearance::edit(&client, |settings| {
            settings.custom_surface_opacity = Some(palette::clamp_opacity(value));
            settings.theme = crate::appearance::ThemeId::Custom;
        });
        ui.set_custom_surface_opacity(f32::from(settings.surface_opacity()));
        view::push_theme(&ui, &settings);
    });
}

pub(crate) fn wire_custom_color(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_custom_edited(move |role, value| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let trimmed = value.trim();
        if trimmed.len() < 7 {
            return;
        }
        let Some((norm, _)) = palette::parse_hex(trimmed) else {
            ui.set_status_text("Неверный цвет".into());
            view::restore_colors(&ui, &crate::appearance::load(&client));
            return;
        };
        let settings = crate::appearance::edit(&client, |settings| {
            match palette::ColorSlot::parse(role.as_str()) {
                Some(palette::ColorSlot::Background) => settings.custom_background = norm,
                Some(palette::ColorSlot::Surface) => settings.custom_surface = norm,
                Some(palette::ColorSlot::Text) => settings.custom_text = norm,
                Some(palette::ColorSlot::Muted) => settings.custom_muted = norm,
                Some(palette::ColorSlot::Accent) => settings.custom_accent = norm,
                Some(palette::ColorSlot::Ink) => settings.custom_on_accent = norm,
                None => return,
            }
            settings.theme = crate::appearance::ThemeId::Custom;
        });
        view::push_theme(&ui, &settings);
    });
}

pub(crate) fn wire_save(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_save_settings(move || {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let mut settings = client.settings().unwrap_or_default();
        settings.tun_enable = ui.get_tun_enabled();
        settings.proxy_enable = ui.get_proxy_enabled();
        if let Ok(port) = ui.get_socks_port().parse::<u16>() {
            if port == 0 {
                ui.set_status_text("Порт SOCKS должен быть от 1 до 65535".into());
                return;
            }
            settings.socks_port = port;
        } else {
            ui.set_status_text("Порт SOCKS должен быть от 1 до 65535".into());
            return;
        }
        let err = client.save_settings(&settings).err();
        if let Some(err) = err {
            ui.set_status_text(err.to_string().into());
        } else if !status::Phase::Connected.is(ui.get_phase()) && !status::Phase::Connecting.is(ui.get_phase()) {
            ui.set_status_text("Сохранено".into());
        }
    });
}

pub(crate) fn wire_support(ui: &MainWindow, session: &Session) {
    let client = session.client.clone();
    let ui_handle = ui.as_weak();
    ui.on_support_clicked(move || {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        match client
            .subscriptions()
            .ok()
            .and_then(|list| list.into_iter().find_map(|sub| sub.meta.support_url))
        {
            Some(url) if status::https_support_url(&url) => {
                let _ = open::that(url);
            }
            Some(_) => ui.set_status_text("Ссылка поддержки должна быть https".into()),
            None => ui.set_status_text("У подписки нет ссылки поддержки".into()),
        }
    });
}

pub(crate) fn wire_export(ui: &MainWindow, session: &Session) {
    let ui_handle = ui.as_weak();
    let client = session.client.clone();
    ui.on_export_logs(move |table| {
        let Some(ui) = ui_handle.upgrade() else {
            return;
        };
        let lines = view::journal_lines(&client);
        let (filter_name, extension, file_name, body) = if table {
            let rows = view::sorted_journal(
                &lines,
                ui.get_log_sort_column(),
                ui.get_log_sort_ascending(),
            );
            ("CSV", "csv", "rustvpn-log.csv", logline::to_csv(&rows))
        } else {
            let mut text = lines.join("\n");
            if !text.is_empty() {
                text.push('\n');
            }
            ("Text", "txt", "rustvpn-log.txt", text)
        };
        let Some(path) = rfd::FileDialog::new()
            .add_filter(filter_name, &[extension])
            .set_file_name(file_name)
            .save_file()
        else {
            return;
        };
        if std::fs::write(&path, body).is_err() {
            ui.set_status_text("Не удалось сохранить журнал".into());
        }
    });
}
