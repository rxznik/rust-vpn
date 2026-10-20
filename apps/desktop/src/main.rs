//! Окно rustvpn на Slint.
//!
//! Каталог данных: $XDG_DATA_HOME/rustvpn или ~/.local/share/rustvpn.
//! Сеть, Xray и SQLite вызываются через rvpn_app::Client.
//! Пинг и connect стартуют в отдельном потоке.
//! Таймер статуса на потоке UI читает снимок статистики.

use rvpn_app::Client;
use rvpn_platform::HostPlatform;
use std::sync::{Arc, Mutex};

slint::include_modules!();

mod actions;
mod appearance;
mod emoji;
mod logline;
mod palette;
mod status;
mod view;

fn main() {
    let data_dir = view::default_data_dir();
    let client = Arc::new(Client::open(data_dir.clone(), Arc::new(HostPlatform::new(data_dir))).expect("open database"));
    install_exit_signals(client.clone());
    let client_bg = client.clone();
    std::thread::spawn(move || {
        let _ = client_bg.refresh_due(true);
        let _ = client_bg.autoconnect();
    });

    let ui = MainWindow::new().expect("window");
    let selected = Arc::new(Mutex::new(String::new()));
    view::load(&ui, &client, &selected);
    let timer = actions::bind(&ui, client.clone(), selected);
    ui.run().expect("run");
    drop(timer);
    client.shutdown();
}

/// Блокирует SIGINT и SIGTERM до остальных потоков. Обычный поток ждёт их через `sigwait` и вызывает `shutdown`.
#[cfg(unix)]
fn install_exit_signals(client: Arc<Client>) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&mut set) != 0 {
            return;
        }
        if libc::sigaddset(&mut set, libc::SIGINT) != 0 || libc::sigaddset(&mut set, libc::SIGTERM) != 0 {
            return;
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return;
        }
    }
    std::thread::spawn(move || {
        let mut sig = 0;
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut set) != 0 {
                return;
            }
            if libc::sigaddset(&mut set, libc::SIGINT) != 0 || libc::sigaddset(&mut set, libc::SIGTERM) != 0 {
                return;
            }
            if libc::sigwait(&set, &mut sig) != 0 {
                return;
            }
        }
        client.shutdown();
        std::process::exit(128 + sig);
    });
}

#[cfg(not(unix))]
fn install_exit_signals(_client: Arc<Client>) {}
