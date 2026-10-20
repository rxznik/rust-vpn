use rvpn_model::OUTBOUND_PROXY;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::LOOPBACK;

const LOG_LINES: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("failed to write xray config: {0}")]
    Config(#[from] std::io::Error),
    #[error("xray exited: {0}")]
    Exited(String),
}

pub struct SpawnSpec {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub config_json: String,
    pub work_dir: PathBuf,
    pub asset_dir: Option<PathBuf>,
}

pub struct Supervisor {
    child: Option<Child>,
    log: Arc<Mutex<VecDeque<Arc<str>>>>,
    readers: Vec<JoinHandle<()>>,
    config_path: Option<PathBuf>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            child: None,
            log: Arc::new(Mutex::new(VecDeque::new())),
            readers: Vec::new(),
            config_path: None,
        }
    }

    /// Если процесс вышел сразу, запуск повторяется один раз.
    /// Пауза 250 мс в `spawn` даёт `try_wait` увидеть этот выход.
    /// `tail()` — stdout и stderr первого падения, снятые до повторного запуска.
    pub fn start(&mut self, spec: &SpawnSpec) -> Result<(), ProcessError> {
        self.stop()?;
        fs::create_dir_all(&spec.work_dir)?;
        let config_path = spec.work_dir.join("xray.json");
        write_private(&config_path, spec.config_json.as_bytes())?;
        self.config_path = Some(config_path);
        if self.spawn(spec)?.is_some() {
            let tail = self.tail();
            if self.spawn(spec)?.is_some() {
                return Err(ProcessError::Exited(tail));
            }
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), ProcessError> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        if let Some(path) = self.config_path.take() {
            let _ = fs::remove_file(path);
        }
        Ok(())
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => child.try_wait().ok().flatten().is_none(),
            None => false,
        }
    }

    pub fn recent_log(&self) -> Vec<Arc<str>> {
        self.log.lock().expect("log").iter().cloned().collect()
    }

    /// Дописывает строку в тот же кольцевой буфер, что читает журнал.
    pub fn push_log(&self, line: &str) {
        push_line(&self.log, Arc::from(line));
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    fn spawn(&mut self, spec: &SpawnSpec) -> Result<Option<std::process::ExitStatus>, ProcessError> {
        let mut command = Command::new(&spec.binary);
        command
            .args(&spec.args)
            .current_dir(&spec.work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(asset) = &spec.asset_dir {
            command.env("XRAY_LOCATION_ASSET", asset);
        }
        let mut child = command.spawn()?;
        self.attach_logs(&mut child);
        self.child = Some(child);
        thread::sleep(Duration::from_millis(250));
        let status = self.child.as_mut().and_then(|child| child.try_wait().ok().flatten());
        if status.is_some() {
            if let Some(mut child) = self.child.take() {
                let _ = child.wait();
            }
            self.join_readers();
        }
        Ok(status)
    }

    fn attach_logs(&mut self, child: &mut Child) {
        self.join_readers();
        if let Some(out) = child.stdout.take() {
            self.readers.push(spawn_reader(out, self.log.clone()));
        }
        if let Some(err) = child.stderr.take() {
            self.readers.push(spawn_reader(err, self.log.clone()));
        }
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }

    fn tail(&self) -> String {
        self.recent_log().iter().map(|line| line.as_ref()).collect::<Vec<_>>().join("\n")
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn spawn_reader<R>(reader: R, log: Arc<Mutex<VecDeque<Arc<str>>>>) -> JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        let lines = BufReader::new(reader).lines();
        for line in lines.map_while(Result::ok) {
            push_line(&log, Arc::from(line));
        }
    })
}

fn push_line(log: &Mutex<VecDeque<Arc<str>>>, line: Arc<str>) {
    let mut queue = log.lock().expect("log");
    if queue.len() == LOG_LINES {
        queue.pop_front();
    }
    queue.push_back(line);
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        if let Some(parent) = path.parent() {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    Ok(())
}

/// Порядок: `XRAY_BIN`, файл `xray` (`xray.exe` на Windows) рядом с этим процессом, затем `resources/xray` этой платформы.
pub fn locate_binary() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../resources/xray");
    let executable = std::env::current_exe().ok();
    locate_candidates(std::env::var_os("XRAY_BIN"), executable.as_deref(), &root)
}

pub fn locate_from(explicit: Option<impl AsRef<std::ffi::OsStr>>, root: &Path) -> Option<PathBuf> {
    locate_candidates(explicit, None, root)
}

fn locate_candidates(explicit: Option<impl AsRef<std::ffi::OsStr>>, executable: Option<&Path>, root: &Path) -> Option<PathBuf> {
    if let Some(path) = explicit {
        let path = PathBuf::from(path.as_ref());
        if path.is_file() {
            return Some(path);
        }
    }
    if let Some(found) = xray_beside(executable) {
        return Some(found);
    }
    let dir = resource_dir()?;
    let path = root.join(dir).join(xray_name());
    path.is_file().then_some(path)
}

fn resource_dir() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-x64")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("linux-arm64")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("macos-x64")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("macos-arm64")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("windows-x64")
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        Some("windows-arm64")
    } else if cfg!(all(target_os = "android", target_arch = "aarch64")) {
        Some("android-arm64")
    } else if cfg!(all(target_os = "android", target_arch = "x86_64")) {
        Some("android-x64")
    } else {
        None
    }
}

fn xray_name() -> &'static str {
    if cfg!(windows) { "xray.exe" } else { "xray" }
}

fn xray_beside(executable: Option<&Path>) -> Option<PathBuf> {
    let path = executable?.parent()?.join(xray_name());
    path.is_file().then_some(path)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficStats {
    pub uplink: u64,
    pub downlink: u64,
}

/// Background `xray api statsquery`. Callers read [`StatsPoller::snapshot`] instead of spawning a process.
/// Queries run 10 seconds apart. While `wanted` is false the thread sleeps and does not spawn `xray`.
pub struct StatsPoller {
    latest: Arc<Mutex<Option<TrafficStats>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl StatsPoller {
    pub fn spawn(binary: PathBuf, api_port: u16, wanted: Arc<AtomicBool>) -> Self {
        let latest = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let latest_bg = latest.clone();
        let stop_bg = stop.clone();
        let thread = thread::spawn(move || {
            while !stop_bg.load(Ordering::Relaxed) {
                if wanted.load(Ordering::Relaxed) {
                    if let Some(stats) = query_stats(&binary, api_port) {
                        *latest_bg.lock().expect("stats") = Some(stats);
                    }
                }
                for _ in 0..100 {
                    if stop_bg.load(Ordering::Relaxed) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
        Self { latest, stop, thread: Some(thread) }
    }

    pub fn snapshot(&self) -> Option<TrafficStats> {
        *self.latest.lock().expect("stats")
    }
}

impl Drop for StatsPoller {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn query_stats(binary: &Path, api_port: u16) -> Option<TrafficStats> {
    let output = Command::new(binary)
        .args(["api", "statsquery", "--server", &format!("{LOOPBACK}:{api_port}"), "-pattern", &format!("outbound>>>{OUTBOUND_PROXY}>>>traffic")])
        .output()
        .ok()?;
    if !output.status.success() && output.stdout.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_stats(&text)
}

pub fn parse_stats(text: &str) -> Option<TrafficStats> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('{') {
        return parse_stats_json(trimmed);
    }
    let mut stats = TrafficStats::default();
    let mut found = false;
    let mut pending = String::new();
    for line in text.lines() {
        let line = line.trim().trim_matches(|c: char| c == '<' || c == '>' || c == ',');
        if let Some(rest) = line.strip_prefix("name:") {
            pending = rest.trim().trim_matches('"').to_string();
        }
        let Some((name, value)) = line.split_once("value:") else {
            continue;
        };
        let name = if name.trim().is_empty() { pending.as_str() } else { name };
        let Ok(value) = value.trim().trim_end_matches(',').trim_matches('"').parse::<u64>() else {
            continue;
        };
        if apply_stat(&mut stats, name, value) {
            found = true;
        }
    }
    found.then_some(stats)
}

fn parse_stats_json(text: &str) -> Option<TrafficStats> {
    let value: Value = serde_json::from_str(text).ok()?;
    let mut stats = TrafficStats::default();
    let mut found = false;
    let items = value.get("stat").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for item in items {
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let Some(amount) = item.get("value").and_then(|v| v.as_u64()) else {
            continue;
        };
        if apply_stat(&mut stats, name, amount) {
            found = true;
        }
    }
    found.then_some(stats)
}

fn apply_stat(stats: &mut TrafficStats, name: &str, value: u64) -> bool {
    if name.contains("uplink") {
        stats.uplink = value;
        true
    } else if name.contains("downlink") {
        stats.downlink = value;
        true
    } else {
        false
    }
}

pub fn config_is_object(value: &Value) -> bool {
    value.as_object().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_candidates_chooses_xray_beside_a_fake_executable() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/xray-beside-exe");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let executable = dir.join("rustvpn");
        let xray = dir.join(xray_name());
        fs::write(&executable, b"not-a-real-binary").unwrap();
        fs::write(&xray, b"not-a-real-binary").unwrap();
        let found = locate_candidates(Some("/no/such/xray"), Some(executable.as_path()), Path::new("/missing"));
        assert_eq!(found.unwrap(), xray);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn locate_candidates_uses_only_the_host_resource_directory() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/xray-host-dir");
        let _ = fs::remove_dir_all(&root);
        let host = resource_dir().expect("host resource dir");
        let other = if host == "linux-x64" { "macos-x64" } else { "linux-x64" };
        fs::create_dir_all(root.join(other)).unwrap();
        fs::write(root.join(other).join(xray_name()), b"other").unwrap();
        assert!(locate_candidates(None::<&str>, None, &root).is_none());
        let expected = root.join(host).join(xray_name());
        fs::create_dir_all(expected.parent().unwrap()).unwrap();
        fs::write(&expected, b"host").unwrap();
        assert_eq!(locate_candidates(None::<&str>, None, &root).unwrap(), expected);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn push_log_appends_to_the_journal_buffer() {
        let supervisor = Supervisor::new();
        supervisor.push_log("Узел Hysteria2 просит отключить проверку сертификата. Проверка остаётся включённой.");
        let log = supervisor.recent_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].as_ref(), "Узел Hysteria2 просит отключить проверку сертификата. Проверка остаётся включённой.");
    }
}
