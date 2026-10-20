//! Мост TUN → локальный SOCKS через tun2proxy.
//!
//! Desktop и Android вызывают `start`. Android передаёт `tun_fd`.
//! iOS вызывает `start_bridge`: он читает и пишет сырые IP-пакеты.
//! `setup_routes` действует, только когда интерфейс создаёт сам tun2proxy.
//! Очередь в сторону ОС вытесняет самый старый пакет, когда в ней больше `PACKET_QUEUE`.
//! Очередь от ОС делает то же самое.
//! `local_bypasses` перечисляет частные сети и loopback.
//! Runtime tokio создаётся внутри рабочего потока и живёт вместе с сессией.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun2proxy::{general_run_async, Args, ArgDns, CancellationToken, LevelFilter, ProxyParameters};

const PACKET_QUEUE: usize = 256;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TunError(pub String);

/// Arguments for one TUN session. `tun_fd` is used on Unix; other targets ignore it.
pub struct TunOptions {
    pub socks: SocketAddr,
    pub username: String,
    pub password: String,
    pub mtu: u16,
    pub bypass: Vec<String>,
    pub tun_fd: Option<i32>,
    pub setup_routes: bool,
    pub dns: String,
}

/// Running bridge. [`TunHandle::take_error`] receives the string from `general_run_async` or `tun2proxy::run`.
pub struct TunHandle {
    token: CancellationToken,
    thread: Option<JoinHandle<()>>,
    errors: Receiver<String>,
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

impl TunHandle {
    pub fn stop(&mut self) {
        self.token.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Latest error published by the worker, if the bridge has already failed.
    pub fn take_error(&self) -> Option<String> {
        self.errors.try_recv().ok()
    }
}

/// Starts tun2proxy on a private multi-thread runtime. A worker failure is sent to [`TunHandle::take_error`].
pub fn start(options: TunOptions) -> Result<TunHandle, TunError> {
    let args = build_args(&options)?;
    let mtu = options.mtu;
    let token = CancellationToken::new();
    let shutdown = token.clone();
    let (tx, errors) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio");
        runtime.block_on(async move {
            if let Err(err) = general_run_async(args, mtu, false, shutdown).await {
                let _ = tx.send(err.to_string());
            }
        });
    });
    Ok(TunHandle { token, thread: Some(thread), errors })
}

/// Queue of IP packets exchanged with a platform that has no tun file descriptor.
///
/// `pop_to_os_wait` blocks until a packet arrives or the timeout elapses. The queue toward the OS
/// drops the oldest packet once it holds more than [`PACKET_QUEUE`]. `push_from_os` keeps the
/// queue from the OS the same way.
pub struct PacketPump {
    inbound_tx: tokio::sync::mpsc::Sender<()>,
    inbound_q: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound: Mutex<VecDeque<Vec<u8>>>,
    ready: Condvar,
}

pub struct BridgeParts {
    pub pump: Arc<PacketPump>,
    inbound_rx: tokio::sync::mpsc::Receiver<()>,
    outbound_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl BridgeParts {
    pub fn create() -> Self {
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(1);
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel();
        let pump = Arc::new(PacketPump {
            inbound_tx,
            inbound_q: Arc::new(Mutex::new(VecDeque::new())),
            outbound: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
        });
        let pump_bg = pump.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio");
            runtime.block_on(async move {
                let mut outbound_rx = outbound_rx;
                while let Some(packet) = outbound_rx.recv().await {
                    if let Ok(mut queue) = pump_bg.outbound.lock() {
                        if queue.len() > PACKET_QUEUE {
                            queue.pop_front();
                        }
                        queue.push_back(packet);
                    }
                    pump_bg.ready.notify_one();
                }
                pump_bg.ready.notify_all();
            });
        });
        Self { pump, inbound_rx, outbound_tx }
    }
}

impl PacketPump {
    pub fn push_from_os(&self, packet: Vec<u8>) -> Result<(), TunError> {
        if packet.is_empty() || packet.len() > 65535 {
            return Err(TunError("packet size".into()));
        }
        if self.inbound_tx.is_closed() {
            return Err(TunError("tunnel closed".into()));
        }
        if let Ok(mut queue) = self.inbound_q.lock() {
            if queue.len() > PACKET_QUEUE {
                queue.pop_front();
            }
            queue.push_back(packet);
        } else {
            return Err(TunError("tunnel closed".into()));
        }
        match self.inbound_tx.try_send(()) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => Err(TunError("tunnel closed".into())),
        }
    }

    pub fn pop_to_os(&self) -> Option<Vec<u8>> {
        self.outbound.lock().ok()?.pop_front()
    }

    /// Blocks until one packet is queued or `timeout` elapses.
    pub fn pop_to_os_wait(&self, timeout: Duration) -> Option<Vec<u8>> {
        let Ok(guard) = self.outbound.lock() else {
            return None;
        };
        if let Some(packet) = {
            let mut guard = guard;
            if guard.is_empty() {
                let (next, _) = self.ready.wait_timeout(guard, timeout).ok()?;
                guard = next;
            }
            guard.pop_front()
        } {
            return Some(packet);
        }
        None
    }
}

pub fn start_bridge(options: TunOptions, mut parts: BridgeParts) -> Result<TunHandle, TunError> {
    let args = build_args(&options)?;
    let mtu = options.mtu;
    let token = CancellationToken::new();
    let shutdown = token.clone();
    let inbound_rx = std::mem::replace(&mut parts.inbound_rx, tokio::sync::mpsc::channel(1).1);
    let inbound_q = Arc::clone(&parts.pump.inbound_q);
    let outbound_tx = parts.outbound_tx.clone();
    let (tx, errors) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio");
        runtime.block_on(async move {
            let device = IpDevice { inbound: inbound_rx, inbound_q, pending_in: Vec::new(), pending_in_pos: 0, outbound: outbound_tx, pending_out: Vec::new() };
            if let Err(err) = tun2proxy::run(device, mtu, args, shutdown).await {
                let _ = tx.send(err.to_string());
            }
        });
    });
    Ok(TunHandle { token, thread: Some(thread), errors })
}

fn build_args(options: &TunOptions) -> Result<Args, TunError> {
    let mut args = Args::default();
    let proxy = ProxyParameters::try_from(proxy_url(options).as_str()).map_err(|err| TunError(err.to_string()))?;
    args.proxy(proxy).dns(ArgDns::OverTcp).setup(options.setup_routes).verbosity(LevelFilter::Warn);
    if let Some(fd) = options.tun_fd {
        #[cfg(unix)]
        {
            args.tun_fd(Some(fd)).close_fd_on_drop(true);
        }
        #[cfg(not(unix))]
        let _ = fd;
    }
    if let Ok(ip) = options.dns.parse() {
        args.dns_addr(ip);
    }
    for cidr in &options.bypass {
        if let Ok(net) = cidr.parse() {
            args.bypass(net);
        }
    }
    Ok(args)
}

fn proxy_url(options: &TunOptions) -> String {
    if options.username.is_empty() {
        format!("socks5://{}", options.socks)
    } else {
        format!("socks5://{}:{}@{}", encode(&options.username), encode(&options.password), options.socks)
    }
}

fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

struct IpDevice {
    inbound: tokio::sync::mpsc::Receiver<()>,
    inbound_q: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pending_in: Vec<u8>,
    pending_in_pos: usize,
    outbound: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    pending_out: Vec<u8>,
}

impl AsyncRead for IpDevice {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let device = self.get_mut();
        if device.pending_in_pos >= device.pending_in.len() {
            match poll_from_os(&device.inbound_q, &mut device.inbound, cx) {
                Poll::Ready(Some(packet)) => {
                    device.pending_in = packet;
                    device.pending_in_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let available = &device.pending_in[device.pending_in_pos..];
        let n = available.len().min(buf.remaining());
        buf.put_slice(&available[..n]);
        device.pending_in_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for IpDevice {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let device = self.get_mut();
        let (packets, parsed) = append_ip_packets(&mut device.pending_out, data);
        for packet in packets {
            if device.outbound.send(packet).is_err() {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "os closed")));
            }
        }
        // A bad version or a declared length of 0 already cleared `pending_out`.
        // Accept the buffer either way so the writer does not retry bytes that were consumed.
        match parsed {
            Ok(()) | Err(()) => Poll::Ready(Ok(data.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn poll_from_os(queue: &Mutex<VecDeque<Vec<u8>>>, wake: &mut tokio::sync::mpsc::Receiver<()>, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
    loop {
        match queue.lock() {
            Ok(mut packets) => {
                if let Some(packet) = packets.pop_front() {
                    return Poll::Ready(Some(packet));
                }
            }
            Err(_) => return Poll::Ready(None),
        }
        match Pin::new(&mut *wake).poll_recv(cx) {
            Poll::Ready(Some(())) => continue,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        }
    }
}

/// Appends `data` and splits off complete IP packets.
/// A bad version byte or a declared length of 0 clears `pending` so the next write is not stuck on it.
/// Packets already split from this write are returned with that error.
fn append_ip_packets(pending: &mut Vec<u8>, data: &[u8]) -> (Vec<Vec<u8>>, Result<(), ()>) {
    pending.extend_from_slice(data);
    let mut ready = Vec::new();
    loop {
        match ip_packet_len(pending) {
            Ok(Some(len)) if len > 0 && pending.len() >= len => {
                ready.push(pending.drain(..len).collect());
            }
            Ok(Some(0)) | Err(()) => {
                pending.clear();
                return (ready, Err(()));
            }
            Ok(Some(_)) | Ok(None) => return (ready, Ok(())),
        }
    }
}

fn ip_packet_len(bytes: &[u8]) -> Result<Option<usize>, ()> {
    if bytes.is_empty() {
        return Ok(None);
    }
    match bytes[0] >> 4 {
        4 if bytes.len() >= 4 => Ok(Some(u16::from_be_bytes([bytes[2], bytes[3]]) as usize)),
        6 if bytes.len() >= 6 => Ok(Some(40 + u16::from_be_bytes([bytes[4], bytes[5]]) as usize)),
        4 | 6 => Ok(None),
        _ => Err(()),
    }
}

/// Private networks and loopback added to the TUN bypass list unless the subscription turns that off.
pub fn local_bypasses() -> Vec<String> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"].into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_length_comes_from_header() {
        let mut packet = vec![0x45, 0, 0, 32];
        packet.extend(std::iter::repeat(0).take(28));
        assert_eq!(ip_packet_len(&packet), Ok(Some(32)));
        assert_eq!(ip_packet_len(&[0x45, 0, 0]), Ok(None));
    }

    #[test]
    fn ipv6_length_includes_the_fixed_header() {
        let mut packet = vec![0x60, 0, 0, 0, 0, 8];
        packet.extend(std::iter::repeat(0).take(42));
        assert_eq!(ip_packet_len(&packet), Ok(Some(48)));
    }

    #[test]
    fn unknown_ip_version_is_invalid() {
        assert_eq!(ip_packet_len(&[0x10, 0, 0, 0]), Err(()));
    }

    #[test]
    fn bad_version_then_valid_ipv4_still_parses() {
        let mut pending = Vec::new();
        let (ready, parsed) = append_ip_packets(&mut pending, &[0x10]);
        assert!(parsed.is_err());
        assert!(ready.is_empty());
        assert!(pending.is_empty());
        let mut packet = vec![0x45, 0, 0, 20];
        packet.extend(std::iter::repeat(0).take(16));
        let (ready, parsed) = append_ip_packets(&mut pending, &packet);
        assert!(parsed.is_ok());
        assert_eq!(ready, vec![packet.clone()]);
        assert!(pending.is_empty());

        let mut with_zero = packet.clone();
        with_zero.extend_from_slice(&[0x45, 0, 0, 0]);
        let (ready, parsed) = append_ip_packets(&mut pending, &with_zero);
        assert!(parsed.is_err());
        assert_eq!(ready, vec![packet.clone()]);
        assert!(pending.is_empty());

        let (ready, parsed) = append_ip_packets(&mut pending, &[0x45, 0, 0, 0]);
        assert!(parsed.is_err());
        assert!(ready.is_empty());
        assert!(pending.is_empty());
        let (ready, parsed) = append_ip_packets(&mut pending, &packet);
        assert!(parsed.is_ok());
        assert_eq!(ready, vec![packet]);
        assert!(pending.is_empty());
    }

    #[test]
    fn inbound_queue_drops_the_oldest_past_256() {
        let parts = BridgeParts::create();
        for n in 0..300u16 {
            parts.pump.push_from_os(vec![n as u8]).unwrap();
        }
        let queue = parts.pump.inbound_q.lock().unwrap();
        assert_eq!(queue.len(), 257);
        assert!(queue.front().unwrap()[0] >= 43, "oldest packets are dropped, first byte was {}", queue.front().unwrap()[0]);
    }

    #[test]
    fn queue_drops_the_oldest_past_256_and_wait_returns_none() {
        let parts = BridgeParts::create();
        for n in 0..300u16 {
            parts.outbound_tx.send(vec![n as u8]).unwrap();
        }
        std::thread::sleep(Duration::from_millis(200));
        let first = parts.pump.pop_to_os_wait(Duration::from_secs(2)).unwrap();
        assert!(first[0] >= 43, "oldest packets are dropped, first byte was {}", first[0]);
        let mut count = 1;
        while parts.pump.pop_to_os_wait(Duration::from_millis(50)).is_some() {
            count += 1;
        }
        assert!(count <= 257, "queue length {count}");
        assert!(parts.pump.pop_to_os_wait(Duration::from_millis(20)).is_none());
    }

    #[test]
    fn push_fails_after_the_inbound_channel_closes() {
        let pump = {
            let parts = BridgeParts::create();
            parts.pump.clone()
        };
        std::thread::sleep(Duration::from_millis(30));
        assert!(pump.push_from_os(Vec::new()).is_err());
        assert!(pump.push_from_os(vec![0x45]).is_err());
    }

    #[test]
    fn socks_password_is_percent_encoded() {
        assert_eq!(encode("a b"), "a%20b");
        assert_eq!(encode("p@ss"), "p%40ss");
        assert!(local_bypasses().contains(&"10.0.0.0/8".to_string()));
        assert!(local_bypasses().contains(&"::1/128".to_string()));
    }
}
