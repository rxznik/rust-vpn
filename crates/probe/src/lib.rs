//! Проверки задержки и готовности локального SOCKS.
//!
//! `tcp_ping` измеряет `connect_timeout`.
//! `icmp_ping` разбирает вывод команды ping (`time=`, `zeit=`, `время=`, суффиксы `ms` и `мс`).
//! `proxy_ping` ходит GET или HEAD через SOCKS5. Пустой логин — без пароля, иначе username/password.
//! `tunnel_ready` для порта 443 ждёт запись handshake или alert после ClientHello.
//! `ProbeError::socks_down` отличает отказ локального порта от ответа сервера.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_ALERT: u8 = 0x15;

/// Failure of a latency or tunnel check. The UI reads [`Display`].
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// Local SOCKS port refused the connection, or reset it on loopback.
    #[error("{0}")]
    Refused(String),
    /// Connect or read exceeded the deadline.
    #[error("{0}")]
    Timeout(String),
    /// SOCKS5 CONNECT reply status byte, other than success.
    #[error("socks status {0}")]
    SocksStatus(u8),
    /// Any other failure, including a closed remote connection.
    #[error("{0}")]
    Other(String),
}

impl ProbeError {
    /// True when nothing is accepting connections on the local SOCKS port.
    pub fn socks_down(&self) -> bool {
        matches!(self, Self::Refused(_))
    }

    fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    fn from_io(err: std::io::Error) -> Self {
        let text = err.to_string();
        let lower = text.to_ascii_lowercase();
        match err.kind() {
            std::io::ErrorKind::ConnectionRefused => Self::Refused(text),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::Timeout("сервер не ответил".into()),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                if lower.contains("127.0.0.1") =>
            {
                Self::Refused(text)
            }
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => Self::Other("сервер закрыл соединение".into()),
            _ if lower.contains("connection refused")
                || (lower.contains("connection reset") && lower.contains("127.0.0.1")) =>
            {
                Self::Refused(text)
            }
            _ if lower.contains("timed out") => Self::Timeout(text),
            _ => Self::Other(text),
        }
    }
}

/// TCP connect time to `host:port`, in milliseconds.
pub fn tcp_ping(host: &str, port: u16, timeout: Duration) -> Result<u32, ProbeError> {
    let addr = resolve(host, port)?;
    let started = Instant::now();
    TcpStream::connect_timeout(&addr, timeout).map_err(ProbeError::from_io)?;
    Ok(started.elapsed().as_millis() as u32)
}

/// Round-trip parsed from one `ping` command. The command output may be English, German, or Russian.
pub fn icmp_ping(host: &str) -> Result<u32, ProbeError> {
    let output = icmp_command(host).output().map_err(ProbeError::from_io)?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_ping_ms(&text).ok_or_else(|| ProbeError::other(text.chars().take(180).collect::<String>()))
}

/// HTTP GET or HEAD through a local SOCKS5 proxy.
///
/// An empty `user` selects the method with no authentication. A non-empty `user` sends that
/// username and `pass` (RFC 1929).
pub fn proxy_ping(socks: SocketAddr, target_url: &str, head: bool, user: &str, pass: &str, timeout: Duration) -> Result<u32, ProbeError> {
    let (host, port, path) = split_http(target_url)?;
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&socks, timeout).map_err(ProbeError::from_io)?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    socks5_connect(&mut stream, &host, port, user, pass)?;
    let method = if head { "HEAD" } else { "GET" };
    let request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(ProbeError::from_io)?;
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).map_err(ProbeError::from_io)?;
    if n == 0 {
        return Err(ProbeError::other("сервер закрыл соединение"));
    }
    Ok(started.elapsed().as_millis() as u32)
}

/// Opens the target through the local SOCKS inbound and checks that a TLS or HTTP reply comes back.
///
/// For `https://` or port 443 the check writes a synthetic TLS 1.0 record containing a TLS 1.3
/// ClientHello (SNI, groups, signatures, supported versions, key share) and waits for a handshake or alert record.
/// `Err` with [`ProbeError::socks_down`] means nothing is listening on that port.
pub fn tunnel_ready(socks: SocketAddr, target_url: &str, user: &str, pass: &str, timeout: Duration) -> Result<(), ProbeError> {
    let (host, port, path) = split_http(target_url)?;
    let mut stream = TcpStream::connect_timeout(&socks, timeout).map_err(ProbeError::from_io)?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();
    socks5_connect(&mut stream, &host, port, user, pass)?;
    let https = target_url.starts_with("https://") || port == 443;
    if https {
        stream.write_all(&tls_client_hello(&host)).map_err(ProbeError::from_io)?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).map_err(ProbeError::from_io)?;
        if byte[0] != TLS_HANDSHAKE && byte[0] != TLS_ALERT {
            return Err(ProbeError::other("сервер закрыл соединение"));
        }
    } else {
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).map_err(ProbeError::from_io)?;
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).map_err(ProbeError::from_io)?;
    }
    Ok(())
}

/// Reads a millisecond value from `ping` output.
///
/// Accepts `time=`, `zeit=`, and `время=` plus a trailing `ms` or `мс`.
pub fn parse_ping_ms(text: &str) -> Option<u32> {
    for raw in text.split_whitespace() {
        let token = raw.trim_matches(['=', '<', '>', ',']).to_lowercase();
        for prefix in ["time=", "zeit=", "время="] {
            if let Some(rest) = token.strip_prefix(prefix) {
                let rest = rest.trim_end_matches("мс").trim_end_matches("ms");
                if let Ok(value) = rest.parse::<f64>() {
                    return Some(value.round() as u32);
                }
            }
        }
        let bare = token.trim_end_matches("мс").trim_end_matches("ms");
        if bare.len() != token.len() {
            if let Ok(value) = bare.parse::<f64>() {
                return Some(value.round() as u32);
            }
        }
    }
    None
}

fn icmp_command(host: &str) -> Command {
    let mut command = Command::new("ping");
    #[cfg(windows)]
    command.args(["-n", "1", "-w", "1000", host]);
    #[cfg(not(windows))]
    command.args(["-c", "1", "-W", "1", host]);
    command
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, ProbeError> {
    (host, port).to_socket_addrs().map_err(ProbeError::from_io)?.next().ok_or_else(|| ProbeError::other("dns"))
}

fn split_http(url: &str) -> Result<(String, u16, String), ProbeError> {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let default_port = if scheme == "http" { 80 } else { 443 };
    let (host, port) = if let Some(host) = authority.strip_prefix('[') {
        let (host, port) = host.split_once("]:").ok_or_else(|| ProbeError::other("url"))?;
        (host.to_string(), port.parse().map_err(|_| ProbeError::other("port"))?)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_string(), port.parse().map_err(|_| ProbeError::other("port"))?)
    } else {
        (authority.to_string(), default_port)
    };
    Ok((host, port, path))
}

fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16, user: &str, pass: &str) -> Result<(), ProbeError> {
    if user.is_empty() {
        stream.write_all(&[0x05, 0x01, 0x00]).map_err(ProbeError::from_io)?;
        let mut greet = [0u8; 2];
        stream.read_exact(&mut greet).map_err(ProbeError::from_io)?;
        if greet != [0x05, 0x00] {
            return Err(ProbeError::other("socks auth"));
        }
    } else {
        stream.write_all(&[0x05, 0x01, 0x02]).map_err(ProbeError::from_io)?;
        let mut greet = [0u8; 2];
        stream.read_exact(&mut greet).map_err(ProbeError::from_io)?;
        if greet != [0x05, 0x02] {
            return Err(ProbeError::other("socks auth"));
        }
        let user = user.as_bytes();
        let pass = pass.as_bytes();
        if user.len() > 255 || pass.len() > 255 {
            return Err(ProbeError::other("socks auth"));
        }
        let mut auth = vec![0x01, user.len() as u8];
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        stream.write_all(&auth).map_err(ProbeError::from_io)?;
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).map_err(ProbeError::from_io)?;
        if status[1] != 0 {
            return Err(ProbeError::other("socks auth"));
        }
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(ProbeError::other("host"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.push((port >> 8) as u8);
    req.push(port as u8);
    stream.write_all(&req).map_err(ProbeError::from_io)?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(ProbeError::from_io)?;
    if header[1] != 0 {
        return Err(ProbeError::SocksStatus(header[1]));
    }
    let skip = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(ProbeError::from_io)?;
            len[0] as usize
        }
        _ => return Err(ProbeError::other("socks atyp")),
    };
    let mut rest = vec![0u8; skip + 2];
    stream.read_exact(&mut rest).map_err(ProbeError::from_io)?;
    Ok(())
}

fn tls_client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let name = if name.len() > 255 { &name[..255] } else { name };
    let mut extensions = Vec::new();
    let mut sni = Vec::new();
    push_u16(&mut sni, (1 + 2 + name.len()) as u16);
    sni.push(0);
    push_u16(&mut sni, name.len() as u16);
    sni.extend_from_slice(name);
    push_ext(&mut extensions, 0, &sni);
    push_ext(&mut extensions, 0x000a, &[0x00, 0x02, 0x00, 0x1d]);
    push_ext(&mut extensions, 0x000d, &[0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
    push_ext(&mut extensions, 0x002b, &[0x02, 0x03, 0x04]);
    let mut share = Vec::new();
    push_u16(&mut share, 36);
    push_u16(&mut share, 0x001d);
    push_u16(&mut share, 32);
    share.extend_from_slice(&[0x33; 32]);
    push_ext(&mut extensions, 0x0033, &share);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0);
    let ciphers = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
    push_u16(&mut hello, ciphers.len() as u16);
    hello.extend_from_slice(&ciphers);
    hello.extend_from_slice(&[1, 0]);
    push_u16(&mut hello, extensions.len() as u16);
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01, (hello.len() >> 16) as u8, (hello.len() >> 8) as u8, hello.len() as u8];
    handshake.extend_from_slice(&hello);
    let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01];
    push_u16(&mut record, handshake.len() as u16);
    record.extend_from_slice(&handshake);
    record
}

fn push_u16(buf: &mut Vec<u8>, value: u16) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn push_ext(buf: &mut Vec<u8>, id: u16, body: &[u8]) {
    push_u16(buf, id);
    push_u16(buf, body.len() as u16);
    buf.extend_from_slice(body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_ping_time() {
        assert_eq!(parse_ping_ms("64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=12.4 ms"), Some(12));
        assert_eq!(parse_ping_ms("64 Bytes von 1.1.1.1: icmp_seq=1 ttl=117 Zeit=23.1 ms"), Some(23));
        assert_eq!(parse_ping_ms("Ответ от 1.1.1.1: время=12мс"), Some(12));
        assert_eq!(parse_ping_ms("Zeit=8ms"), Some(8));
    }

    #[test]
    fn socks_down_is_connection_refused() {
        let err = tcp_ping("127.0.0.1", 1, Duration::from_millis(200)).unwrap_err();
        assert!(err.socks_down(), "{err}");
        assert!(matches!(err, ProbeError::Refused(_)));
    }

    #[test]
    fn tcp_ping_reaches_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let _ = listener.accept();
        });
        let delay = tcp_ping("127.0.0.1", port, Duration::from_secs(2)).unwrap();
        assert!(delay < 2000);
    }

    fn serve_socks(reply: Option<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut greet = [0u8; 3];
            if stream.read_exact(&mut greet).is_err() {
                return;
            }
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            if header[3] == 3 {
                let mut len = [0u8; 1];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                if stream.read_exact(&mut rest).is_err() {
                    return;
                }
            }
            let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut buf = [0u8; 128];
            let _ = stream.read(&mut buf);
            if let Some(byte) = reply {
                let _ = stream.write_all(&[byte]);
            }
        });
        addr
    }

    #[test]
    fn client_hello_is_one_tls_record() {
        let hello = tls_client_hello("www.example.com");
        assert_eq!(hello[0], TLS_HANDSHAKE);
        let len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + len);
    }

    #[test]
    fn tunnel_ready_accepts_a_tls_reply_and_rejects_a_close() {
        let alive = serve_socks(Some(TLS_HANDSHAKE));
        tunnel_ready(alive, "https://www.example.com/generate_204", "", "", Duration::from_secs(2)).unwrap();
        let dead = serve_socks(None);
        let err = tunnel_ready(dead, "https://www.example.com/generate_204", "", "", Duration::from_secs(2)).unwrap_err();
        assert!(err.to_string().contains("закрыл"));
    }

    #[test]
    fn tunnel_ready_http_and_socks_password() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut greet = [0u8; 3];
            if stream.read_exact(&mut greet).is_err() {
                return;
            }
            let _ = stream.write_all(&[0x05, 0x02]);
            let mut ulen = [0u8; 2];
            if stream.read_exact(&mut ulen).is_err() {
                return;
            }
            let mut user = vec![0u8; ulen[1] as usize];
            if stream.read_exact(&mut user).is_err() {
                return;
            }
            let mut plen = [0u8; 1];
            if stream.read_exact(&mut plen).is_err() {
                return;
            }
            let mut pass = vec![0u8; plen[0] as usize];
            if stream.read_exact(&mut pass).is_err() {
                return;
            }
            let _ = stream.write_all(&[0x01, 0x00]);
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            if header[3] == 3 {
                let mut len = [0u8; 1];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                if stream.read_exact(&mut rest).is_err() {
                    return;
                }
            }
            let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"H");
        });
        tunnel_ready(addr, "http://[::1]:80/", "user", "secret", Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn socks_status_is_typed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut greet = [0u8; 3];
            if stream.read_exact(&mut greet).is_err() {
                return;
            }
            let _ = stream.write_all(&[0x05, 0x00]);
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            if header[3] == 3 {
                let mut len = [0u8; 1];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                let _ = stream.read_exact(&mut rest);
            }
            let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        });
        let err = proxy_ping(addr, "http://203.0.113.10/", false, "", "", Duration::from_secs(2)).unwrap_err();
        assert!(matches!(err, ProbeError::SocksStatus(5)));
    }

    #[test]
    fn proxy_ping_sends_username_auth_when_user_is_set() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut greet = [0u8; 3];
            if stream.read_exact(&mut greet).is_err() {
                return;
            }
            if stream.write_all(&[0x05, 0x02]).is_err() {
                return;
            }
            let mut ulen = [0u8; 2];
            if stream.read_exact(&mut ulen).is_err() {
                return;
            }
            let mut user = vec![0u8; ulen[1] as usize];
            if stream.read_exact(&mut user).is_err() {
                return;
            }
            let mut plen = [0u8; 1];
            if stream.read_exact(&mut plen).is_err() {
                return;
            }
            let mut pass = vec![0u8; plen[0] as usize];
            if stream.read_exact(&mut pass).is_err() {
                return;
            }
            let _ = tx.send((greet, ulen[0], user, pass));
            if stream.write_all(&[0x01, 0x00]).is_err() {
                return;
            }
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            if header[3] == 3 {
                let mut len = [0u8; 1];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut rest = vec![0u8; len[0] as usize + 2];
                if stream.read_exact(&mut rest).is_err() {
                    return;
                }
            }
            let _ = stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"H");
        });
        proxy_ping(addr, "http://example.invalid/", false, "session-user", "session-pass", Duration::from_secs(2)).unwrap();
        let (greet, version, user, pass) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(greet, [0x05, 0x01, 0x02]);
        assert_eq!(version, 0x01);
        assert_eq!(user, b"session-user");
        assert_eq!(pass, b"session-pass");
    }

    #[test]
    fn proxy_ping_head_through_local_socks_returns_milliseconds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else { return };
            let mut greet = [0u8; 3];
            if stream.read_exact(&mut greet).is_err() || greet != [0x05, 0x01, 0x00] {
                return;
            }
            if stream.write_all(&[0x05, 0x00]).is_err() {
                return;
            }
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() || header[1] != 0x01 || header[3] != 0x03 {
                return;
            }
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).is_err() {
                return;
            }
            let mut rest = vec![0u8; len[0] as usize + 2];
            if stream.read_exact(&mut rest).is_err() {
                return;
            }
            if stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).is_err() {
                return;
            }
            let mut req = [0u8; 256];
            let _ = stream.read(&mut req);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        });
        let delay_ms = proxy_ping(addr, "http://example.com/", true, "", "", Duration::from_secs(2)).unwrap();
        assert!(delay_ms < 2_000);
    }
}
