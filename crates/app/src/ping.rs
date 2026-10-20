use super::{AppError, Client, ServerRow};
use rvpn_model::{
    PingStyle, PingType, Protocol, SortType, DELAY_FAIR_MS, DELAY_GOOD_MS,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

impl Client {
    /// Stops a `ping_many` batch that is still waiting on the slowest probes.
    pub fn cancel_ping(&self) {
        self.ping_epoch.fetch_add(1, Ordering::SeqCst);
    }

    pub fn ping(&self, server_id: &str) -> Result<Option<u32>, AppError> {
        let result = self.probe_one(server_id)?;
        self.db().set_delay(server_id, result)?;
        Ok(result)
    }

    fn probe_one(&self, server_id: &str) -> Result<Option<u32>, AppError> {
        let (server, settings) = {
            let store = self.db();
            (store.get_server(server_id)?, store.settings()?)
        };
        if matches!(server.protocol, Protocol::Json { .. }) {
            return Ok(None);
        }
        let kind = settings.ping_type;
        let result = match kind {
            PingType::Tcp => rvpn_probe::tcp_ping(&server.address, server.port, Duration::from_secs(3)).ok(),
            PingType::Icmp => rvpn_probe::icmp_ping(&server.address).ok(),
            PingType::Proxy | PingType::ProxyHead => {
                let live = self.session().as_ref().map(Arc::clone);
                let Some(live) = live else {
                    return Err(AppError::new("proxy ping needs an active connection"));
                };
                let socks = SocketAddr::from(([127, 0, 0, 1], live.socks_port));
                rvpn_probe::proxy_ping(socks, &settings.check_url, kind == PingType::ProxyHead, &live.socks_user, &live.socks_password, Duration::from_secs(8)).ok()
            }
        };
        Ok(result)
    }

    pub fn ping_many(&self, ids: &[String]) -> Vec<(String, Option<u32>)> {
        let epoch = self.ping_epoch.load(Ordering::SeqCst);
        let settings = self.settings().unwrap_or_default();
        let width = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 16);
        let budget = match settings.ping_type {
            PingType::Icmp => Duration::from_secs(2),
            PingType::Proxy | PingType::ProxyHead => Duration::from_secs(8),
            PingType::Tcp => Duration::from_secs(3),
        };
        let deadline = std::time::Instant::now() + budget;
        let mut out = Vec::new();
        for chunk in ids.chunks(width) {
            if self.ping_epoch.load(Ordering::SeqCst) != epoch || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::scope(|scope| {
                let mut joins = Vec::new();
                for id in chunk {
                    let id = id.clone();
                    joins.push(scope.spawn(move || {
                        if self.ping_epoch.load(Ordering::SeqCst) != epoch || std::time::Instant::now() >= deadline {
                            return (id, None);
                        }
                        (id.clone(), self.probe_one(&id).ok().flatten())
                    }));
                }
                for join in joins {
                    if let Ok(item) = join.join() {
                        out.push(item);
                    }
                }
            });
        }
        let _ = self.db().set_delays(&out);
        out
    }
}

pub(crate) fn format_delay(ms: Option<u32>, style: PingStyle) -> String {
    let Some(ms) = ms else {
        return "—".into();
    };
    if style == PingStyle::Icon {
        if ms < DELAY_GOOD_MS {
            "good".into()
        } else if ms < DELAY_FAIR_MS {
            "fair".into()
        } else {
            "slow".into()
        }
    } else {
        format!("{ms} ms")
    }
}

pub(crate) fn sort_rows(rows: &mut [(Option<u32>, ServerRow)], sort: SortType) {
    match sort {
        SortType::Without => {}
        SortType::Alphabet => rows.sort_by(|a, b| a.1.name.cmp(&b.1.name).then_with(|| a.1.id.cmp(&b.1.id))),
        SortType::Ping => rows.sort_by(|a, b| match (a.0, b.0) {
            (Some(left), Some(right)) => left.cmp(&right).then_with(|| a.1.name.cmp(&b.1.name)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.1.name.cmp(&b.1.name),
        }),
    }
}
