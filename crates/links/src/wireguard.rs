use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, Server, WireGuardPeer};
use url::Url;

pub(crate) fn parse_wireguard(url: &Url) -> Result<Server, LinkError> {
    let query = query_pairs(url);
    let reserved = query
        .get("reserved")
        .map(|v| v.split(',').filter_map(|p| p.trim().parse().ok()).collect())
        .unwrap_or_default();
    Ok(bare_server(
        host_of(url),
        port_of(url, 51820),
        Protocol::Wireguard(WireGuardPeer {
            secret_key: percent_decode(url.username()),
            public_key: query.get("publickey").cloned().unwrap_or_default(),
            address: query.get("address").cloned(),
            mtu: query.get("mtu").and_then(|v| v.parse().ok()),
            reserved,
        }),
    ))
}
