use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, Server};
use url::Url;

pub(crate) fn parse_hy2(url: &Url) -> Result<Server, LinkError> {
    let query = query_pairs(url);
    let password = {
        let user = percent_decode(url.username());
        if let Some(pass) = url.password() {
            format!("{user}:{}", percent_decode(pass))
        } else {
            user
        }
    };
    let alpn = query.get("alpn").map(|v| split_csv(v)).unwrap_or_default();
    Ok(bare_server(
        host_of(url),
        port_of(url, 443),
        Protocol::Hysteria2 {
            password,
            sni: query.get("sni").cloned(),
            insecure: flag_on(query.get("insecure").map(|s| s.as_str())),
            obfs: query.get("obfs").cloned(),
            obfs_password: query.get("obfs-password").cloned(),
            alpn,
            pin_sha256: query.get("pinsha256").cloned(),
        },
    ))
}
