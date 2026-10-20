use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, RealitySettings, Security, Server};
use url::Url;

pub(crate) fn parse_vless(url: &Url) -> Result<Server, LinkError> {
    let uuid = percent_decode(url.username());
    if uuid.is_empty() {
        return Err(LinkError::Invalid("vless uuid missing".into()));
    }
    let query = query_pairs(url);
    let transport = transport_from_query(&query);
    let security = match query.get("security").map(|s| s.as_str()).unwrap_or("none") {
        "reality" => Security::Reality(RealitySettings {
            server_name: query.get("sni").cloned().unwrap_or_else(|| host_of(url)),
            public_key: query.get("pbk").cloned().unwrap_or_default(),
            short_id: query.get("sid").cloned().unwrap_or_default(),
            fingerprint: query.get("fp").cloned(),
            spider_x: query.get("spx").cloned(),
        }),
        "tls" => Security::Tls(tls_from_query(&query, url)),
        _ => Security::None,
    };
    Ok(bare_server(
        host_of(url),
        port_of(url, 443),
        Protocol::Vless {
            uuid,
            encryption: query.get("encryption").cloned().unwrap_or_else(|| "none".into()),
            flow: query.get("flow").cloned().filter(|s| !s.is_empty()),
            transport,
            security,
        },
    ))
}
