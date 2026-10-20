use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, Server};
use url::Url;

pub(crate) fn parse_trojan(url: &Url) -> Result<Server, LinkError> {
    let password = percent_decode(url.username());
    if password.is_empty() {
        return Err(LinkError::Invalid("trojan password missing".into()));
    }
    let query = query_pairs(url);
    Ok(bare_server(
        host_of(url),
        port_of(url, 443),
        Protocol::Trojan {
            password,
            transport: transport_from_query(&query),
            tls: tls_from_query(&query, url),
        },
    ))
}
