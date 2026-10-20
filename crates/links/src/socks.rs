use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, Server};
use url::Url;

pub(crate) fn parse_socks(raw: &str, url: &Url, decoded_already: bool) -> Result<Server, LinkError> {
    if !decoded_already && url.username().is_empty() && url.password().is_none() {
        let body = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
        let (body, _) = body.split_once('#').unwrap_or((body, ""));
        let body = body.trim_start_matches('/');
        if let Some(decoded) = b64_decode(body) {
            if let Ok(text) = String::from_utf8(decoded) {
                if text.contains('@') {
                    let nested_raw = format!("socks://{text}");
                    let nested = Url::parse(&nested_raw).map_err(|e| LinkError::Invalid(e.to_string()))?;
                    return parse_socks(&nested_raw, &nested, true);
                }
            }
        }
    }
    let username = nonempty(percent_decode(url.username()));
    let password = url.password().map(percent_decode).and_then(nonempty);
    Ok(bare_server(
        host_of(url),
        port_of(url, 1080),
        Protocol::Socks { username, password },
    ))
}
