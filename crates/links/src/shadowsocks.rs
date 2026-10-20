use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, Server};
use url::Url;

pub(crate) fn parse_ss_sip002(url: &Url) -> Result<Server, LinkError> {
    let user = percent_decode(url.username());
    let (method, password) = if let Some(pass) = url.password() {
        (user, percent_decode(pass))
    } else if let Some(decoded) = b64_decode(&user) {
        let text = String::from_utf8(decoded).map_err(|e| LinkError::Invalid(e.to_string()))?;
        split_method_password(&text)?
    } else {
        return Err(LinkError::Invalid("shadowsocks userinfo".into()));
    };
    let query = query_pairs(url);
    Ok(bare_server(
        host_of(url),
        port_of(url, 8388),
        Protocol::Shadowsocks {
            method,
            password,
            plugin: query.get("plugin").cloned(),
            plugin_opts: None,
        },
    ))
}

pub(crate) fn parse_ss_legacy(raw: &str) -> Result<Server, LinkError> {
    let body = raw.trim_start_matches("ss://").trim_start_matches("SS://");
    let (body, _name) = body.split_once('#').unwrap_or((body, ""));
    let decoded = b64_decode(body).ok_or_else(|| LinkError::Invalid("shadowsocks base64".into()))?;
    let text = String::from_utf8(decoded).map_err(|e| LinkError::Invalid(e.to_string()))?;
    let (user, hostport) = text.split_once('@').ok_or_else(|| LinkError::Invalid("shadowsocks legacy".into()))?;
    let (method, password) = split_method_password(user)?;
    let (host, port) = split_host_port(hostport, 8388)?;
    Ok(bare_server(host, port, Protocol::Shadowsocks { method, password, plugin: None, plugin_opts: None }))
}
