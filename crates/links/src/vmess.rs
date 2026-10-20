use super::LinkError;
use super::common::*;
use rvpn_model::{Protocol, Server, TlsSettings, Transport};
use serde_json::Value;

pub(crate) fn parse_vmess(raw: &str) -> Result<Server, LinkError> {
    let body = raw.split_once("://").map(|(_, b)| b).unwrap_or(raw);
    let (body, _) = body.split_once('#').unwrap_or((body, ""));
    let decoded = b64_decode(body).ok_or_else(|| LinkError::Invalid("vmess base64".into()))?;
    let value: Value = serde_json::from_slice(&decoded).map_err(|e| LinkError::Invalid(e.to_string()))?;
    let obj = value.as_object().ok_or_else(|| LinkError::Invalid("vmess json".into()))?;
    let host = json_str(obj, "add").ok_or_else(|| LinkError::Invalid("vmess add".into()))?;
    let port = json_port(obj.get("port")).unwrap_or(443);
    let name = json_str(obj, "ps").unwrap_or_else(|| format!("{host}:{port}"));
    let network = json_str(obj, "net").unwrap_or_else(|| "tcp".into());
    let header = json_str(obj, "type").filter(|s| s != "none");
    let transport = Transport {
        network,
        path: json_str(obj, "path").filter(|s| !s.is_empty()),
        host: json_str(obj, "host").filter(|s| !s.is_empty()),
        service_name: json_str(obj, "path").filter(|_| json_str(obj, "net").as_deref() == Some("grpc")),
        header_type: header,
        mode: json_str(obj, "mode"),
        authority: None,
    };
    let tls_flag = json_str(obj, "tls").unwrap_or_default();
    let tls = if tls_flag.eq_ignore_ascii_case("tls") {
        Some(TlsSettings {
            sni: json_str(obj, "sni").or_else(|| json_str(obj, "host")),
            alpn: json_str(obj, "alpn").map(|v| split_csv(&v)).unwrap_or_default(),
            fingerprint: json_str(obj, "fp"),
            insecure: json_str(obj, "allowInsecure").map(|v| flag_on(Some(&v))).unwrap_or(false),
            pinned_sha256: None,
        })
    } else {
        None
    };
    let mut server = bare_server(
        host,
        port,
        Protocol::Vmess {
            uuid: json_str(obj, "id").unwrap_or_default(),
            alter_id: json_port(obj.get("aid")).unwrap_or(0),
            security: json_str(obj, "scy").unwrap_or_else(|| "auto".into()),
            transport,
            tls,
        },
    );
    server.name = name;
    if let Some(desc) = json_str(obj, "serverDescription").and_then(|v| maybe_b64_text(&v)) {
        server.description = Some(desc);
    }
    Ok(server)
}
