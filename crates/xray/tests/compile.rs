use rvpn_links::parse_server;
use rvpn_model::CoreSettings;
use rvpn_xray::{compile, locate_binary, prepare_passthrough, CompileError, CompileRequest};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn compiled(link: &str) -> serde_json::Value {
    let server = parse_server(link, Some("sub")).unwrap();
    compile(&CompileRequest {
        server: &server,
        settings: &CoreSettings::default(),
        fragment: server.fragment.as_ref(),
        noise: server.noise.as_ref(),
        routing: None,
        dns: None,
    })
}

fn snapshot(name: &str, value: &serde_json::Value) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.json"));
    let pretty = serde_json::to_string_pretty(value).unwrap() + "\n";
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() || !path.exists() {
        fs::write(&path, &pretty).unwrap();
    }
    let expected = fs::read_to_string(&path).unwrap();
    assert_eq!(expected, pretty, "snapshot {name}");
}

fn work_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp").join(name)
}

fn xray_accepts(value: &serde_json::Value) {
    let Some(binary) = locate_binary() else {
        return;
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = work_dir(&format!("xray-test-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("config.json");
    fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    let output = Command::new(binary).args(["run", "-test", "-c"]).arg(&path).output().unwrap();
    assert!(output.status.success(), "xray rejected config: {}", String::from_utf8_lossy(&output.stderr));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn snapshots_match_xray() {
    let vmess = "vmess://eyJ2IjoiMiIsInBzIjoidm0iLCJhZGQiOiIyMDMuMC4xMTMuOSIsInBvcnQiOiIxMDA4NiIsImlkIjoiMjIyMjIyMjItMjIyMi00MjIyLTgyMjItMjIyMjIyMjIyMjIyIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsInRscyI6InRscyIsInNuaSI6ImV4LmNvbSJ9";
    let cases = [
        ("vless-reality", "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=reality&pbk=qGPTy8EZokn3hWp6hKBQ0MVvEuLRJCcv5UdWeP4TVhI&type=tcp&sni=www.example.com&fp=chrome&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#Example"),
        ("vmess", vmess),
        ("trojan", "trojan://secret@203.0.113.8:443?security=tls&type=tcp&sni=cdn.example#Node"),
        ("shadowsocks", "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@203.0.113.4:8388#ssnode"),
        ("socks", "socks://user:pass@203.0.113.5:1080#sock"),
        ("hysteria2", "hy2://s3cret@203.0.113.6:443?sni=hy.example&insecure=1#hy"),
    ];
    for (name, link) in cases {
        let value = compiled(link);
        snapshot(name, &value);
        xray_accepts(&value);
    }
}

#[test]
fn passthrough_keeps_listeners_on_loopback() {
    let rejected = prepare_passthrough(
        r#"{"inbounds":[{"listen":"0.0.0.0","port":1,"protocol":"socks"}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#,
        None,
        true,
        std::path::Path::new("/tmp/runtime"),
    );
    assert!(rejected.unwrap_err().to_string().contains("local"));
    let raw = r#"{"log":{"access":"../etc/passwd","loglevel":"warning"},"inbounds":[{"port":1,"protocol":"socks"}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#;
    let value: serde_json::Value = serde_json::from_str(&prepare_passthrough(raw, None, true, std::path::Path::new("/tmp/runtime")).unwrap()).unwrap();
    assert_eq!(value["inbounds"][0]["listen"], "127.0.0.1");
    assert!(value["log"].get("access").is_none());
    assert_eq!(value["log"]["loglevel"], "warning");
    assert_eq!(value["outbounds"][0]["protocol"], "freedom");
}

#[test]
fn fragment_uses_dialer_proxy() {
    let link = "trojan://secret@203.0.113.8:443?security=tls&sni=cdn.example&fragment=10-20,5-10,tlshello&noises=rand,10-20,10-16#n";
    let value = compiled(link);
    assert_eq!(value["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "fragment");
    assert_eq!(value["outbounds"][1]["tag"], "fragment");
    xray_accepts(&value);
}

#[test]
fn insecure_is_omitted_and_wireguard_mux_and_api_listen() {
    for link in [
        "hy2://s3cret@203.0.113.6:443?sni=hy.example&insecure=1#hy",
        "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&security=tls&sni=ex.com&insecure=1#a",
    ] {
        let text = serde_json::to_string(&compiled(link)).unwrap();
        assert!(!text.contains("allowInsecure"), "{link}");
        assert!(text.contains("\"routeOnly\":true"));
    }
    let server = parse_server("wireguard://c2VjcmV0@203.0.113.7:51820?publickey=cHVi&address=10.0.0.2/32", Some("sub")).unwrap();
    let mut settings = CoreSettings::default();
    settings.mux.enabled = true;
    let value = compile(&CompileRequest {
        server: &server,
        settings: &settings,
        fragment: None,
        noise: None,
        routing: None,
        dns: None,
    });
    assert_eq!(value["outbounds"][0]["protocol"], "wireguard");
    assert!(value["outbounds"][0].get("mux").is_none());
    let rejected = prepare_passthrough(
        r#"{"api":{"listen":"0.0.0.0:1"},"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"socks"}]}"#,
        None,
        true,
        std::path::Path::new("/tmp/runtime"),
    );
    assert!(rejected.is_err());
}

#[test]
fn passthrough_fills_missing_api_listen_and_rejects_non_object_inbound() {
    let raw = r#"{"api":{"tag":"api"},"inbounds":[{"listen":"127.0.0.1","port":1,"protocol":"socks"}],"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#;
    let value: serde_json::Value = serde_json::from_str(&prepare_passthrough(raw, None, true, std::path::Path::new("/tmp/runtime")).unwrap()).unwrap();
    assert_eq!(value["api"]["listen"], "127.0.0.1:10085");
    assert_eq!(value["api"]["tag"], "api");
    assert_eq!(value["outbounds"][0]["protocol"], "freedom");
    let empty = r#"{"api":{"listen":""},"outbounds":[{"protocol":"freedom","tag":"direct"}]}"#;
    let value: serde_json::Value = serde_json::from_str(&prepare_passthrough(empty, None, true, std::path::Path::new("/tmp/runtime")).unwrap()).unwrap();
    assert_eq!(value["api"]["listen"], "127.0.0.1:10085");
    assert_eq!(value["outbounds"][0]["tag"], "direct");
    let bad = prepare_passthrough(r#"{"inbounds":["nope"]}"#, None, true, std::path::Path::new("/tmp/runtime"));
    assert!(matches!(bad, Err(CompileError::Listen)));
}

#[test]
fn locate_binary_prefers_an_explicit_file() {
    let path = work_dir("xray-bin").join("xray");
    let _ = fs::create_dir_all(path.parent().unwrap());
    fs::write(&path, b"not-a-real-binary").unwrap();
    let found = rvpn_xray::locate_from(Some(path.as_os_str()), std::path::Path::new("/missing"));
    assert_eq!(found.unwrap(), path);
    assert!(rvpn_xray::locate_from(Some("/no/such/xray"), std::path::Path::new("/missing")).is_none());
    let _ = fs::remove_dir_all(path.parent().unwrap());
}
