use rvpn_model::CoreSettings;
use rvpn_xray::{compile, locate_binary, parse_stats, CompileRequest, SpawnSpec, Supervisor};
use rvpn_model::{Protocol, Server};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

#[test]
fn stats_parser_reads_uplink_and_downlink() {
    let text = "stat: outbound>>>proxy>>>traffic>>>uplink value: 12\nstat: outbound>>>proxy>>>traffic>>>downlink value: 34\n";
    let stats = parse_stats(text).unwrap();
    assert_eq!(stats.uplink, 12);
    assert_eq!(stats.downlink, 34);
}

#[test]
fn stats_parser_reads_split_lines_and_json() {
    let split = "name: \"outbound>>>proxy>>>traffic>>>uplink\"\nvalue: 12\nname: \"outbound>>>proxy>>>traffic>>>downlink\"\nvalue: 34\n";
    let stats = parse_stats(split).unwrap();
    assert_eq!(stats.uplink, 12);
    assert_eq!(stats.downlink, 34);
    let json = r#"{"stat":[{"name":"outbound>>>proxy>>>traffic>>>uplink","value":7},{"name":"outbound>>>proxy>>>traffic>>>downlink","value":9}]}"#;
    let stats = parse_stats(json).unwrap();
    assert_eq!((stats.uplink, stats.downlink), (7, 9));
    assert!(parse_stats("").is_none());
    assert!(parse_stats("no stats here").is_none());
}

#[test]
fn failed_process_is_restarted_once() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/exit-test");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let mut supervisor = Supervisor::new();
    let err = supervisor
        .start(&SpawnSpec {
            binary: "/bin/false".into(),
            args: vec![],
            config_json: "{}".into(),
            work_dir: dir.clone(),
            asset_dir: None,
        })
        .unwrap_err();
    assert!(err.to_string().contains("exited"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn socks_inbound_answers_handshake() {
    let Some(binary) = locate_binary() else {
        eprintln!("skip socks smoke: xray binary missing");
        return;
    };
    let port = free_port();
    let mut settings = CoreSettings::default();
    settings.socks_port = port;
    settings.api_port = free_port();
    let server = Server {
        id: "local".into(),
        subscription_id: None,
        name: "direct".into(),
        address: "127.0.0.1".into(),
        port: 9,
        protocol: Protocol::Socks { username: None, password: None },
        description: None,
        fragment: None,
        noise: None,
        raw_link: None,
        delay_ms: None,
    };
    let config = compile(&CompileRequest {
        server: &server,
        settings: &settings,
        fragment: None,
        noise: None,
        routing: None,
        dns: None,
    });
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tmp/socks-test");
    let _ = fs::remove_dir_all(&dir);
    let mut supervisor = Supervisor::new();
    supervisor
        .start(&SpawnSpec {
            binary,
            args: vec!["run".into(), "-c".into(), dir.join("xray.json").display().to_string()],
            config_json: serde_json::to_string(&config).unwrap(),
            work_dir: dir.clone(),
            asset_dir: None,
        })
        .unwrap_or_else(|err| panic!("{err}\n{}", supervisor.recent_log().iter().map(|line| line.as_ref()).collect::<Vec<_>>().join("\n")));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("socks port");
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0x05, 0x00]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(supervisor.config_path().unwrap()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    supervisor.stop().unwrap();
    let _ = fs::remove_dir_all(&dir);
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
