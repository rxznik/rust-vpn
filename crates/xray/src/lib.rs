//! Сборка конфига Xray и запуск бинарника v26.3.27.
//!
//! Inbound socks и http слушают 127.0.0.1.
//! Sniffing включает routeOnly.
//! Fragment и noise поднимают freedom-outbound с тегом fragment
//! и dialerProxy у прокси.
//! JSON-подписка проходит prepare_passthrough: listen только loopback,
//! пустой `api.listen` становится `127.0.0.1:10085`,
//! пути логов только внутри каталога сессии.
//! Поля `tls.insecure` и Hysteria2 `insecure` читаются из ссылки и в JSON не пишутся:
//! проверка сертификата остаётся включённой, `allowInsecure` не появляется.
//! Статистика читается командой api statsquery по шаблону
//! outbound>>>proxy>>>traffic и отдаётся снимком фонового потока.

pub(crate) const LOOPBACK: &str = "127.0.0.1";

mod compile;
mod process;

pub use compile::{compile, prepare_passthrough, CompileError, CompileRequest};
pub use process::{config_is_object, locate_binary, locate_from, parse_stats, query_stats, ProcessError, SpawnSpec, StatsPoller, Supervisor, TrafficStats};
