//! Разбор строк журнала Xray и сортировка таблицы.

const ACCESS_LEVEL: &str = "access";

/// Колонки таблицы журнала. Числа совпадают с заголовком Slint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LogColumn {
    Stamp = 0,
    Level = 1,
    From = 2,
    Accepted = 3,
    Route = 4,
    Email = 5,
    Message = 6,
}

impl LogColumn {
    pub fn from_i32(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::Stamp,
            1 => Self::Level,
            2 => Self::From,
            3 => Self::Accepted,
            4 => Self::Route,
            5 => Self::Email,
            6 => Self::Message,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub stamp: String,
    pub level: String,
    pub from: String,
    pub accepted: String,
    pub route: String,
    pub email: String,
    pub message: String,
}

impl LogLine {
    fn message_only(message: impl Into<String>) -> Self {
        Self {
            stamp: String::new(),
            level: String::new(),
            from: String::new(),
            accepted: String::new(),
            route: String::new(),
            email: String::new(),
            message: message.into(),
        }
    }
}

pub fn parse_line(line: &str) -> LogLine {
    let Some((stamp, rest)) = split_stamp(line) else {
        return LogLine::message_only(line);
    };
    if let Some(mut row) = parse_service(rest) {
        row.stamp = stamp;
        return row;
    }
    if let Some(mut row) = parse_access(rest) {
        row.stamp = stamp;
        row.level = ACCESS_LEVEL.into();
        return row;
    }
    let mut row = LogLine::message_only(rest.trim_start());
    row.stamp = stamp;
    row
}

pub fn sort_rows(rows: &mut [LogLine], column: i32, ascending: bool) {
    let Some(column) = LogColumn::from_i32(column) else {
        return;
    };
    rows.sort_by(|left, right| {
        let order = column_value(left, column).cmp(column_value(right, column));
        if ascending { order } else { order.reverse() }
    });
}

fn column_value(row: &LogLine, column: LogColumn) -> &str {
    match column {
        LogColumn::Stamp => row.stamp.as_str(),
        LogColumn::Level => row.level.as_str(),
        LogColumn::From => row.from.as_str(),
        LogColumn::Accepted => row.accepted.as_str(),
        LogColumn::Route => row.route.as_str(),
        LogColumn::Email => row.email.as_str(),
        LogColumn::Message => row.message.as_str(),
    }
}

pub fn to_csv(rows: &[LogLine]) -> String {
    let mut out = String::from("timestamp,level,from,accepted,route,email,message\n");
    for row in rows {
        let fields = [&row.stamp, &row.level, &row.from, &row.accepted, &row.route, &row.email, &row.message];
        for (index, field) in fields.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&csv_field(field));
        }
        out.push('\n');
    }
    out
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn split_stamp(line: &str) -> Option<(String, &str)> {
    let mut parts = line.splitn(3, ' ');
    let date = parts.next()?;
    let time = parts.next()?;
    let rest = parts.next().unwrap_or("");
    if !is_date(date) || !is_time(time) {
        return None;
    }
    Some((format!("{date} {time}"), rest))
}

fn is_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10 && bytes[4] == b'/' && bytes[7] == b'/' && digits(&bytes[0..4]) && digits(&bytes[5..7]) && digits(&bytes[8..10])
}

fn is_time(value: &str) -> bool {
    let (clock, fraction) = value.split_once('.').unwrap_or((value, ""));
    let bytes = clock.as_bytes();
    bytes.len() == 8 && bytes[2] == b':' && bytes[5] == b':' && digits(&bytes[0..2]) && digits(&bytes[3..5]) && digits(&bytes[6..8]) && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

fn digits(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| byte.is_ascii_digit())
}

fn parse_service(rest: &str) -> Option<LogLine> {
    let rest = rest.trim_start();
    let (level, after) = bracket(rest)?;
    let level = normalize_level(&level)?;
    let mut row = LogLine::message_only(after.trim_start());
    row.level = level;
    Some(row)
}

fn normalize_level(raw: &str) -> Option<String> {
    match raw.to_ascii_lowercase().as_str() {
        "info" => Some("info".into()),
        "warning" | "warn" => Some("warning".into()),
        "error" => Some("error".into()),
        "debug" => Some("debug".into()),
        _ => None,
    }
}

fn parse_access(rest: &str) -> Option<LogLine> {
    let rest = rest.trim_start().strip_prefix("from ")?;
    let (from, rest) = next_token(rest)?;
    let rest = rest.trim_start().strip_prefix("accepted ")?;
    let (accepted, rest) = next_token(rest)?;
    let rest = rest.trim_start();
    let (route, rest) = if let Some((route, after)) = bracket(rest) {
        (route, after.trim_start())
    } else {
        (String::new(), rest)
    };
    let email = rest.strip_prefix("email:").map(|value| value.trim()).unwrap_or("").to_string();
    let mut row = LogLine::message_only("");
    row.from = from;
    row.accepted = accepted;
    row.route = route;
    row.email = email;
    Some(row)
}

fn bracket(value: &str) -> Option<(String, &str)> {
    let value = value.trim_start();
    let inside = value.strip_prefix('[')?;
    let end = inside.find(']')?;
    Some((inside[..end].to_string(), &inside[end + 1..]))
}

fn next_token(value: &str) -> Option<(String, &str)> {
    let value = value.trim_start();
    if value.is_empty() {
        return None;
    }
    let end = value.find(char::is_whitespace).unwrap_or(value.len());
    Some((value[..end].to_string(), &value[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_line_keeps_session_in_the_message() {
        let row = parse_line("2026/10/15 13:40:01 [Info] [12345] app/dispatcher: текст");
        assert_eq!(row.stamp, "2026/10/15 13:40:01");
        assert_eq!(row.level, "info");
        assert!(row.from.is_empty());
        assert!(row.accepted.is_empty());
        assert!(row.route.is_empty());
        assert!(row.email.is_empty());
        assert_eq!(row.message, "[12345] app/dispatcher: текст");
    }

    #[test]
    fn access_line_reads_route_and_email() {
        let row = parse_line("2026/10/15 13:40:01.123456 from 127.0.0.1:1 accepted tcp:example.com:443 [socks -> proxy] email: user");
        assert_eq!(row.stamp, "2026/10/15 13:40:01.123456");
        assert_eq!(row.level, "access");
        assert_eq!(row.from, "127.0.0.1:1");
        assert_eq!(row.accepted, "tcp:example.com:443");
        assert_eq!(row.route, "socks -> proxy");
        assert_eq!(row.email, "user");
        assert!(row.message.is_empty());
    }

    #[test]
    fn unknown_line_stays_in_the_message() {
        let row = parse_line("plain line");
        assert!(row.stamp.is_empty());
        assert!(row.level.is_empty());
        assert_eq!(row.message, "plain line");
    }

    #[test]
    fn csv_quotes_comma_and_quote() {
        let row = LogLine {
            stamp: "2026/10/15 13:40:01".into(),
            level: "info".into(),
            from: String::new(),
            accepted: String::new(),
            route: String::new(),
            email: String::new(),
            message: "say \"hi\", now".into(),
        };
        let csv = to_csv(&[row]);
        assert!(csv.starts_with("timestamp,level,from,accepted,route,email,message\n"));
        assert!(csv.contains("\"say \"\"hi\"\", now\""));
    }

    #[test]
    fn sort_follows_the_chosen_column_and_direction() {
        let mut rows = vec![
            LogLine { stamp: "2026/10/15 13:40:02".into(), level: "warning".into(), from: "10.0.0.2:1".into(), accepted: "tcp:b.example:443".into(), route: "socks -> proxy".into(), email: "b".into(), message: "second".into() },
            LogLine { stamp: "2026/10/15 13:40:01".into(), level: "info".into(), from: "10.0.0.1:1".into(), accepted: "tcp:a.example:443".into(), route: "http -> proxy".into(), email: "a".into(), message: "first".into() },
        ];
        sort_rows(&mut rows, 0, true);
        assert_eq!(rows[0].stamp, "2026/10/15 13:40:01");
        sort_rows(&mut rows, 0, false);
        assert_eq!(rows[0].stamp, "2026/10/15 13:40:02");
        sort_rows(&mut rows, 5, true);
        assert_eq!(rows[0].email, "a");
        let kept = rows.clone();
        sort_rows(&mut rows, -1, true);
        assert_eq!(rows, kept);
    }
}
