use serde_json::{json, Value};

pub(crate) fn outbound(raw: &str) -> Value {
 json!({"protocol": "freedom", "settings": {"comment": raw}})
}
