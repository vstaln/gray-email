//! NDJSON protocol 1.1 sidecar.
//! Manifest answers without config; delivery failures never echo secrets.
use serde_json::{json, Value};
use std::path::Path;
use std::sync::LazyLock;

/// Static manifest (`email` 0.1.x, protocol 1.1, no commands).
pub static MANIFEST: LazyLock<Value> = LazyLock::new(|| {
    json!({
        "name": "email",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "1.1",
        "requires_plugins": ["gateway"],
        "commands": [],
        "hooks": ["prompt/context"],
        "tools": [{
            "name": "email_send",
            "label": "Email Send",
            "description": "Send an email via the configured account. The body is markdown rendered to text+html; attachments are local file paths. Recipient defaults to the configured home address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient address; default: the configured home address"},
                    "subject": {"type": "string", "description": "Subject line"},
                    "body": {"type": "string", "description": "Message body (markdown: rendered to text+html)"},
                    "attachments": {"type": "array", "items": {"type": "string"}, "description": "Optional local file paths to attach (up to 20 MiB each)"}
                },
                "required": ["body"]
            }
        }]
    })
});

const PROMPT_CONTEXT: &str = "Email tools: email_send mails text (markdown, rendered to text+html) to an address; `to` defaults to the configured home address, `attachments` takes local file paths. Replies to inbound mail keep the thread via In-Reply-To. Errors say exactly what to fix; nothing is sent when a call is invalid. Never send secrets.";

fn is_error() -> Value {
    json!({
        "content": "Email delivery failed. Run gray-email doctor; do not blindly retry partial sends.",
        "is_error": true
    })
}

/// A specific, fixable failure. `detail` must never contain config values.
fn not_sent(detail: impl std::fmt::Display) -> Value {
    json!({
        "content": format!("Not sent: {detail}. Nothing reached the SMTP server; fix it and call again."),
        "is_error": true
    })
}

/// Dispatch one protocol method. Never echoes config/password text:
/// failures describe the caller's own input or a sanitized reason only.
pub async fn dispatch(method: &str, params: &Value, config_path: &Path) -> Value {
    if method == "plugin/manifest" {
        return MANIFEST.clone();
    }
    if method == "prompt/context" {
        return json!({"text": PROMPT_CONTEXT});
    }
    if method == "tool/call" {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        return match name {
            "email_send" => send_mail(params, config_path).await,
            _ => is_error(),
        };
    }
    json!({"error": "Unsupported method"})
}

async fn send_mail(params: &Value, config_path: &Path) -> Value {
    let args = params.get("args").cloned().unwrap_or(Value::Null);
    let body = args.get("body").and_then(Value::as_str).unwrap_or("");
    if body.trim().is_empty() {
        return not_sent("body is empty");
    }
    let config = match crate::config::load_config(config_path) {
        Ok(c) => c,
        Err(_) => return is_error(),
    };
    let fallback = config
        .get("home_address")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            config
                .get("allowed_senders")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let to = args
        .get("to")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .unwrap_or(&fallback);
    if to.is_empty() {
        return not_sent("no recipient: pass `to` or configure a home address");
    }
    if !crate::config::addr_valid(&Value::String(to.to_string())) {
        return not_sent("to must be a valid email address");
    }
    let subject = args
        .get("subject")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("gray")
        .chars()
        .take(200)
        .collect::<String>();
    if subject.bytes().any(|b| b == b'\r' || b == b'\n') {
        return not_sent("subject must be a single line");
    }
    let mut attachments = Vec::new();
    if let Some(paths) = args.get("attachments").and_then(Value::as_array) {
        if paths.len() > 10 {
            return not_sent("at most 10 attachments per message");
        }
        for p in paths {
            let Some(path) = p.as_str() else {
                return not_sent("attachments must be file paths");
            };
            match crate::mail::read_attachment(path) {
                Ok(a) => attachments.push(a),
                Err(e) => return not_sent(e),
            }
        }
    }
    let (text, html) = crate::mail::render(body);
    let mail = crate::mail::OutMail {
        to: to.to_string(),
        subject,
        text,
        html,
        attachments,
        reply_to: None,
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(90),
        crate::mail::send(&config, &mail),
    )
    .await
    {
        Ok(Ok(msg)) => json!({"content": msg}),
        Ok(Err(e)) => not_sent(e),
        Err(_) => is_error(),
    }
}

/// The sidecar loop: one JSON request per stdin line, one `{"id", "result"}`
/// reply per line on stdout. `plugin/shutdown` and EOF exit.
pub fn serve(config_path: &Path) -> ! {
    use std::io::{BufRead, Write};
    const LIMIT: usize = 256 * 1024;
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("sidecar runtime builds");
    loop {
        let mut buf: Vec<u8> = Vec::new();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(_) => std::process::exit(1),
        };
        if n == 0 {
            std::process::exit(0);
        }
        if buf.len() > LIMIT {
            std::process::exit(1);
        }
        let text = match String::from_utf8(buf) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if text.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !req.is_object() {
            continue;
        }
        if req.get("method").and_then(Value::as_str) == Some("plugin/shutdown") {
            std::process::exit(0);
        }
        let id = match req.get("id") {
            Some(Value::Number(_)) => req.get("id").cloned().unwrap(),
            _ => continue,
        };
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let params = match req.get("params") {
            Some(Value::Object(_)) => req.get("params").cloned().unwrap(),
            _ => json!({}),
        };
        let result = rt.block_on(dispatch(method, &params, config_path));
        let row = json!({"id": id, "result": result});
        if writeln!(out, "{row}").is_err() {
            std::process::exit(1);
        }
        if out.flush().is_err() {
            std::process::exit(1);
        }
    }
}
