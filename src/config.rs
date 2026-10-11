//! Private config load/save/validate.
//! Errors never contain config values.
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Default config path: ~/.config/gray-email/config.json
pub fn default_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config/gray-email/config.json")
}

/// Write JSON (pretty + trailing newline) atomically: parents 0700,
/// temp file + rename, replacement mode 0600.
pub fn atomic_json(path: &Path, data: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|_| "cannot create config directory".to_string())?;
        }
    }
    let mut text =
        serde_json::to_string_pretty(data).map_err(|_| "cannot encode config".to_string())?;
    text.push('\n');
    let tmp_path = path.with_extension("tmp");
    // Born 0600: passwords are never readable by others, not even briefly.
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .map_err(|_| "cannot write config".to_string())?;
    }
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect config".to_string())?;
    fs::rename(&tmp_path, path).map_err(|_| "cannot replace config".to_string())?;
    Ok(())
}

fn int_in(data: &Value, key: &str, low: u64, high: u64) -> Result<(), String> {
    if let Some(v) = data.get(key) {
        let ok = v.as_u64().is_some_and(|n| (low..=high).contains(&n));
        if !ok {
            return Err(format!("{key} must be an integer between {low} and {high}"));
        }
    }
    Ok(())
}

/// A plausible mailbox address: `local@domain`, no whitespace/controls,
/// <=254 chars. Deliberately permissive — the wire decides for real.
pub fn addr_valid(v: &Value) -> bool {
    match v.as_str() {
        Some(s) => {
            let s = s.trim();
            if s.is_empty() || s.len() > 254 || s.bytes().any(|b| b <= b' ' || b == 0x7f) {
                return false;
            }
            let Some((local, domain)) = s.rsplit_once('@') else {
                return false;
            };
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

/// A message target: any well-formed address the allowlist could hold.
pub fn target_valid(v: &Value) -> bool {
    addr_valid(v)
}

/// "tls" | "starttls" | "plain" — anything else is a typo that must not
/// silently downgrade.
pub fn security_valid(v: &Value) -> bool {
    matches!(v.as_str(), Some("tls" | "starttls" | "plain"))
}

fn str_nonempty(data: &Value, key: &str) -> Result<(), String> {
    match data.get(key).and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => Ok(()),
        _ => Err(format!("{key} is missing; run setup")),
    }
}

/// Validate a config object. Error texts never echo config values.
pub fn validate_config(data: &Value) -> Result<(), String> {
    if !data.is_object() {
        return Err("Configuration must be an object".to_string());
    }
    if !addr_valid(data.get("address").unwrap_or(&Value::Null)) {
        return Err("address must be a valid email address".to_string());
    }
    str_nonempty(data, "password")?;
    str_nonempty(data, "imap_host")?;
    str_nonempty(data, "smtp_host")?;
    match data.get("allowed_senders").and_then(Value::as_array) {
        Some(a) if a.iter().all(addr_valid) => {}
        _ => return Err("allowed_senders must be an array of email addresses".to_string()),
    }
    int_in(data, "imap_port", 1, 65535)?;
    int_in(data, "smtp_port", 1, 65535)?;
    int_in(data, "poll_seconds", 5, 86400)?;
    int_in(data, "timeout_seconds", 1, 86400)?;
    int_in(data, "max_requests", 1, 1000)?;
    int_in(data, "queue_capacity", 1, 100000)?;
    if data
        .get("busy_input_mode")
        .is_some_and(|v| !matches!(v.as_str(), Some("queue" | "steer")))
    {
        return Err("busy_input_mode must be queue or steer".to_string());
    }
    int_in(data, "concurrency", 1, 16)?;
    for key in ["imap_security", "smtp_security"] {
        if let Some(v) = data.get(key) {
            if !security_valid(v) {
                return Err(format!("{key} must be tls, starttls or plain"));
            }
        }
    }
    if let Some(t) = data.get("restart_notification") {
        if !t.is_boolean() {
            return Err("restart_notification must be true or false".to_string());
        }
    }
    if let Some(h) = data.get("home_address") {
        if !h.is_null() && !addr_valid(h) {
            return Err("home_address must be an email address".to_string());
        }
    }
    for key in ["gray_bin", "gray_home", "workdir"] {
        let ok = data
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| Path::new(s).is_absolute());
        if !ok {
            return Err(format!("{key} must be an absolute path"));
        }
    }
    Ok(())
}

/// Load + validate. Any IO/parse failure maps to the setup hint.
pub fn load_config(path: &Path) -> Result<Value, String> {
    let data: Value = fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| "Configuration missing or invalid; run setup".to_string())?;
    validate_config(&data)?;
    Ok(data)
}

/// Validate + atomic save.
pub fn save_config(path: &Path, data: &Value) -> Result<(), String> {
    validate_config(data)?;
    atomic_json(path, data)
}

/// One string config value, or "".
pub fn cfg_str<'a>(config: &'a Value, key: &str) -> &'a str {
    config.get(key).and_then(Value::as_str).unwrap_or("")
}
