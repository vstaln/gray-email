//! Email-side pairing. A sender the allowlist does not admit gets a reply
//! carrying their own address and a one-shot code; the owner approves the
//! code with `gray email pairing approve email <code>` and that address
//! joins the allowlist. The discovery happens where the user already is.

use serde_json::Value;
use std::path::Path;

/// A fresh code: 8 uppercase alphanumerics (short enough
/// to read off a phone, 36^8 space, single-use).
pub fn gen_code() -> String {
    const ALPHABET: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = [0u8; 8];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut bytes);
        }
    }
    bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// The reply an un-admitted sender sees. From: is trivially forged — the
/// note says so once, then carries on.
pub fn unconfigured_reply(addr: &str, code: &str) -> String {
    format!(
        "access not configured.\n\
         Your address: {addr}\n\
         Pairing code: {code}\n\
         Ask the bot owner to approve with:\n\
         gray email pairing approve email {code}"
    )
}

/// What the gateway sends when mail arrives from an address the allowlist
/// does not hold: mint (or reuse) a code and reply. Admitted senders and
/// automated mail never see this — `None` for them.
pub struct PairingReply {
    pub text: String,
    #[allow(dead_code)]
    pub code: String,
}

pub fn reply_for(
    store: &crate::store::Store,
    addr: &str,
    admitted: bool,
) -> Option<PairingReply> {
    if admitted || addr.is_empty() {
        return None;
    }
    let code = store
        .pairing_code_for(addr)
        .ok()
        .flatten()
        .unwrap_or_else(gen_code);
    store.pairing_insert(&code, addr).ok()?;
    Some(PairingReply {
        text: unconfigured_reply(addr, &code),
        code,
    })
}

/// Consume a code and admit its address into `allowed_senders`. Config is
/// rewritten privately (0600) exactly as the wizard would.
pub fn approve(config_path: &Path, platform: &str, code: &str) -> Result<String, String> {
    if platform != "email" {
        return Err(format!(
            "unknown platform '{platform}'; the only one is email"
        ));
    }
    let store = crate::gateway::open_store(config_path)?;
    let addr = store
        .pairing_take(code.trim())?
        .ok_or_else(|| "unknown or already-used pairing code".to_string())?;
    if !crate::config::addr_valid(&Value::String(addr.clone())) {
        return Err("pairing code did not resolve to an email address".to_string());
    }
    let mut config = crate::config::load_config(config_path)?;
    let mut allowed: Vec<String> = config
        .get("allowed_senders")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if allowed.iter().any(|u| u.eq_ignore_ascii_case(&addr)) {
        return Ok(format!("{addr} was already allowed"));
    }
    allowed.push(addr.clone());
    config["allowed_senders"] = Value::Array(allowed.into_iter().map(Value::String).collect());
    crate::config::save_config(config_path, &config)?;
    Ok(format!(
        "{addr} can now trigger the bot; restart the gateway to apply (it re-reads on start)"
    ))
}
