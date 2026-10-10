//! Doctor preflight checks with safe errors.
//! Every failure is a category string; config values never surface.
use serde_json::Value;

/// Production entry point: checks `config` locally, then opens a real IMAP
/// session (login + SELECT) and a real SMTP submit login on the live hosts.
pub async fn doctor(config: &Value) -> Result<(), String> {
    let gray_bin = config.get("gray_bin").and_then(Value::as_str).unwrap_or("");
    if !is_executable(gray_bin) {
        return Err("gray executable is missing or not executable".to_string());
    }
    let gray_home = config
        .get("gray_home")
        .and_then(Value::as_str)
        .unwrap_or("");
    let provider: Value = std::fs::read(std::path::Path::new(gray_home).join("config.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| "gray provider configuration is missing or invalid".to_string())?;
    if provider
        .get("model")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("gray has no configured model".to_string());
    }
    let mut inbox = crate::mail::connect(config).await?;
    inbox.logout().await;
    println!("IMAP connect, TLS handshake, login and INBOX select verified.");
    println!("SMTP check next — sending a real login+logout round trip.");
    smtp_probe(config).await?;
    println!("SMTP connect, TLS negotiation and login verified.");
    println!("Fetching mail and provider generation were not tested.");
    Ok(())
}

/// Open the SMTP transport and prove the credentials with a login. lettre
/// connects lazily, so `test_connection` is what touches the wire.
async fn smtp_probe(config: &Value) -> Result<(), String> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, Tokio1Executor};
    let host = config
        .get("smtp_host")
        .and_then(Value::as_str)
        .unwrap_or("");
    let security = config
        .get("smtp_security")
        .and_then(Value::as_str)
        .unwrap_or("starttls");
    let port = config
        .get("smtp_port")
        .and_then(Value::as_u64)
        .map(|p| p.clamp(1, 65535) as u16)
        .unwrap_or(if security == "tls" { 465 } else { 587 });
    let creds = Credentials::new(
        config
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        config
            .get("password")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    );
    let transport: lettre::AsyncSmtpTransport<Tokio1Executor> = match security {
        "plain" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .credentials(creds)
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build(),
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| format!("SMTP configuration failed: {e}"))?
            .port(port)
            .credentials(creds)
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build(),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| format!("SMTP configuration failed: {e}"))?
            .port(port)
            .credentials(creds)
            .timeout(Some(std::time::Duration::from_secs(30)))
            .build(),
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(45),
        transport.test_connection(),
    )
    .await
    .map_err(|_| "SMTP probe timed out".to_string())?
    .map_err(|e| format!("SMTP probe failed: {e}"))?;
    Ok(())
}

/// `os.access(path, X_OK)` equivalent: a real file with any exec bit set.
fn is_executable(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}
