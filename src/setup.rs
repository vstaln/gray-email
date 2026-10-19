//! Interactive setup wizard.
//! Credentials stay in the wizard; the model never receives the password.
use serde_json::{json, Value};
use std::path::Path;

/// Terminal IO. The real implementation talks to stdin/stderr; tests inject
/// a scripted fake. `print_line` goes to user-visible output (never logs).
pub trait Prompter {
    fn is_terminal(&self) -> bool;
    fn prompt(&mut self, text: &str) -> Result<String, String>;
    fn prompt_hidden(&mut self, text: &str) -> Result<String, String>;
    fn confirm(&mut self, text: &str) -> Result<bool, String>;
    fn print_line(&mut self, text: &str);
}

/// Real terminal prompter (hidden input via `stty -echo`, no new deps).
pub struct Tty;

impl Prompter for Tty {
    fn is_terminal(&self) -> bool {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }
    fn prompt(&mut self, text: &str) -> Result<String, String> {
        use std::io::Write;
        let _ = std::io::stderr().write_all(text.as_bytes());
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|_| "cannot read terminal input".to_string())?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
    fn prompt_hidden(&mut self, text: &str) -> Result<String, String> {
        use std::io::Write;
        let _ = std::io::stderr().write_all(text.as_bytes());
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let res = without_echo(|| std::io::stdin().read_line(&mut line));
        let _ = std::io::stderr().write_all(b"\n");
        res.map_err(|_| "cannot read terminal input".to_string())?;
        Ok(line.trim().to_string())
    }
    fn confirm(&mut self, text: &str) -> Result<bool, String> {
        let answer = self.prompt(text)?.trim().to_ascii_lowercase();
        Ok(answer == "y" || answer == "yes")
    }
    fn print_line(&mut self, text: &str) {
        eprintln!("{text}");
    }
}

/// Echo off for one read. Ctrl-C would otherwise kill setup with the
/// terminal still silent, so SIGINT restores it first (tcsetattr is
/// async-signal-safe).
#[cfg(unix)]
fn without_echo<T>(read: impl FnOnce() -> T) -> T {
    static SAVED: std::sync::OnceLock<libc::termios> = std::sync::OnceLock::new();
    extern "C" fn restore_and_exit(_: libc::c_int) {
        if let Some(t) = SAVED.get() {
            unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
        }
        unsafe { libc::_exit(130) };
    }
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut term) } != 0 {
        return read();
    }
    let saved = *SAVED.get_or_init(|| term);
    let mut quiet = saved;
    quiet.c_lflag &= !libc::ECHO;
    let handler = restore_and_exit as extern "C" fn(libc::c_int) as libc::sighandler_t;
    let old = unsafe {
        libc::tcsetattr(0, libc::TCSANOW, &quiet);
        libc::signal(libc::SIGINT, handler)
    };
    let out = read();
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, &saved);
        libc::signal(libc::SIGINT, old);
    }
    out
}

/// Windows echo off for one read: clear ENABLE_ECHO_INPUT on the console
/// input buffer. A console control handler puts the mode back before the
/// default Ctrl-C processing kills setup, same shape as the unix version.
#[cfg(windows)]
fn without_echo<T>(read: impl FnOnce() -> T) -> T {
    use std::ffi::c_void;
    type Bool = i32;
    type Dword = u32;
    type Handle = *mut c_void;
    const STD_INPUT_HANDLE: Dword = -10i32 as Dword;
    const ENABLE_ECHO_INPUT: Dword = 0x0004;
    extern "system" {
        fn GetStdHandle(which: Dword) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut Dword) -> Bool;
        fn SetConsoleMode(handle: Handle, mode: Dword) -> Bool;
        fn SetConsoleCtrlHandler(
            handler: Option<extern "system" fn(Dword) -> Bool>,
            add: Bool,
        ) -> Bool;
    }
    static SAVED: std::sync::OnceLock<Dword> = std::sync::OnceLock::new();
    extern "system" fn restore(_: Dword) -> Bool {
        if let Some(&mode) = SAVED.get() {
            unsafe {
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
            }
        }
        0
    }
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if input.is_null() {
        return read();
    }
    let mut mode: Dword = 0;
    if unsafe { GetConsoleMode(input, &mut mode) } == 0 {
        return read();
    }
    let saved = *SAVED.get_or_init(|| mode);
    unsafe {
        SetConsoleMode(input, saved & !ENABLE_ECHO_INPUT);
        SetConsoleCtrlHandler(Some(restore), 1);
    }
    let out = read();
    unsafe {
        SetConsoleMode(input, saved);
        SetConsoleCtrlHandler(Some(restore), 0);
    }
    out
}

#[cfg(not(any(unix, windows)))]
fn without_echo<T>(read: impl FnOnce() -> T) -> T {
    read()
}

/// Resolve the gray binary (`GRAY_BIN` env or `PATH` lookup).
fn resolve_gray(explicit: &str) -> Option<String> {
    let candidate = explicit.trim();
    if candidate.is_empty() {
        return None;
    }
    if candidate.contains('/') || candidate.contains('\\') {
        let path = Path::new(candidate);
        if path.is_file() && is_executable(path) {
            return Some(candidate.to_string());
        }
        return None;
    }
    // Executables carry extensions on Windows (`gray` is `gray.exe`).
    let names: Vec<String> = {
        #[cfg(windows)]
        {
            [".exe", ".cmd", ".bat", ".com", ".ps1", ""]
                .iter()
                .map(|ext| format!("{candidate}{ext}"))
                .collect()
        }
        #[cfg(not(windows))]
        {
            vec![candidate.to_string()]
        }
    };
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        for name in &names {
            let full = dir.join(name);
            if full.is_file() && is_executable(&full) {
                return Some(full.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn absolutize(path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

fn shellexpand_home(raw: &str) -> String {
    if raw == "~" || raw.starts_with("~/") {
        if let Some(home) = crate::config::user_home() {
            return if raw == "~" {
                home.to_string_lossy().into_owned()
            } else {
                home.join(&raw[2..]).to_string_lossy().into_owned()
            };
        }
    }
    raw.to_string()
}

/// Split a comma-separated prompt answer into trimmed non-empty entries.
fn csv(answer: &str) -> Vec<String> {
    answer
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Dedupe keeping order, case-insensitively (addresses).
fn merge(prior: Vec<String>, extra: &[String]) -> Vec<String> {
    let mut out = prior;
    for e in extra {
        if !out.iter().any(|u| u.eq_ignore_ascii_case(e)) {
            out.push(e.clone());
        }
    }
    out
}

/// One port answer: blank takes the default, else 1-65535.
fn port_or(answer: &str, default: u64) -> Result<u64, String> {
    if answer.trim().is_empty() {
        return Ok(default);
    }
    let port: u64 = answer
        .trim()
        .parse()
        .map_err(|_| "Port must be a number between 1 and 65535".to_string())?;
    if !(1..=65535).contains(&port) {
        return Err("Port must be a number between 1 and 65535".to_string());
    }
    Ok(port)
}

/// One security answer: tls | starttls | plain.
fn security(answer: &str, default: &str) -> Result<String, String> {
    let s = answer.trim().to_lowercase();
    if s.is_empty() {
        return Ok(default.to_string());
    }
    match s.as_str() {
        "tls" | "ssl" | "implicit" => Ok("tls".to_string()),
        "starttls" => Ok("starttls".to_string()),
        "plain" | "none" => Ok("plain".to_string()),
        _ => Err("Security must be tls, starttls or plain".to_string()),
    }
}

/// The wizard: account credentials, IMAP and SMTP endpoints, the allowlist.
/// A live IMAP login + SELECT and an SMTP login prove the answers before
/// anything is called done.
pub async fn run(path: &Path, io: &mut dyn Prompter) -> Result<bool, String> {
    if !io.is_terminal() {
        return Err("Setup needs a terminal for hidden password input".to_string());
    }
    if path.exists() && !io.confirm("Replace existing configuration? [y/N] ")? {
        return Ok(false);
    }
    // Gray's binary and home are resolved silently (env, then the
    // conventional defaults) — derived facts, not questions.
    let gray = resolve_gray(&std::env::var("GRAY_BIN").unwrap_or_else(|_| "gray".to_string()))
        .ok_or_else(|| "Install gray first; executable not found".to_string())?;
    let gray_home = absolutize(Path::new(&shellexpand_home(
        &std::env::var("GRAY_HOME").unwrap_or_else(|_| "~/.gray".to_string()),
    )));

    // Whoever the old config allowed stays allowed: the wizard only adds.
    let prior = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .filter(Value::is_object);
    let prior_allowed: Vec<String> = prior
        .as_ref()
        .and_then(|p| p.get("allowed_senders"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    for line in [
        "Connect gray to an email mailbox (Gmail, Fastmail, your own server).",
        "The bot polls INBOX over IMAP and replies over SMTP; a live login",
        "against both checks the answers. Use an app password where the",
        "provider requires one (Gmail: myaccount.google.com/apppasswords).",
    ] {
        io.print_line(line);
    }

    let address = io.prompt("Email address the bot reads and sends from: ")?;
    let address = address.trim().to_lowercase();
    if !crate::config::addr_valid(&Value::String(address.clone())) {
        return Err("A full email address is required (you@example.com)".to_string());
    }
    let password = io.prompt_hidden("Password / app password: ")?;
    if password.is_empty() {
        return Err("A password is required".to_string());
    }

    io.print_line("Inbound (IMAP):");
    let imap_host = io.prompt("IMAP host (e.g. imap.gmail.com): ")?;
    let imap_host = imap_host.trim().to_string();
    if imap_host.is_empty() || imap_host.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("IMAP host is required (no spaces)".to_string());
    }
    let imap_security = security(
        &io.prompt("IMAP security: tls (993), starttls or plain (143) [tls]: ")?,
        "tls",
    )?;
    let default_port: u64 = if imap_security == "tls" { 993 } else { 143 };
    let imap_port = port_or(&io.prompt(&format!("IMAP port [{default_port}]: "))?, default_port)?;

    io.print_line("Outbound (SMTP):");
    let smtp_host = io.prompt("SMTP host (e.g. smtp.gmail.com): ")?;
    let smtp_host = smtp_host.trim().to_string();
    if smtp_host.is_empty() || smtp_host.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("SMTP host is required (no spaces)".to_string());
    }
    let smtp_security = security(
        &io.prompt("SMTP security: starttls (587), tls (465) or plain (25) [starttls]: ")?,
        "starttls",
    )?;
    let default_port: u64 = match smtp_security.as_str() {
        "tls" => 465,
        "plain" => 25,
        _ => 587,
    };
    let smtp_port = port_or(&io.prompt(&format!("SMTP port [{default_port}]: "))?, default_port)?;

    let poll_answer = io.prompt("Poll interval in seconds [60]: ")?;
    let poll_seconds: u64 = if poll_answer.trim().is_empty() {
        60
    } else {
        poll_answer
            .trim()
            .parse()
            .map_err(|_| "Poll interval must be a number of seconds".to_string())?
    };
    if !(5..=86400).contains(&poll_seconds) {
        return Err("Poll interval must be between 5 and 86400 seconds".to_string());
    }

    io.print_line(
        "Access control: only allowlisted From: addresses can trigger the bot. \
         Anyone else who writes gets a pairing code the owner can approve.",
    );
    let allowed_answer = io.prompt(
        "Allowed senders (comma-separated; first is usually yours — empty admits nobody): ",
    )?;
    let allowed: Vec<String> = csv(&allowed_answer)
        .iter()
        .map(|a| a.to_lowercase())
        .collect();
    if !allowed
        .iter()
        .all(|a| crate::config::addr_valid(&Value::String(a.clone())))
    {
        return Err("Allowed senders must be full email addresses".to_string());
    }
    let allowed = merge(prior_allowed, &allowed);

    let default_home = allowed
        .first()
        .cloned()
        .unwrap_or_else(|| address.clone());
    let home_answer = io.prompt(&format!(
        "Home address for cron/notices [{default_home}]: "
    ))?;
    let home_address = if home_answer.trim().is_empty() {
        default_home
    } else {
        let h = home_answer.trim().to_lowercase();
        if !crate::config::addr_valid(&Value::String(h.clone())) {
            return Err("Home address must be an email address".to_string());
        }
        h
    };

    // `path.parent` is the state dir; like the other adapters, the saved
    // config holds absolute paths or `save_config` validation rejects it.
    let workdir = path
        .parent()
        .map(|p| absolutize(p).to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let mut saved = json!({
        "address": address,
        "password": password,
        "imap_host": imap_host,
        "imap_port": imap_port,
        "imap_security": imap_security,
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_security": smtp_security,
        "poll_seconds": poll_seconds,
        "allowed_senders": allowed,
        "home_address": home_address,
        "gray_bin": absolutize(Path::new(&gray)).to_string_lossy(),
        "gray_home": gray_home.to_string_lossy(),
        "workdir": workdir,
        "session_reset": {
            "mode": "both",
            "idle_minutes": 1_440,
            "at_hour": 4
        }
    });
    // A re-run replaces only what the wizard asked about: limits and other
    // hand-tuned keys survive (unless they no longer validate).
    if let Some(mut merged) = prior {
        for (k, v) in saved.as_object().into_iter().flatten() {
            if k != "session_reset" || merged.get(k).is_none() {
                merged[k] = v.clone();
            }
        }
        if crate::config::validate_config(&merged).is_ok() {
            saved = merged;
        }
    }
    crate::config::save_config(path, &saved)?;
    io.print_line("Configuration saved privately.");

    // Prove it with live logins before anyone is told it worked.
    crate::doctor::doctor(&saved).await.map_err(|e| {
        format!("Saved, but the doctor disagreed: {e}. Fix it, then run `gray email doctor` and `gray email install`.")
    })?;
    io.print_line("Doctor verified the configuration.");
    Ok(true)
}
