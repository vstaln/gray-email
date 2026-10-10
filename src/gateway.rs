//! The email daemon: poll INBOX over IMAP -> header preflight -> durable
//! inbox -> isolated gray turns -> SMTP replies out.
//!
//! Admission mirrors the other adapters: the From: address must be on
//! `allowed_senders`; automated/bulk mail is silently dropped; an
//! un-admitted human sender gets a pairing reply instead of silence.
//! UID tracking: a durable `uid_floor` in the store plus the \\Seen flag
//! mean a restart neither replays the backlog nor re-delivers seen mail.
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::mail::{Inbox, OutMail};
use crate::runner::RunError;
use crate::store::Store;

/// The queue file next to the config.
pub fn open_store(config_path: &Path) -> Result<Store, String> {
    Store::new(&Store::default_path(config_path))
}

struct Daemon {
    config: Value,
    config_path: PathBuf,
    store: Store,
}

impl Daemon {
    fn home_address(&self) -> String {
        self.config
            .get("home_address")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                self.config
                    .get("allowed_senders")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default()
    }

    /// Addresses compare case-insensitively; the allowlist decides who gets
    /// a turn. An empty list admits nobody.
    fn sender_admitted(&self, addr: &str) -> bool {
        !addr.is_empty()
            && self
                .config
                .get("allowed_senders")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .any(|u| u.eq_ignore_ascii_case(addr))
                })
                .unwrap_or(false)
    }

    /// One claimed inbox item end to end. A generated answer retries
    /// delivery instead of regenerating; a Busy conversation waits.
    async fn work(&self) -> Result<bool, String> {
        let Some(item) = self.store.claim()? else {
            return Ok(false);
        };
        let outcome = crate::runner::run_gray(
            &self.config,
            &self.config_path,
            &item.conversation,
            &item.text,
            None,
        )
        .await;
        match outcome {
            Ok(answer) => {
                let (text, html) = crate::mail::render(&answer);
                let mail = OutMail {
                    to: item.target.clone(),
                    subject: crate::mail::reply_subject(&item.subject),
                    text,
                    html,
                    attachments: Vec::new(),
                    reply_to: if item.msg_id.is_empty() {
                        None
                    } else {
                        Some(item.msg_id.clone())
                    },
                };
                let mut attempts = 0u32;
                loop {
                    match crate::mail::send(&self.config, &mail).await {
                        Ok(_) => {
                            self.store.complete(&item.id, &answer)?;
                            break;
                        }
                        Err(e) => {
                            attempts += 1;
                            if attempts > 3 {
                                self.store
                                    .fail(&item.id, &format!("delivery failed: {e}"))?;
                                break;
                            }
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }
            }
            Err(RunError::Busy) => {
                self.store.requeue(&item.id)?;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                let _ = say(
                    &self.config,
                    &item.target,
                    &crate::mail::reply_subject(&item.subject),
                    &e.to_string(),
                    if item.msg_id.is_empty() {
                        None
                    } else {
                        Some(&item.msg_id)
                    },
                )
                .await;
                self.store.fail(&item.id, &e.to_string())?;
            }
        }
        Ok(true)
    }
}

/// One plain notice email (pairing replies, lifecycle, queue-full, errors).
async fn say(
    config: &Value,
    to: &str,
    subject: &str,
    text: &str,
    reply_to: Option<&str>,
) -> Result<(), String> {
    if !crate::config::addr_valid(&Value::String(to.to_string())) {
        return Err("notice target is not a valid address".to_string());
    }
    let (plain, html) = crate::mail::render(text);
    crate::mail::send(
        config,
        &OutMail {
            to: to.to_string(),
            subject: subject.to_string(),
            text: plain,
            html,
            attachments: Vec::new(),
            reply_to: reply_to.map(str::to_string),
        },
    )
    .await
    .map(|_| ())
}

/// Header preflight + full fetch + enqueue for one unseen uid. Every path
/// advances the floor so one poison message cannot stall the poll.
async fn process_uid(daemon: &Daemon, inbox: &mut Inbox, uid: u32) -> Result<(), String> {
    let head = match inbox.head(uid).await {
        Ok(Some(h)) => h,
        Ok(None) => return Ok(()), // unreadable headers: mark seen, move on
        Err(e) => return Err(e),   // transport trouble: reconnect
    };
    if head.from.is_empty() || head.automated {
        inbox.mark_seen(uid).await;
        return Ok(());
    }
    if !daemon.sender_admitted(&head.from) {
        if let Some(reply) = crate::pairing::reply_for(&daemon.store, &head.from, false) {
            let _ = say(
                &daemon.config,
                &head.from,
                &crate::mail::reply_subject(&head.subject),
                &reply.text,
                if head.msg_id.is_empty() {
                    None
                } else {
                    Some(&head.msg_id)
                },
            )
            .await;
        }
        inbox.mark_seen(uid).await;
        return Ok(());
    }
    let raw = inbox.raw(uid).await?;
    let spool = crate::mail::spool_dir(&daemon.config_path);
    let mail = match crate::mail::parse_full(head, uid, &raw, &spool) {
        Ok(m) => m,
        Err(e) => {
            // One unparseable message must not stall the poll: mark seen,
            // log, move on.
            eprintln!("[email] could not parse uid {uid}: {e}");
            inbox.mark_seen(uid).await;
            return Ok(());
        }
    };
    if mail.text.trim().is_empty() {
        inbox.mark_seen(uid).await;
        return Ok(());
    }
    let conversation = crate::session::conversation_key(&mail.from);
    let capacity = daemon
        .config
        .get("queue_capacity")
        .and_then(Value::as_u64)
        .unwrap_or(1000);
    match daemon.store.enqueue(
        &mail.from,
        &mail.from,
        &conversation,
        &mail.text,
        &mail.subject,
        &mail.msg_id,
        capacity,
    ) {
        Ok(id) => eprintln!("[email] queued {id} from {} (uid {uid})", mail.from),
        Err(e) => {
            let _ = say(
                &daemon.config,
                &mail.from,
                &crate::mail::reply_subject(&mail.subject),
                &format!("Queue full ({e}); try again later."),
                if mail.msg_id.is_empty() {
                    None
                } else {
                    Some(&mail.msg_id)
                },
            )
            .await;
        }
    }
    inbox.mark_seen(uid).await;
    Ok(())
}

/// Connect -> baseline -> poll until the connection fails or shutdown.
/// `notice` is mailed to the home address once, on the first poll.
async fn poll_session(
    daemon: &Daemon,
    shutdown: &tokio::sync::Notify,
    notice: &mut Option<String>,
) -> Result<(), String> {
    let mut inbox = crate::mail::connect(&daemon.config).await?;
    // First-ever connect skips the backlog: the floor starts at UIDNEXT-1.
    let mut floor: u32 = match daemon
        .store
        .meta_get("uid_floor")
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
    {
        Some(f) => f,
        None => {
            let f = inbox.uid_next.saturating_sub(1);
            let _ = daemon.store.meta_set("uid_floor", &f.to_string());
            eprintln!("[email] first poll: {} existing messages skipped", f);
            f
        }
    };
    if let Some(text) = notice.take() {
        let home = daemon.home_address();
        if !home.is_empty() {
            let _ = say(&daemon.config, &home, "gray email gateway", &text, None).await;
        }
    }
    let poll_secs = daemon
        .config
        .get("poll_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(60)
        .clamp(5, 86400);
    loop {
        let uids = inbox.new_uids(floor).await?;
        for uid in uids {
            if let Err(e) = process_uid(daemon, &mut inbox, uid).await {
                return Err(e);
            }
            floor = floor.max(uid);
            let _ = daemon.store.meta_set("uid_floor", &floor.to_string());
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(poll_secs)) => {},
            _ = shutdown.notified() => break,
        }
    }
    inbox.logout().await;
    Ok(())
}

fn config_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

/// The daemon: lock + pidfile, workers, reconnect loop, graceful stop.
pub async fn run(config_path: &Path) -> Result<(), String> {
    let dir = config_dir(config_path);
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(&dir)
        .map_err(|_| "cannot create config directory".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    // daemon.json: `status` and lifecycle read it; removed on every exit.
    let pid_path = dir.join("daemon.json");
    {
        let stamp = serde_json::json!({
            "pid": std::process::id(),
            "started_at": crate::store::now_secs()
        });
        let _ = crate::config::atomic_json(&pid_path, &stamp);
    }
    struct RemovePid(PathBuf);
    impl Drop for RemovePid {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _remove_pid = RemovePid(pid_path);

    // One daemon per config: two would double-poll the same mailbox.
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("gateway.lock"))
        .map_err(|_| "cannot open gateway lock".to_string())?;
    use std::os::unix::io::AsRawFd;
    let locked = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if !locked {
        return Err("Another gateway is running".to_string());
    }
    let _lock = lock_file;

    let config = crate::config::load_config(config_path)?;
    let store = open_store(config_path)?;
    let interrupted = store.recover().unwrap_or(0);

    let daemon = Arc::new(Daemon {
        config: config.clone(),
        config_path: config_path.to_path_buf(),
        store,
    });

    // Boot notice is computed now (it records lifecycle state) and mailed
    // on the first successful IMAP connect.
    let gray_bin = Path::new(crate::config::cfg_str(&daemon.config, "gray_bin"));
    let mut notice = if crate::lifecycle::enabled(&daemon.config) {
        crate::lifecycle::boot_via(gray_bin, &dir, interrupted).await
    } else {
        let _ = crate::lifecycle::boot(&dir);
        None
    };

    // Workers drain the inbox; the poll loop only ever enqueues.
    let workers = daemon
        .config
        .get("concurrency")
        .and_then(Value::as_u64)
        .unwrap_or(2)
        .clamp(1, 16);
    let stop = Arc::new(tokio::sync::Notify::new());
    let mut handles = Vec::new();
    for _ in 0..workers {
        let d = daemon.clone();
        let stop = stop.clone();
        handles.push(tokio::spawn(async move {
            loop {
                match d.work().await {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => eprintln!("[email] worker error: {e}"),
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {},
                    _ = stop.notified() => break,
                }
            }
        }));
    }

    let shutdown = Arc::new(tokio::sync::Notify::new());
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("SIGINT handler");
            tokio::select! {
                _ = term.recv() => {},
                _ = int.recv() => {},
            }
            shutdown.notify_waiters();
        });
    }

    let mut backoff = Duration::from_secs(1);
    'outer: loop {
        match poll_session(&daemon, &shutdown, &mut notice).await {
            Ok(()) => break 'outer,
            Err(e) => {
                eprintln!("[email] {e}; reconnecting in {}s", backoff.as_secs());
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {},
                    _ = shutdown.notified() => break 'outer,
                }
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        }
    }

    eprintln!("[email] shutting down");
    // Goodbye notices go out over SMTP before the workers are dropped.
    let running: Vec<String> = daemon
        .store
        .running_targets()
        .map(|items| items.into_iter().map(|i| i.target).collect())
        .unwrap_or_default();
    let gray_bin = Path::new(crate::config::cfg_str(&daemon.config, "gray_bin"));
    let goodbye = crate::lifecycle::stop_via(gray_bin, &dir).await;
    let home = daemon.home_address();
    for (target, text) in crate::lifecycle::shutdown_targets(&running, &home, &goodbye) {
        let _ = say(&daemon.config, &target, "gray email gateway", text, None).await;
    }

    stop.notify_waiters();
    for h in handles {
        h.abort();
    }
    // If shutdown happened between connects, still record a clean exit so
    // the next boot does not report a crash.
    if std::fs::read(dir.join(crate::lifecycle::STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|s| s.get("state").and_then(Value::as_str).map(str::to_string))
        .as_deref()
        == Some("running")
    {
        let restart = crate::lifecycle::restart_requested(&dir);
        crate::lifecycle::mark_stopped(&dir, restart);
    }
    Ok(())
}
