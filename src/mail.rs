//! IMAP poll + SMTP submit: the wire half of the adapter.
//! Inbound: UNSEEN above the uid floor, header preflight (allowlist +
//! automated-sender filter) before the body is fetched, MIME parse,
//! attachments spooled to disk. Outbound: lettre SMTP submit with a
//! text+html alternative built from the agent's markdown reply.
use futures_util::StreamExt;
use serde_json::Value;
use std::fmt;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Gmail-safe cap on one reply body (hermes parity).
pub const MAX_BODY: usize = 50_000;
/// Refuse attachments larger than this, in or out.
pub const MAX_ATTACHMENT: usize = 20 * 1024 * 1024;
const HEADER_QUERY: &str = "BODY.PEEK[HEADER.FIELDS (FROM SUBJECT MESSAGE-ID \
    AUTO-SUBMITTED PRECEDENCE LIST-UNSUBSCRIBE X-AUTO-RESPONSE-SUPPRESS)]";
/// The pre-auth header fetch never downloads more than this.
const HEADER_CAP: usize = 64 * 1024;
/// The full-message fetch never downloads more than this.
const BODY_CAP: usize = 8 * 1024 * 1024;

/// Address substrings that mark an automated sender: silently skipped.
const NOREPLY: &[&str] = &[
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "mailer-daemon",
    "postmaster",
    "bounce",
    "notifications@",
    "automated@",
    "auto-confirm",
    "auto-reply",
    "automailer",
];

trait Io: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send> Io for T {}
type Stream = Box<dyn Io>;
type ImapSession = async_imap::Session<Stream>;

/// One sanitized transport failure: never contains config values.
fn wire(e: impl std::fmt::Display) -> String {
    let text = e.to_string();
    let first = text.lines().next().unwrap_or("").trim();
    if first.len() > 160 {
        let mut end = 160;
        while !first.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &first[..end])
    } else {
        first.to_string()
    }
}

fn cfg<'a>(config: &'a Value, key: &str) -> &'a str {
    config.get(key).and_then(Value::as_str).unwrap_or("")
}

fn cfg_port(config: &Value, key: &str, default: u16) -> u16 {
    config
        .get(key)
        .and_then(Value::as_u64)
        .map(|p| p.clamp(1, 65535) as u16)
        .unwrap_or(default)
}

fn tls_connector() -> tokio_rustls::TlsConnector {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(client))
}

async fn tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|_| format!("cannot resolve the IMAP host {host:?}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve the IMAP host {host:?}"))?;
    tokio::time::timeout(Duration::from_secs(30), TcpStream::connect(addr))
        .await
        .map_err(|_| "timed out connecting to the IMAP server".to_string())?
        .map_err(wire)
}

async fn tls<S>(host: &str, stream: S) -> Result<tokio_rustls::client::TlsStream<S>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send + 'static,
{
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| format!("invalid IMAP host name {host:?}"))?;
    tokio::time::timeout(
        Duration::from_secs(30),
        tls_connector().connect(name, stream),
    )
    .await
    .map_err(|_| "timed out in the IMAP TLS handshake".to_string())?
    .map_err(wire)
}

/// One CRLF line off a raw pre-TLS socket, byte at a time so nothing past
/// the line is consumed before the TLS upgrade.
async fn raw_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let mut b = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut b))
            .await
            .map_err(|_| "timed out waiting for the IMAP server".to_string())?
            .map_err(wire)?;
        if n == 0 {
            return Err("IMAP server closed the connection".to_string());
        }
        if b[0] == b'\n' {
            break;
        }
        if buf.len() >= 8192 {
            return Err("overlong IMAP line".to_string());
        }
        buf.push(b[0]);
    }
    String::from_utf8(buf).map_err(|_| "non-UTF-8 IMAP greeting".to_string())
}

/// STARTTLS on 143: greeting, `STARTTLS`, tagged OK, then the TLS upgrade.
/// The post-upgrade session has no second greeting — `Client::new` does not
/// need one.
async fn starttls(
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let mut stream = tcp(host, port).await?;
    let greeting = raw_line(&mut stream).await?;
    if greeting.contains(" BYE") || greeting.starts_with("* PREAUTH") {
        return Err("IMAP server refused the connection".to_string());
    }
    stream.write_all(b"a1 STARTTLS\r\n").await.map_err(wire)?;
    let mut ok = false;
    for _ in 0..16 {
        let line = raw_line(&mut stream).await?;
        if let Some(rest) = line.strip_prefix("a1 ") {
            ok = rest.starts_with("OK");
            break;
        }
    }
    if !ok {
        return Err("IMAP server refused STARTTLS".to_string());
    }
    tls(host, stream).await
}

/// A logged-in IMAP session on INBOX plus the UIDNEXT seen at SELECT.
pub struct Inbox {
    session: ImapSession,
    /// UIDNEXT at SELECT time: the first-connect baseline.
    pub uid_next: u32,
}

/// Connect, log in, select INBOX. Errors never contain the password.
pub async fn connect(config: &Value) -> Result<Inbox, String> {
    let host = cfg(config, "imap_host");
    if host.is_empty() {
        return Err("imap_host is not configured".to_string());
    }
    let security = cfg(config, "imap_security");
    let security = if security.is_empty() { "tls" } else { security };
    let port = cfg_port(
        config,
        "imap_port",
        if security == "tls" { 993 } else { 143 },
    );
    let stream: Stream = match security {
        "plain" => Box::new(tcp(host, port).await?),
        "starttls" => Box::new(starttls(host, port).await?),
        _ => Box::new(tls(host, tcp(host, port).await?).await?),
    };
    let client = async_imap::Client::new(stream);
    let mut session = client
        .login(cfg(config, "address"), cfg(config, "password"))
        .await
        .map_err(|(e, _)| format!("IMAP login failed: {}", wire(e)))?;
    // 163/NetEase require RFC 2971 ID after LOGIN; only when advertised.
    if let Ok(caps) = session.capabilities().await {
        if caps.has_str("ID") {
            let _ = session
                .id([
                    ("name", Some("gray-email")),
                    ("version", Some(env!("CARGO_PKG_VERSION"))),
                ])
                .await;
        }
    }
    let mbox = session
        .select("INBOX")
        .await
        .map_err(|e| format!("cannot select INBOX: {}", wire(e)))?;
    Ok(Inbox {
        session,
        uid_next: mbox.uid_next.unwrap_or(1),
    })
}

impl Inbox {
    /// UNSEEN uids above `floor`, oldest first.
    pub async fn new_uids(&mut self, floor: u32) -> Result<Vec<u32>, String> {
        let set = self
            .session
            .uid_search("UNSEEN")
            .await
            .map_err(|e| format!("IMAP search failed: {}", wire(e)))?;
        let mut uids: Vec<u32> = set.into_iter().filter(|u| *u > floor).collect();
        uids.sort_unstable();
        Ok(uids)
    }

    /// Header-only preflight for one uid.
    pub async fn head(&mut self, uid: u32) -> Result<Option<Head>, String> {
        let fetches = self
            .session
            .uid_fetch(uid.to_string(), HEADER_QUERY)
            .await
            .map_err(|e| format!("IMAP header fetch failed: {}", wire(e)))?;
        tokio::pin!(fetches);
        let mut head = None;
        while let Some(item) = fetches.next().await {
            let f = item.map_err(|e| format!("IMAP header fetch failed: {}", wire(e)))?;
            if let Some(raw) = f.header() {
                let raw = &raw[..raw.len().min(HEADER_CAP)];
                head = parse_head(raw);
                break;
            }
        }
        Ok(head)
    }

    /// The full RFC822 bytes for one uid, capped.
    pub async fn raw(&mut self, uid: u32) -> Result<Vec<u8>, String> {
        let fetches = self
            .session
            .uid_fetch(uid.to_string(), "BODY.PEEK[]")
            .await
            .map_err(|e| format!("IMAP fetch failed: {}", wire(e)))?;
        tokio::pin!(fetches);
        while let Some(item) = fetches.next().await {
            let f = item.map_err(|e| format!("IMAP fetch failed: {}", wire(e)))?;
            if let Some(body) = f.body() {
                return Ok(body[..body.len().min(BODY_CAP)].to_vec());
            }
        }
        Err("IMAP fetch returned no message body".to_string())
    }

    /// Best-effort \Seen so the next poll does not re-deliver.
    pub async fn mark_seen(&mut self, uid: u32) {
        if let Ok(fetches) = self
            .session
            .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Seen)")
            .await
        {
            tokio::pin!(fetches);
            while fetches.next().await.is_some() {}
        }
    }

    pub async fn noop(&mut self) -> Result<(), String> {
        self.session
            .noop()
            .await
            .map_err(|e| format!("IMAP noop failed: {}", wire(e)))
    }

    pub async fn logout(&mut self) {
        let _ = self.session.logout().await;
    }
}

/// The headers needed to admit or drop a sender before the body is fetched.
pub struct Head {
    /// Bare lowercased addr-spec from From:; "" drops the message.
    pub from: String,
    pub subject: String,
    pub msg_id: String,
    /// Automated/bulk mail the bot never answers.
    pub automated: bool,
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let msg = mail_parser::MessageParser::default().parse_headers(raw)?;
    let from = msg
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address.as_ref())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && s.contains('@'))
        .unwrap_or_default();
    let mut automated = false;
    let mut subject = String::new();
    let mut msg_id = String::new();
    for (name, value) in msg.headers_raw() {
        let lower = value.trim().to_lowercase();
        match name {
            "Subject" => subject = value.trim().to_string(),
            "Message-ID" => msg_id = value.trim().to_string(),
            "Auto-Submitted" => automated |= lower != "no" && !lower.is_empty(),
            "Precedence" => automated |= matches!(lower.as_str(), "bulk" | "list" | "junk"),
            "List-Unsubscribe" | "X-Auto-Response-Suppress" => automated |= !lower.is_empty(),
            _ => {}
        }
    }
    automated |= NOREPLY.iter().any(|p| from.contains(p));
    Some(Head {
        from,
        subject,
        msg_id,
        automated,
    })
}

/// What the gateway enqueues for one admitted message.
pub struct InMail {
    pub from: String,
    pub subject: String,
    pub msg_id: String,
    /// Plain text body, spooled attachment paths appended as a list.
    pub text: String,
}

/// Decode the best text body: text/plain preferred; text/html stripped as a
/// fallback (mirrors hermes `_extract_text_body`).
pub fn body_text(msg: &mail_parser::Message) -> String {
    if let Some(text) = msg.body_text(0) {
        return text.trim().to_string();
    }
    if let Some(html) = msg.body_html(0) {
        return strip_html(&html).trim().to_string();
    }
    String::new()
}

/// Naive HTML tag stripper for the no-plain-part fallback.
pub fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    loop {
        match rest.find('<') {
            None => {
                out.push_str(rest);
                break;
            }
            Some(i) => {
                out.push_str(&rest[..i]);
                let after = &rest[i..];
                let Some(end) = after.find('>') else { break };
                let mut cap = end.min(8);
                while !after.is_char_boundary(cap) {
                    cap -= 1;
                }
                let tag = &after[..cap];
                let t = tag.trim_start_matches('<').trim_start_matches('/');
                if t.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("br"))
                    || t.starts_with(|c: char| c.eq_ignore_ascii_case(&'p'))
                {
                    out.push('\n');
                }
                rest = &after[end + 1..];
            }
        }
    }
    let mut out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    out
}

fn safe_filename(raw: &str, uid: u32, index: usize) -> String {
    let mut name: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if name.is_empty() || name.starts_with('.') {
        name = format!("part{index}");
    }
    format!("{uid}-{name}")
}

/// The attachment spool directory beside the config file.
pub fn spool_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("attachments")
}

/// Parse a full message and spool its attachments. Returns the sender,
/// subject, message-id and the prompt text (subject + body + spool paths).
pub fn parse_full(head: Head, uid: u32, raw: &[u8], spool: &Path) -> Result<InMail, String> {
    let Some(msg) = mail_parser::MessageParser::default().parse(raw) else {
        return Err("could not parse the message".to_string());
    };
    let mut text = format!("Subject: {}\n\n", head.subject);
    let body = body_text(&msg);
    text.push_str(&body[..body.len().min(MAX_BODY)]);
    if body.len() > MAX_BODY {
        text.push_str("\n\n[body truncated]");
    }

    let mut saved: Vec<String> = Vec::new();
    for (i, part) in msg.attachments().enumerate() {
        use mail_parser::MimeHeaders;
        let name = part.attachment_name().unwrap_or("attachment");
        let bytes = part.contents();
        if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT {
            saved.push(format!("- {name} (skipped: too large or empty)"));
            continue;
        }
        if let Err(e) = std::fs::create_dir_all(spool) {
            return Err(format!("cannot create attachment spool: {e}"));
        }
        let path = spool.join(safe_filename(name, uid, i));
        if std::fs::write(&path, bytes).is_err() {
            saved.push(format!("- {name} (could not be saved)"));
            continue;
        }
        saved.push(format!("- {} ({})", path.display(), name));
    }
    if !saved.is_empty() {
        text.push_str("\n\nAttachments saved to disk:\n");
        text.push_str(&saved.join("\n"));
    }
    Ok(InMail {
        from: head.from,
        subject: head.subject,
        msg_id: head.msg_id,
        text,
    })
}

// ---------------------------------------------------------------------------
// outbound
// ---------------------------------------------------------------------------

/// One file to attach (path + guessed content type).
pub struct OutAttachment {
    pub filename: String,
    pub data: Vec<u8>,
    pub mime: String,
}

/// Everything a send needs; threading headers make replies land in the
/// sender's mail thread instead of a new one.
pub struct OutMail {
    pub to: String,
    pub subject: String,
    /// Plain-text body (markdown flattened).
    pub text: String,
    /// HTML body (the same markdown rendered).
    pub html: String,
    pub attachments: Vec<OutAttachment>,
    /// Stored `In-Reply-To`/`References` value, with brackets.
    pub reply_to: Option<String>,
}

fn mime_for(path: &str) -> String {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "html" | "htm" => "text/html",
        "csv" => "text/csv",
        "json" => "application/json",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Read one file for attachment; errors describe the path, never contents.
pub fn read_attachment(path: &str) -> Result<OutAttachment, String> {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        crate::config::user_home()
            .map(|h| h.join(rest))
            .unwrap_or_else(|| PathBuf::from(path))
    } else {
        PathBuf::from(path)
    };
    let data = std::fs::read(&expanded)
        .map_err(|_| format!("cannot read attachment {}", expanded.display()))?;
    if data.is_empty() || data.len() > MAX_ATTACHMENT {
        return Err(format!(
            "attachment {} is empty or over {} MiB",
            expanded.display(),
            MAX_ATTACHMENT / (1024 * 1024)
        ));
    }
    let filename = expanded
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "attachment".to_string());
    Ok(OutAttachment {
        mime: mime_for(&filename),
        filename,
        data,
    })
}

fn bracketed(id: &str) -> String {
    let id = id.trim();
    if id.starts_with('<') {
        id.to_string()
    } else {
        format!("<{id}>")
    }
}

/// Submit one message over SMTP. Errors never contain config values.
pub async fn send(config: &Value, mail: &OutMail) -> Result<String, String> {
    use lettre::message::{header, Attachment, Mailbox, MultiPart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    let from_addr = cfg(config, "address");
    let from: Mailbox = from_addr
        .parse()
        .map_err(|_| "configured address is not a valid mailbox".to_string())?;
    let to: Mailbox = mail
        .to
        .trim()
        .parse()
        .map_err(|_| "recipient is not a valid mailbox".to_string())?;

    let mut builder = lettre::Message::builder()
        .from(from)
        .to(to)
        .subject(&mail.subject);
    if let Some(id) = &mail.reply_to {
        let id = bracketed(id);
        builder = builder.in_reply_to(id.clone()).references(id);
    }

    let alt = MultiPart::alternative_plain_html(mail.text.clone(), mail.html.clone());
    let part = if mail.attachments.is_empty() {
        alt
    } else {
        let mut mixed = MultiPart::mixed().multipart(alt);
        for a in &mail.attachments {
            let ct: header::ContentType = a.mime.parse().unwrap_or_else(|_| {
                header::ContentType::parse("application/octet-stream").unwrap()
            });
            mixed = mixed.singlepart(Attachment::new(a.filename.clone()).body(a.data.clone(), ct));
        }
        mixed
    };
    let message = builder
        .multipart(part)
        .map_err(|e| format!("cannot build the message: {e}"))?;

    let host = cfg(config, "smtp_host");
    if host.is_empty() {
        return Err("smtp_host is not configured".to_string());
    }
    let security = cfg(config, "smtp_security");
    let security = if security.is_empty() {
        "starttls"
    } else {
        security
    };
    let port = cfg_port(
        config,
        "smtp_port",
        if security == "tls" { 465 } else { 587 },
    );
    let creds = Credentials::new(
        cfg(config, "address").to_string(),
        cfg(config, "password").to_string(),
    );
    let transport: lettre::AsyncSmtpTransport<Tokio1Executor> = match security {
        "plain" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .credentials(creds)
            .timeout(Some(Duration::from_secs(30)))
            .build(),
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| format!("SMTP configuration failed: {}", wire(e)))?
            .port(port)
            .credentials(creds)
            .timeout(Some(Duration::from_secs(30)))
            .build(),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| format!("SMTP configuration failed: {}", wire(e)))?
            .port(port)
            .credentials(creds)
            .timeout(Some(Duration::from_secs(30)))
            .build(),
    };
    let response = tokio::time::timeout(Duration::from_secs(60), transport.send(message))
        .await
        .map_err(|_| "timed out sending via SMTP".to_string())?
        .map_err(|e| format!("SMTP send failed: {}", wire(e)))?;
    Ok(format!("sent to {} ({})", mail.to, response.code()))
}

/// `Re:` prefix, unless the subject already answers something.
pub fn reply_subject(subject: &str) -> String {
    let s = subject.trim();
    if s.is_empty() {
        "gray".to_string()
    } else if s.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("re:")) {
        s.to_string()
    } else {
        format!("Re: {s}")
    }
}

// ---------------------------------------------------------------------------
// markdown -> plain + html
// ---------------------------------------------------------------------------

fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Inline markdown for one HTML line: **bold**, *em*, `code`, [text](url).
fn inline(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 32);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &text[i..];
        if let Some(after) = rest.strip_prefix("**") {
            if let Some(end) = after.find("**") {
                out.push_str("<strong>");
                out.push_str(&inline(&after[..end]));
                out.push_str("</strong>");
                i += 4 + end;
                continue;
            }
        }
        if let Some(after) = rest.strip_prefix('`') {
            if let Some(end) = after.find('`') {
                out.push_str("<code>");
                out.push_str(&esc(&after[..end]));
                out.push_str("</code>");
                i += 2 + end;
                continue;
            }
        }
        if rest.starts_with('[') {
            if let Some(close) = rest.find("](") {
                if let Some(open) = rest[close + 2..].find(')') {
                    let label = &rest[1..close];
                    let url = &rest[close + 2..close + 2 + open];
                    if url.starts_with("http://") || url.starts_with("https://") {
                        out.push_str(&format!("<a href=\"{}\">{}</a>", esc(url), esc(label)));
                        i += close + 3 + open;
                        continue;
                    }
                }
            }
        }
        if rest.starts_with('*') && rest.len() > 2 && rest.as_bytes()[1] != b'*' {
            if let Some(end) = rest[1..].find('*') {
                if end > 0 {
                    out.push_str("<em>");
                    out.push_str(&esc(&rest[1..1 + end]));
                    out.push_str("</em>");
                    i += 2 + end;
                    continue;
                }
            }
        }
        out.push_str(&esc(&rest[..rest.chars().next().unwrap().len_utf8()]));
        i += rest.chars().next().unwrap().len_utf8();
    }
    out
}

/// Markdown -> (plain text, html). Headings, paragraphs, `code`/`pre`,
/// lists, bold/em, links — enough for an agent reply.
pub fn render(md: &str) -> (String, String) {
    let mut text = String::new();
    let mut html =
        String::from("<html><body style=\"font-family:sans-serif;font-size:14px;color:#222\">");
    let mut in_code = false;
    let mut in_list = false;
    let mut para: Vec<String> = Vec::new();
    let flush_para = |text: &mut String, html: &mut String, para: &mut Vec<String>| {
        if !para.is_empty() {
            let joined = para.join("\n");
            text.push_str(&joined);
            text.push_str("\n\n");
            html.push_str("<p>");
            html.push_str(
                &para
                    .iter()
                    .map(|l| inline(l))
                    .collect::<Vec<_>>()
                    .join("<br>\n"),
            );
            html.push_str("</p>\n");
            para.clear();
        }
    };
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            flush_para(&mut text, &mut html, &mut para);
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            if in_code {
                html.push_str("</code></pre>\n");
            } else {
                html.push_str("<pre style=\"background:#f4f4f4;padding:8px\"><code>");
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            text.push_str(line);
            text.push('\n');
            html.push_str(&esc(line));
            html.push('\n');
            continue;
        }
        let t = line.trim_end();
        if t.is_empty() {
            flush_para(&mut text, &mut html, &mut para);
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            continue;
        }
        if let Some(h) = t.strip_prefix("#### ") {
            flush_para(&mut text, &mut html, &mut para);
            text.push_str(&format!("{h}\n\n"));
            html.push_str(&format!("<h4>{}</h4>\n", inline(h)));
            continue;
        }
        if let Some(h) = t.strip_prefix("### ") {
            flush_para(&mut text, &mut html, &mut para);
            text.push_str(&format!("{h}\n\n"));
            html.push_str(&format!("<h3>{}</h3>\n", inline(h)));
            continue;
        }
        if let Some(h) = t.strip_prefix("## ") {
            flush_para(&mut text, &mut html, &mut para);
            text.push_str(&format!("{h}\n\n"));
            html.push_str(&format!("<h2>{}</h2>\n", inline(h)));
            continue;
        }
        if let Some(h) = t.strip_prefix("# ") {
            flush_para(&mut text, &mut html, &mut para);
            text.push_str(&format!("{h}\n\n"));
            html.push_str(&format!("<h1>{}</h1>\n", inline(h)));
            continue;
        }
        let bullet = t.strip_prefix("- ").or_else(|| t.strip_prefix("* "));
        if let Some(item) = bullet {
            flush_para(&mut text, &mut html, &mut para);
            if !in_list {
                html.push_str("<ul>\n");
                in_list = true;
            }
            text.push_str(&format!("- {item}\n"));
            html.push_str(&format!("<li>{}</li>\n", inline(item)));
            continue;
        }
        para.push(t.to_string());
    }
    flush_para(&mut text, &mut html, &mut para);
    if in_list {
        html.push_str("</ul>\n");
    }
    if in_code {
        html.push_str("</code></pre>\n");
    }
    html.push_str("</body></html>");
    (text.trim_end().to_string(), html)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_parses_sender_and_automated() {
        let raw = b"From: Bot <noreply@example.com>\r\nSubject: hi\r\nAuto-Submitted: auto-generated\r\n\r\n";
        let h = parse_head(raw).unwrap();
        assert_eq!(h.from, "noreply@example.com");
        assert_eq!(h.subject, "hi");
        assert!(h.automated);
        let raw = b"From: A Person <a@example.com>\r\nSubject: yo\r\n\r\n";
        let h = parse_head(raw).unwrap();
        assert_eq!(h.from, "a@example.com");
        assert!(!h.automated);
    }

    #[test]
    fn render_simple_markdown() {
        let (text, html) = render("# Title\n\nsome **bold** text\n\n- one\n- two\n");
        assert!(text.contains("Title"));
        assert!(text.contains("- one"));
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<li>one</li>"));
    }

    #[test]
    fn strip_html_basic() {
        assert_eq!(
            strip_html("<p>Hello <b>world</b></p><p>next</p>").trim(),
            "Hello world\n\nnext"
        );
    }

    #[test]
    fn reply_subject_prefixes_once() {
        assert_eq!(reply_subject("hello"), "Re: hello");
        assert_eq!(reply_subject("Re: hello"), "Re: hello");
        assert_eq!(reply_subject(""), "gray");
    }
}
