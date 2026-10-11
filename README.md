# gray-email

A standalone email channel adapter for [gray](https://github.com/vstaln/gray)
— IMAP in, SMTP out, with its own setup wizard, pairing allowlist, durable
SQLite queue, and a background service. Same shape as
`gray-discord-plugin`/`gray-irc`, mail transport underneath (ported from
hermes `plugins/platforms/email` — `async-imap` + `lettre` + `mail-parser`).

**Status: v1.** Inbound mail from allowlisted senders runs one isolated
`gray` turn per sender; outbound is SMTP submit with the agent's markdown
reply rendered to text+html. See [runtime policy and limits](docs/RUNTIME.md).

## Requirements

- `gray` on PATH, provider/model configured in `~/.gray/config.json`
- An email mailbox the bot can poll (IMAP) and send from (SMTP)
- An **app password** where the provider requires one — Gmail:
  `myaccount.google.com/apppasswords` (needs 2-Step Verification);
  Fastmail/Outlook/iCloud have equivalent app-password pages. Your normal
  account password only works on providers that still allow it.

## Install

```sh
cargo install --path .          # puts gray-email on PATH
gray plugin install email       # or let gray find the binary
```

## Setup

```sh
gray email setup                # or: gray gateway setup email
```

The wizard asks for:

- the bot's email address and password (entered hidden — use an app
  password)
- IMAP host, security (tls → 993, starttls/plain → 143), port
- SMTP host, security (starttls → 587, tls → 465, plain → 25), port
- poll interval (default 60 s)
- addresses allowed to trigger the bot (comma-separated)
- home address for cron/notices (default: first allowed address)

It saves the config privately (`~/.config/gray-email/config.json`, mode
0600), registers the `email_send` tool with gray, probes live IMAP and SMTP
logins (doctor), and offers to install the background service.

## Running

```sh
gray email status      # service health
gray email stop        # graceful stop (mails shutdown notices)
gray email restart
gray email uninstall   # service only; config and sessions stay
gray email run         # foreground daemon (what the service execs)
gray email doctor      # verify IMAP+SMTP logins and local gray config
gray email queue list / cancel <id>
gray email allowlist add|remove|list
gray email pairing approve email <CODE>
gray email limits --timeout-seconds 600 --concurrency 2 --max-requests 200
```

The service probes what this box actually supervises with (runit,
`systemd --user`, or a detached gray-managed process) and installs
accordingly — never a root unit, never a secret in a unit file.

A mail whose body starts with `/steer <text>` adds guidance to the turn
already running for that sender; with nothing running it is sent as a new
message. Mail arriving while a turn runs queues as its own next turn
("Queued — N ahead.", at most once per 30s); set `busy_input_mode: "steer"`
to steer the running turn instead.

A mail whose body starts with `/stop` cancels the turn running for that
sender ("Stopped."); queued mail still runs next. With nothing running the
reply is "Nothing running."

## Tools

`email_send(to?, subject?, body, attachments?)` — the model's outbound
channel. `to` defaults to the configured home address; `body` is markdown
rendered to a text+html alternative; `attachments` is a list of local file
paths (≤ 20 MiB each, up to 10 files). Registered on setup; also invocable
via the sidecar protocol.

## Limits

- Inbound is allowlist-only and headers are checked before bodies are
  fetched (preflight), so strangers and bulk mail never cost a download.
- Automated senders (noreply/mailer-daemon addresses, `Auto-Submitted`,
  `Precedence: bulk|list|junk`, `List-Unsubscribe`) are silently skipped.
- Polling, not IMAP IDLE — one `UID SEARCH UNSEEN` per `poll_seconds`
  (60 default, floor 5). First connect skips the existing backlog.
- Replies carry `In-Reply-To`/`References` so they thread in the sender's
  mail client; subjects are `Re:`-prefixed once.
- Attachments inbound are spooled to `~/.config/gray-email/attachments/`
  and the paths are handed to the agent; outbound attachments are read
  from local paths.
- No Authentication-Results/SPF/DKIM enforcement: `From:` is trusted for
  the allowlist decision (the hermes adapter's stricter auth check is
  documented in docs/RUNTIME.md as a follow-up).
