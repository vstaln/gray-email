# Runtime notes

Requires a gray core implementing `gray -p --json` protocol 1 (the same
`{"protocol":1,"turn_id",...}` NDJSON the discord/slack/irc adapters
consume).

## Transport

Inbound: `async-imap` (tokio) over implicit TLS (993, default), STARTTLS
(143, manual greeting + tagged `STARTTLS` + upgrade), or plain (local/dev
only). rustls + webpki roots, no openssl. RFC 2971 `ID` is sent after
LOGIN when the server advertises it (163/NetEase require it). The daemon
polls `UID SEARCH UNSEEN` every `poll_seconds` (default 60); reconnects
with bounded backoff (1s → 300s).

Outbound: `lettre` `AsyncSmtpTransport` — `relay` for implicit TLS (465),
`starttls_relay` (587, default), `builder_dangerous` for plain (25).
Credentials are LOGIN user/pass from the config; `test_connection` is what
doctor uses to prove them.

## Inbound policy

- `UNSEEN` uids above the durable `uid_floor` (SQLite `meta`) are
  candidates; each processed uid raises the floor and gets `\Seen`, so a
  restart never re-delivers. First-ever connect sets the floor to
  `UIDNEXT-1` — the existing backlog is skipped, not replayed.
- Preflight fetches only the headers needed to decide (`From`, `Subject`,
  `Message-ID`, `Auto-Submitted`, `Precedence`, `List-Unsubscribe`,
  `X-Auto-Response-Suppress`, ≤ 64 KiB) before any body is downloaded
  (≤ 8 MiB cap).
- Automated mail is dropped silently: noreply-ish sender substrings
  (hermes' pattern list) or the bulk headers above.
- The `From:` address must be on `allowed_senders` (case-insensitive); an
  un-admitted sender gets one pairing reply (code minted in SQLite) —
  `gray email pairing approve email <code>` adds the address. **Caveat:**
  `From:` is trivially forgeable; the pairing code only proves control of
  the reply path, not sender identity. The hermes adapter's
  Authentication-Results pinning (`authserv_id` + SPF/DKIM/DMARC clause
  parsing) is not ported — it is the follow-up for hostile environments.
- Conversation key: `mail:<sender>` — one session per correspondent, so a
  thread keeps context. Session reset policy `session_reset` (`both`:
  1,440 idle minutes or the next 04:00 local boundary) mirrors the other
  adapters.

## Queue

Accepted mail commits to `email.sqlite` next to the config before any
agent work: `queued` → `running` → `done`/`failed`/`cancelled`. Boot
re-queues interrupted `running` rows and reports the count in the startup
notice. `concurrency` workers (default 2, max 16) claim items; a
per-conversation flock serializes turns with one sender. `queue list`
shows pending work; `queue cancel <id>` cancels what is still queued.

## Turn

The prompt handed to gray is `Subject: …` + the decoded text body
(text/plain preferred; text/html tag-stripped as a fallback), capped at
50,000 chars, plus a list of spooled attachment paths. Attachments land in
`<config dir>/attachments/<uid>-<name>` with the filename sanitized; empty
or >20 MiB parts are skipped and noted.

## Delivery

Replies are SMTP submits, not connection-bound writes: a generated answer
retries delivery (3 attempts, 5 s apart) rather than regenerating —
at-least-once, never exactly-once. Markdown renders to
`multipart/alternative` (text + html); `In-Reply-To`/`References` carry the
original `Message-ID` and the subject is `Re:`-prefixed once, so replies
thread in the sender's client.

`email_send` is a standalone submit, not an outbox transaction — its
errors must not be blindly retried.

## Limits

`gray email limits --timeout-seconds 600 --concurrency 2 --max-requests 200`
sets turn wall time, worker count, and per-turn provider requests; restart
to apply. `queue_capacity` (default 1,000) bounds the inbox; a full queue
mails the sender instead of dropping silently.

## Lifecycle notices

`lifecycle.json` + `restart_pending` next to the config, worded by
`gray gateway lifecycle boot|stop` when the installed gray has it (local
fallback otherwise). Senders with a running turn get the shutdown/restart
mail; the home address gets the boot notice ("restarted", "online", or
"back after an unexpected stop" with the interrupted count).
`restart_notification: false` in the config silences all of it.

## Secrets

`config.json` (address, app password, hosts) is written 0600 into a 0700
directory by the wizard; passwords are entered hidden, never echoed into
logs, unit files, or tool results. `gray_bin`/`gray_home`/`workdir` are
absolute paths validated on load.
