# E2NB - Email to Notification Blaster

A professional Python application that monitors multiple sources (Email via IMAP/POP3, local SMTP receiver, RSS/Atom feeds, web page changes, HTTP endpoint availability) and forwards notifications through 8 channels: SMS, Voice calls, WhatsApp, Slack, Telegram, Discord, SMTP email forwarding, and custom webhooks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
  - [Email Settings](#email-settings)
  - [Advanced Email Settings](#advanced-email-settings)
  - [General Settings](#general-settings)
  - [SMTP Receiver](#smtp-receiver)
  - [RSS Feed Monitoring](#rss-feed-monitoring)
  - [Web Page Monitoring](#web-page-monitoring)
  - [HTTP Endpoint Monitoring](#http-endpoint-monitoring)
- [Notification Channels](#notification-channels)
  - [Twilio SMS](#twilio-sms)
  - [Twilio Voice](#twilio-voice)
  - [Twilio WhatsApp](#twilio-whatsapp)
  - [Slack](#slack)
  - [Telegram](#telegram)
  - [Discord](#discord)
  - [SMTP Email Forwarding](#smtp-email-forwarding)
  - [Custom Webhook](#custom-webhook)
- [GUI Version](#gui-version)
- [Headless Daemon](#headless-daemon)
  - [Command-Line Arguments](#command-line-arguments)
  - [Signal Handling](#signal-handling)
  - [Systemd Service](#systemd-service)
  - [Docker Deployment](#docker-deployment)
- [Monitoring Sources In-Depth](#monitoring-sources-in-depth)
  - [Email Monitoring (IMAP)](#email-monitoring-imap)
  - [Email Monitoring (POP3)](#email-monitoring-pop3)
  - [SMTP Receiver In-Depth](#smtp-receiver-in-depth)
  - [RSS Feed Monitoring In-Depth](#rss-feed-monitoring-in-depth)
  - [Web Page Monitoring In-Depth](#web-page-monitoring-in-depth)
  - [HTTP Endpoint Monitoring In-Depth](#http-endpoint-monitoring-in-depth)
- [State Management](#state-management)
- [Security](#security)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

E2NB is designed for scenarios where you need real-time alerts from multiple sources delivered to multiple destinations. Common use cases include:

- **Server monitoring**: Watch HTTP endpoints and get SMS/Slack alerts when services go down
- **Email forwarding**: Forward important emails to Telegram, Discord, or Slack channels
- **Price tracking**: Monitor product pages for changes and get notified instantly
- **News monitoring**: Track RSS feeds and get alerts for specific keywords
- **Security alerting**: Forward security notification emails to multiple team channels simultaneously
- **Uptime monitoring**: Track API health endpoints and get voice calls when critical services fail

E2NB runs in two modes:
- **GUI mode** (`e2nb.py`): Desktop application with a modern Tkinter interface for interactive configuration and monitoring
- **Headless mode** (`e2nb-headless.py`): Daemon suitable for servers, supporting systemd, signal-based config reloading, and unattended operation

## Architecture

```
e2nb/
├── e2nb_core.py          # Shared core module - all business logic
├── e2nb.py               # GUI version (Tkinter desktop app)
├── e2nb-headless.py      # Headless daemon for server deployment
├── config.ini            # Configuration file (auto-created on first run)
├── requirements.txt      # Python dependencies
├── e2nb_state.json    # Persistent state file (auto-created at runtime)
└── monitor/              # Screenshot assets for documentation
    ├── emailsettings.png
    ├── integrations.png
    ├── logs.png
    └── twilio.png
```

### Module Responsibilities

| Module | Lines | Purpose |
|--------|-------|---------|
| `e2nb_core.py` | ~3250 | Configuration management, email operations (IMAP/POP3), SMTP receiver, RSS/Web/HTTP monitoring, all 8 notification channel implementations, input validation, state management, HTTP retry logic |
| `e2nb.py` | ~3065 | Tkinter GUI with modern dark sidebar, scrollable form pages, real-time log viewer, toggle switches, toast notifications, connection testing |
| `e2nb-headless.py` | ~825 | CLI daemon with argparse, signal handling (SIGHUP reload), thread-safe config swapping, systemd integration |

### Data Flow

```
Sources                      Core                        Channels
┌──────────┐              ┌──────────────┐           ┌──────────┐
│ IMAP     │──┐           │              │──────────>│ SMS      │
│ POP3     │──┤           │ Notification │──────────>│ Voice    │
│ SMTP Recv│──┼──────────>│ Dispatcher   │──────────>│ WhatsApp │
│ RSS Feeds│──┤           │              │──────────>│ Slack    │
│ Web Pages│──┤           │ (routes to   │──────────>│ Telegram │
│ HTTP Endp│──┘           │  all enabled │──────────>│ Discord  │
└──────────┘              │  channels)   │──────────>│ SMTP     │
                          │              │──────────>│ Webhook  │
                          └──────────────┘           └──────────┘
```

## Requirements

- **Python 3.8** or higher
- An email account with IMAP or POP3 access (optional if using other sources)
- API credentials for your desired notification services

### Dependencies

| Package | Min Version | Purpose | Required? |
|---------|-------------|---------|-----------|
| `twilio` | 8.0.0 | SMS, Voice calls, WhatsApp | Only if using Twilio services |
| `slack_sdk` | 3.20.0 | Slack channel notifications | Only if using Slack |
| `requests` | 2.28.0 | HTTP requests for webhooks, web/HTTP monitoring | Yes |
| `urllib3` | 2.0.0 | Retry logic and connection pooling | Yes |
| `feedparser` | 6.0.0 | RSS/Atom feed parsing | Only if using RSS monitoring |
| `beautifulsoup4` | 4.12.0 | HTML parsing for web monitoring & RSS content extraction | Only if using web monitoring or RSS |
| `aiosmtpd` | 1.4.0 | Local SMTP server for receiving emails | Only if using SMTP receiver |

The GUI version additionally requires `tkinter`, which is included with most Python installations. On some Linux distributions you may need to install it separately (e.g., `sudo apt install python3-tk`).

**Graceful degradation**: If an optional library is not installed, the corresponding feature is disabled automatically. The application will not crash; it will log a warning and skip that feature.

## Installation

```bash
# Clone repository
git clone https://github.com/morroware/e2nb.git
cd e2nb

# Install all dependencies
pip install -r requirements.txt

# Or install only what you need:
pip install requests urllib3                    # Core (required)
pip install twilio                             # For SMS/Voice/WhatsApp
pip install slack_sdk                          # For Slack
pip install feedparser                         # For RSS feeds
pip install beautifulsoup4                     # For web page monitoring
pip install aiosmtpd                           # For SMTP receiver
```

## Quick Start

### 1. Run the GUI to configure

```bash
python e2nb.py
```

A config.ini file is created automatically on first run with default values.

### 2. Configure a source

In the sidebar under **Sources**, click **Email** and enter your IMAP/POP3 server details and credentials. Or enable one of the other sources (RSS, Web, HTTP).

### 3. Configure a notification channel

In the sidebar under **Notifications**, enable at least one channel (e.g., Telegram, Discord, or Slack) and enter the required credentials.

### 4. Start monitoring

Click **Start Monitoring** in the header. Activity appears in the **Logs** page.

### 5. Deploy headless (optional)

Once your config.ini is working, deploy to a server:

```bash
python e2nb-headless.py -c /path/to/config.ini -l /var/log/e2nb.log --no-console
```

---

## Configuration Reference

All configuration is stored in `config.ini`. The file is auto-created on first run. You can edit it manually or use the GUI.

### Email Settings

```ini
[Email]
protocol = imap
imap_server = imap.gmail.com
imap_port = 993
pop3_server = pop.gmail.com
pop3_port = 995
username = your.email@gmail.com
password = your-app-specific-password
filter_emails = alerts@example.com, @trusted-domain.com
```

| Setting | Description | Default |
|---------|-------------|---------|
| `protocol` | Email protocol: `imap` or `pop3` | `imap` |
| `imap_server` | IMAP server hostname | `imap.gmail.com` |
| `imap_port` | IMAP port (993 for SSL, 143 for STARTTLS) | `993` |
| `pop3_server` | POP3 server hostname | `pop.gmail.com` |
| `pop3_port` | POP3 port (995 for SSL, 110 for STARTTLS) | `995` |
| `username` | Full email address for login | *(empty)* |
| `password` | Password or app-specific password | *(empty)* |
| `filter_emails` | Comma-separated sender whitelist. Use `@domain.com` to allow all senders from a domain. Leave empty to accept all. | *(empty)* |

### Advanced Email Settings

```ini
[Email]
tls_mode = implicit
verify_ssl = True
max_emails_per_check = 5
connection_timeout = 30
```

| Setting | Description | Default |
|---------|-------------|---------|
| `tls_mode` | `implicit` (SSL on connect, ports 993/995), `explicit` (STARTTLS, ports 143/110), or `none` (no encryption) | `implicit` |
| `verify_ssl` | Verify SSL/TLS certificates. Set to `False` for self-signed certs. | `True` |
| `max_emails_per_check` | Maximum number of emails to process per monitoring cycle (1-100) | `5` |
| `connection_timeout` | Connection timeout in seconds (5-300) | `30` |

### General Settings

```ini
[Settings]
check_interval = 60
max_sms_length = 1600
```

| Setting | Description | Default |
|---------|-------------|---------|
| `check_interval` | Seconds between monitoring cycles (10-86400) | `60` |
| `max_sms_length` | Maximum characters for SMS messages before truncation | `1600` |

### SMTP Receiver

Run a local SMTP server to receive emails pushed from other systems, instead of polling a remote mailbox.

```ini
[SmtpReceiver]
enabled = False
host = 0.0.0.0
port = 2525
use_auth = False
username =
password =
filter_emails =
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable the local SMTP receiver | `False` |
| `host` | Network interface to bind to. `0.0.0.0` = all interfaces, `127.0.0.1` = localhost only | `0.0.0.0` |
| `port` | TCP port to listen on. Use 2525+ to avoid needing root privileges. Ports below 1024 require root. | `2525` |
| `use_auth` | Require SMTP LOGIN/PLAIN authentication from sending clients | `False` |
| `username` | Username clients must authenticate with (only when `use_auth = True`) | *(empty)* |
| `password` | Password clients must authenticate with (only when `use_auth = True`) | *(empty)* |
| `filter_emails` | Comma-separated sender whitelist, same format as email filters | *(empty)* |

**Requires**: `aiosmtpd` package (`pip install aiosmtpd`).

### RSS Feed Monitoring

Monitor RSS and Atom feeds for new items.

```ini
[RSS]
enabled = False
feeds = [{"name": "Tech News", "url": "https://example.com/feed.xml", "keywords": ["python", "ai"]}]
check_interval = 300
max_age_hours = 24
max_items_per_check = 10
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable RSS feed monitoring | `False` |
| `feeds` | JSON array of feed objects (see below) | `[]` |
| `check_interval` | Seconds between feed checks (minimum 60) | `300` |
| `max_age_hours` | Ignore items published more than this many hours ago | `24` |
| `max_items_per_check` | Maximum new items to process per feed per check | `10` |

**Feed object format**:

```json
[
  {
    "name": "Feed Display Name",
    "url": "https://example.com/feed.xml",
    "keywords": ["optional", "keyword", "filters"]
  }
]
```

- `name` (required): Display name for notifications
- `url` (required): Feed URL (RSS or Atom)
- `keywords` (optional): Array of keywords. If provided, only items containing at least one keyword in the title or summary will trigger notifications.

**Requires**: `feedparser` package (`pip install feedparser`).

### Web Page Monitoring

Detect changes on web pages by periodically fetching them and comparing content hashes.

```ini
[WebMonitor]
enabled = False
pages = [{"name": "Product Page", "url": "https://example.com/product", "selector": ".price"}]
check_interval = 300
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable web page monitoring | `False` |
| `pages` | JSON array of page objects (see below) | `[]` |
| `check_interval` | Seconds between page checks | `300` |

**Page object format**:

```json
[
  {
    "name": "Product Page",
    "url": "https://example.com/product",
    "selector": ".price"
  }
]
```

- `name` (required): Display name for notifications
- `url` (required): Page URL to monitor
- `selector` (optional): CSS selector to monitor only a specific part of the page (e.g., `.price`, `#stock-status`, `div.content`). If omitted, the entire page body is monitored.

When a change is detected, E2NB sends a notification with the page name and the new content (or a change summary).

**Requires**: `beautifulsoup4` package for CSS selector support (`pip install beautifulsoup4`). Without it, full-page monitoring still works but CSS selectors are ignored.

### HTTP Endpoint Monitoring

Monitor HTTP/HTTPS endpoints for availability and correct status codes.

```ini
[HttpMonitor]
enabled = False
endpoints = [{"name": "API Health", "url": "https://api.example.com/health", "method": "GET", "expected_status": 200}]
check_interval = 60
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable HTTP endpoint monitoring | `False` |
| `endpoints` | JSON array of endpoint objects (see below) | `[]` |
| `check_interval` | Seconds between endpoint checks | `60` |

**Endpoint object format**:

```json
[
  {
    "name": "API Health",
    "url": "https://api.example.com/health",
    "method": "GET",
    "expected_status": 200
  }
]
```

- `name` (required): Display name for notifications
- `url` (required): Endpoint URL
- `method` (optional): HTTP method (`GET`, `POST`, `HEAD`, etc.). Default: `GET`
- `expected_status` (optional): Expected HTTP status code. Default: `200`

**Notification triggers**:
- **Endpoint DOWN**: Sent when an endpoint returns an unexpected status code or fails to respond
- **Endpoint RECOVERED**: Sent when a previously-down endpoint starts responding correctly again
- Response time is measured and included in notifications

---

## Notification Channels

Each channel has an `enabled` toggle. You can enable any combination of channels simultaneously. All enabled channels receive every notification.

### Twilio SMS

Send SMS text messages via the Twilio API. Supports multiple recipients.

```ini
[Twilio]
enabled = True
account_sid = ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
auth_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
from_number = +15551234567
destination_number = +15559876543, +15551111111
```

| Setting | Description |
|---------|-------------|
| `account_sid` | Your Twilio Account SID (starts with `AC`) |
| `auth_token` | Your Twilio Auth Token |
| `from_number` | Your Twilio phone number (E.164 format: `+1XXXXXXXXXX`) |
| `destination_number` | Comma-separated recipient phone numbers in E.164 format |

**Setup steps**:
1. Create a Twilio account at https://www.twilio.com
2. Get your Account SID and Auth Token from the Twilio Console dashboard
3. Purchase a phone number or use the trial number
4. If on a trial account, verify recipient numbers in the Twilio Console

Messages longer than `max_sms_length` (default 1600) are automatically truncated.

### Twilio Voice

Make automated voice calls that read notification content via text-to-speech.

```ini
[Voice]
enabled = True
account_sid = ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
auth_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
from_number = +15551234567
destination_number = +15559876543
```

| Setting | Description |
|---------|-------------|
| `account_sid` | Your Twilio Account SID |
| `auth_token` | Your Twilio Auth Token |
| `from_number` | Your Twilio phone number |
| `destination_number` | Comma-separated recipient phone numbers |

The notification content is converted to speech using Twilio's TwiML `<Say>` verb. Content is sanitized to prevent TwiML injection.

### Twilio WhatsApp

Send WhatsApp messages via Twilio's WhatsApp API.

```ini
[WhatsApp]
enabled = True
account_sid = ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
auth_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
from_number = whatsapp:+14155238886
to_number = whatsapp:+15559876543
```

| Setting | Description |
|---------|-------------|
| `account_sid` | Your Twilio Account SID |
| `auth_token` | Your Twilio Auth Token |
| `from_number` | Twilio WhatsApp sender (must include `whatsapp:` prefix) |
| `to_number` | Recipient WhatsApp number (must include `whatsapp:` prefix) |

**Setup steps**:
1. Enable WhatsApp in your Twilio Console
2. For testing, use the Twilio WhatsApp Sandbox: send "join <sandbox-keyword>" to the sandbox number
3. For production, apply for a WhatsApp Business Profile through Twilio

### Slack

Post notifications to a Slack channel via Bot Token.

```ini
[Slack]
enabled = True
token = xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx
channel = #notifications
```

| Setting | Description |
|---------|-------------|
| `token` | Slack Bot Token (starts with `xoxb-`) |
| `channel` | Channel name (e.g., `#notifications`) or channel ID (e.g., `C01XXXXXXXX`) |

**Setup steps**:
1. Go to https://api.slack.com/apps and create a new app
2. Under **OAuth & Permissions**, add the `chat:write` bot scope
3. Install the app to your workspace
4. Copy the **Bot User OAuth Token** (starts with `xoxb-`)
5. Invite the bot to your target channel: `/invite @YourBotName`

### Telegram

Send messages via a Telegram bot.

```ini
[Telegram]
enabled = True
bot_token = 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
chat_id = -1001234567890
```

| Setting | Description |
|---------|-------------|
| `bot_token` | Bot token from @BotFather |
| `chat_id` | Chat/group/channel ID |

**Setup steps**:
1. Message [@BotFather](https://t.me/botfather) on Telegram and send `/newbot`
2. Follow the prompts to name your bot and get the token
3. To get your chat ID: message [@userinfobot](https://t.me/userinfobot) or for groups, add [@RawDataBot](https://t.me/rawdatabot) to the group
4. For channels: add the bot as an admin and use the channel's numeric ID (starts with `-100`)

Messages are sent with MarkdownV2 formatting. If MarkdownV2 fails (e.g., due to special characters), E2NB automatically falls back to plain text. Messages are truncated to 4096 characters (Telegram API limit).

### Discord

Post notifications via Discord webhook.

```ini
[Discord]
enabled = True
webhook_url = https://discord.com/api/webhooks/xxxxxxxxxxxx/xxxxxxxxxxxx
```

| Setting | Description |
|---------|-------------|
| `webhook_url` | Discord webhook URL |

**Setup steps**:
1. In your Discord server, go to the target channel's settings
2. Navigate to **Integrations > Webhooks**
3. Click **New Webhook**, configure it, and copy the webhook URL

Messages are truncated to 2000 characters (Discord API limit).

### SMTP Email Forwarding

Forward notifications as emails through an outbound SMTP server.

```ini
[SMTP]
enabled = False
smtp_server = smtp.gmail.com
smtp_port = 587
use_tls = True
username = your.email@gmail.com
password = your-app-specific-password
from_address = notifications@example.com
to_addresses = admin@example.com, team@example.com
subject_prefix = [E2NB]
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable SMTP email notifications | `False` |
| `smtp_server` | Outbound SMTP server hostname | `smtp.gmail.com` |
| `smtp_port` | SMTP port. Use 587 for STARTTLS, 465 for implicit SSL | `587` |
| `use_tls` | Use STARTTLS encryption | `True` |
| `username` | SMTP authentication username (usually your email) | *(empty)* |
| `password` | SMTP authentication password | *(empty)* |
| `from_address` | Sender address for notification emails | *(empty)* |
| `to_addresses` | Comma-separated list of recipient addresses | *(empty)* |
| `subject_prefix` | Prefix prepended to notification email subjects | `[E2NB]` |

### Custom Webhook

Send notifications as HTTP POST requests with a JSON payload to any URL.

```ini
[CustomWebhook]
enabled = True
webhook_url = https://api.example.com/webhook
```

| Setting | Description |
|---------|-------------|
| `webhook_url` | HTTP(S) endpoint that accepts POST requests |

**JSON payload format** sent to your endpoint:

```json
{
  "subject": "Email Subject or Event Title",
  "body": "Full notification body content",
  "sender": "source@example.com or source name",
  "timestamp": "2024-12-05T10:15:30.000000"
}
```

The webhook includes automatic retry with exponential backoff for transient failures (HTTP 429, 500, 502, 503, 504).

---

## GUI Version

```bash
python e2nb.py
```

### Interface Layout

The GUI uses a modern dark-sidebar design with four sections:

**Sidebar Sections**:
- **Sources** (with active count badge): Email, RSS Feeds, Web Pages, HTTP Endpoints - each with a green/gray status dot
- **Notifications** (with active count badge): SMS, Voice, WhatsApp, Slack, Telegram, Discord, Webhook, Email (SMTP) - each with a status dot
- **Configuration**: General settings (check interval, SMS length)
- **Monitor**: Activity Logs with real-time color-coded output

**Header Controls**:
- **Save** button (also Ctrl+S): Saves all settings to config.ini
- **Start Monitoring** button: Begins monitoring all enabled sources
- **Stop** button: Gracefully stops monitoring
- Status badge showing monitoring state

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+S | Save settings to config.ini |
| Ctrl+L | Switch to Logs page |

### Testing Features

Each source/notification page includes test buttons:

- **Email page**: "Test Connection" - verifies IMAP or POP3 connectivity
- **SMTP Receiver page**: "Test Port" - checks if the receiver port is available
- **RSS page**: "Validate Feeds" - parses the JSON and tests the first feed URL
- **HTTP Endpoints page**: "Validate & Test" - parses JSON and tests the first endpoint
- **Web Pages page**: "Validate Pages" - validates the JSON configuration
- **SMTP Notifications page**: "Test Connection" - verifies SMTP server connectivity

### Log Viewer

The Logs page shows real-time monitoring activity with:
- Color-coded severity levels (blue=INFO, yellow=WARNING, red=ERROR, green=SUCCESS)
- Timestamps for each entry
- Auto-scroll toggle
- Clear Logs button

---

## Headless Daemon

The headless version is designed for unattended server deployment.

```bash
python e2nb-headless.py [options]
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-c, --config FILE` | Path to configuration file | `config.ini` |
| `-l, --log-file FILE` | Path to log file | `email_monitor.log` |
| `-v, --verbose` | Enable debug-level logging | Off |
| `--no-console` | Suppress console output (log to file only) | Off |
| `--test` | Validate configuration, test connections, and exit | Off |
| `--version` | Display version and exit | - |

### Examples

```bash
# Basic usage with defaults
python e2nb-headless.py

# Production deployment
python e2nb-headless.py -c /etc/e2nb/config.ini -l /var/log/e2nb.log --no-console

# Test configuration before deploying
python e2nb-headless.py -c /etc/e2nb/config.ini --test

# Debug mode
python e2nb-headless.py -v
```

### Signal Handling

| Signal | Action |
|--------|--------|
| `SIGINT` (Ctrl+C) | Graceful shutdown - stops monitoring loop, closes connections |
| `SIGTERM` | Graceful shutdown (same as SIGINT) |
| `SIGHUP` | Hot-reload configuration from config.ini without restarting |

**Hot reload** (SIGHUP): The daemon re-reads config.ini, validates the new configuration, and atomically swaps it in. The old HTTP session is closed and a new NotificationDispatcher is created. This allows you to change settings without any downtime.

```bash
# Reload config on a running daemon
kill -HUP $(pgrep -f e2nb-headless)
```

### Systemd Service

Create `/etc/systemd/system/e2nb.service`:

```ini
[Unit]
Description=E2NB Email to Notification Blaster
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=e2nb
Group=e2nb
WorkingDirectory=/opt/e2nb
ExecStart=/usr/bin/python3 /opt/e2nb/e2nb-headless.py -c /etc/e2nb/config.ini -l /var/log/e2nb.log --no-console
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/e2nb.log /opt/e2nb/e2nb_state.json
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
# Setup
sudo useradd -r -s /bin/false e2nb
sudo mkdir -p /opt/e2nb /etc/e2nb
sudo cp e2nb_core.py e2nb-headless.py /opt/e2nb/
sudo cp config.ini /etc/e2nb/config.ini
sudo chown -R e2nb:e2nb /opt/e2nb

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable e2nb
sudo systemctl start e2nb

# Check status
sudo systemctl status e2nb

# View logs
sudo journalctl -u e2nb -f

# Reload configuration (no restart needed)
sudo systemctl reload e2nb
```

### Docker Deployment

Example `Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY e2nb_core.py e2nb-headless.py ./
COPY config.ini /etc/e2nb/config.ini
CMD ["python", "e2nb-headless.py", "-c", "/etc/e2nb/config.ini", "-l", "/var/log/e2nb.log"]
```

```bash
docker build -t e2nb .
docker run -d --name e2nb \
  -v /path/to/config.ini:/etc/e2nb/config.ini:ro \
  -v /path/to/state:/app/e2nb_state.json \
  e2nb
```

---

## Monitoring Sources In-Depth

### Email Monitoring (IMAP)

IMAP is the recommended email protocol. E2NB connects via SSL/TLS, searches for unread emails, processes them, and marks them as read only after at least one notification is successfully delivered.

**How it works**:
1. Connects to the IMAP server with SSL (port 993) or STARTTLS (port 143)
2. Selects the INBOX folder
3. Searches for UNSEEN (unread) messages
4. Fetches message content using `BODY.PEEK[]` (does not mark as read during fetch)
5. Applies sender filters if configured
6. Dispatches notifications to all enabled channels
7. Only marks the email as `\Seen` (read) if at least one notification succeeds
8. Disconnects after each cycle

**Email filters**: When `filter_emails` is configured, only emails from matching senders are processed:
- Exact email match: `alerts@example.com` matches only that address
- Domain match: `@example.com` matches any sender from that domain (e.g., `alice@example.com`, `bob@example.com`)
- Multiple filters: comma-separated, any match allows the email through

### Email Monitoring (POP3)

POP3 is an alternative for servers that don't support IMAP. E2NB tracks processed messages via content hashing to avoid duplicates.

**How it works**:
1. Connects via SSL (port 995) or STARTTLS (port 110)
2. Lists available messages
3. Downloads each message and computes an MD5 hash of `sender + subject + body`
4. Skips messages whose hash has already been seen (persisted in `e2nb_state.json`)
5. Dispatches notifications for new messages
6. Deletes the message from the server if notification succeeds
7. Periodically cleans up old hash records

### SMTP Receiver In-Depth

The SMTP receiver runs a local SMTP server using `aiosmtpd`. External systems can forward emails directly to E2NB.

**Use cases**:
- Receive forwarded emails from another mail server
- Accept emails from applications or scripts via `sendmail` or SMTP
- Act as a lightweight mail-to-notification bridge

**Authentication**: When `use_auth = True`, the receiver requires LOGIN or PLAIN SMTP authentication. Clients must authenticate with the configured username/password before the server will accept their email.

**Sending a test email to the SMTP receiver**:

```bash
# Using Python
python -c "
import smtplib
from email.mime.text import MIMEText
msg = MIMEText('Test body')
msg['Subject'] = 'Test Subject'
msg['From'] = 'test@example.com'
msg['To'] = 'receiver@localhost'
with smtplib.SMTP('localhost', 2525) as s:
    s.send_message(msg)
"

# Using curl
curl smtp://localhost:2525 \
  --mail-from "test@example.com" \
  --mail-rcpt "receiver@localhost" \
  -T - <<EOF
From: test@example.com
Subject: Test Alert
Content-Type: text/plain

This is a test notification.
EOF
```

### RSS Feed Monitoring In-Depth

E2NB uses `feedparser` to poll RSS and Atom feeds at the configured interval.

**How it works**:
1. Parses each feed URL
2. For each entry, generates a unique ID from the entry's `guid` or `link`
3. Compares against seen items persisted in `e2nb_state.json`
4. Filters by age (skips items older than `max_age_hours`)
5. Filters by keywords if configured (checks title and summary)
6. Creates a notification with the item's title and content
7. Marks the item as seen

**Feed JSON examples**:

```json
[
  {"name": "Hacker News", "url": "https://hnrss.org/newest"},
  {"name": "Python Blog", "url": "https://blog.python.org/feeds/posts/default", "keywords": ["release", "security"]},
  {"name": "AWS Status", "url": "https://status.aws.amazon.com/rss/all.rss"}
]
```

### Web Page Monitoring In-Depth

E2NB detects changes by computing SHA-256 hashes of page content and comparing against stored hashes.

**How it works**:
1. Fetches the page via HTTP GET
2. If a CSS `selector` is specified and BeautifulSoup is available, extracts only the matching element's text
3. If no selector, uses the full page body text
4. Computes SHA-256 hash of the normalized content
5. Compares against the stored hash in `e2nb_state.json`
6. If different (and not the first check), sends a change notification
7. Updates the stored hash

**Page JSON examples**:

```json
[
  {"name": "Product Price", "url": "https://store.example.com/widget", "selector": ".price-current"},
  {"name": "Status Page", "url": "https://status.example.com", "selector": "#current-status"},
  {"name": "Full Page", "url": "https://example.com/announcements"}
]
```

### HTTP Endpoint Monitoring In-Depth

E2NB monitors endpoint availability by making HTTP requests and checking the response status code.

**How it works**:
1. Makes an HTTP request using the configured method (default GET)
2. Compares the response status code against `expected_status` (default 200)
3. Measures response time
4. Tracks state transitions: UP -> DOWN, DOWN -> UP (recovered)
5. Sends notifications only on state changes (avoids flooding)

**Endpoint JSON examples**:

```json
[
  {"name": "API Health", "url": "https://api.example.com/health", "expected_status": 200},
  {"name": "Website", "url": "https://www.example.com", "method": "HEAD", "expected_status": 200},
  {"name": "Auth Service", "url": "https://auth.example.com/ping", "expected_status": 204}
]
```

---

## State Management

E2NB persists monitoring state in `e2nb_state.json` to survive restarts. This file is managed automatically.

**Tracked state**:
- `seen_rss_items`: Per-feed set of item IDs to avoid duplicate notifications
- `seen_pop3_messages`: Set of message hashes for POP3 duplicate detection
- `imap_last_uid`: Per-server last seen UID for IMAP UID-based tracking
- `web_page_hashes`: Per-URL SHA-256 content hashes for change detection
- `http_endpoint_status`: Per-endpoint up/down status and timestamps
- `last_updated`: Timestamp of last state save

**Atomicity**: State is written atomically (write to temp file, then rename) to prevent corruption if the process is interrupted during a save.

**Cleanup**: Old entries are automatically cleaned up when sets grow beyond 1000 items per category, keeping the most recent entries.

---

## Security

- **TwiML injection prevention**: Voice call content is sanitized to prevent XML/TwiML injection
- **Markdown injection prevention**: Telegram messages have special characters escaped for MarkdownV2
- **SSL/TLS certificate verification**: Enabled by default for all connections; configurable per-source
- **Input validation**: URLs, phone numbers, and email addresses are validated before use
- **Atomic state writes**: Prevents state file corruption on crash
- **No credential logging**: Passwords and tokens are never written to log output
- **SMTP receiver authentication**: Optional authentication for the local SMTP server
- **Sandboxed systemd deployment**: Example service file includes security hardening directives

---

## API Reference

### Core Classes

#### NotificationDispatcher

Routes notifications to all enabled channels.

```python
from e2nb_core import NotificationDispatcher, load_config

config = load_config()
dispatcher = NotificationDispatcher(config)

if dispatcher.has_any_enabled():
    results = dispatcher.dispatch(notification, callback=on_result)

# Clean up when done
dispatcher.close()
```

#### EmailNotification

Data class representing a notification from any source.

```python
from e2nb_core import EmailNotification

notification = EmailNotification(
    email_id=b'123',
    sender='user@example.com',
    subject='Test Subject',
    body='Email body content'
)

message = notification.notification_message  # "Test Subject: Email body content"
sms_text = notification.truncate_for_sms(160)
```

#### MonitorEvent

Data class for events from monitoring sources (RSS, Web, HTTP).

```python
from e2nb_core import MonitorEvent

event = MonitorEvent(
    source_type='rss',
    source_name='Tech News',
    title='New Python Release',
    body='Python 3.13 has been released...',
    severity='info',
    metadata={'url': 'https://example.com/article'}
)

# Convert to EmailNotification for dispatching
notification = event.to_email_notification()
```

#### SmtpReceiver

Local SMTP server for receiving emails.

```python
from e2nb_core import SmtpReceiver, SmtpReceiverConfig

config = SmtpReceiverConfig(
    enabled=True,
    host='0.0.0.0',
    port=2525,
    use_auth=False,
    username='',
    password='',
    filter_emails=[]
)

def on_email(notification):
    print(f"Received: {notification.subject}")

receiver = SmtpReceiver(config, callback=on_email)
success, message = receiver.start()
# ... later ...
receiver.stop()
```

#### MonitorState

Persistent state management for monitoring sources.

```python
from e2nb_core import MonitorState

state = MonitorState()  # Loads from e2nb_state.json

# RSS tracking
state.is_rss_item_seen('feed_name', 'item_id')
state.mark_rss_item_seen('feed_name', 'item_id')

# POP3 tracking
state.is_pop3_message_seen('hash_string')
state.mark_pop3_message_seen('hash_string')

# Save state to disk
state.save()
```

### Configuration Classes

```python
from e2nb_core import (
    EmailConfig,         # IMAP/POP3 email connection settings
    TwilioConfig,        # SMS, Voice, WhatsApp credentials
    SlackConfig,         # Slack bot token and channel
    TelegramConfig,      # Telegram bot token and chat ID
    DiscordConfig,       # Discord webhook URL
    WebhookConfig,       # Custom webhook URL
    SmtpConfig,          # SMTP email forwarding settings
    SmtpReceiverConfig,  # Local SMTP receiver settings
    RssFeedConfig,       # RSS monitoring configuration
    WebMonitorConfig,    # Web page monitoring configuration
    HttpEndpointConfig,  # HTTP endpoint monitoring configuration
    AppSettings,         # General application settings
)
```

### Email Operations

```python
from e2nb_core import (
    connect_to_imap, fetch_unread_emails, mark_as_read,
    connect_to_pop3, fetch_pop3_emails, delete_pop3_message,
    extract_email_body, decode_email_subject, get_sender_email, check_email_filter,
    test_imap_connection, test_pop3_connection,
)

# IMAP
imap = connect_to_imap('imap.gmail.com', 993, 'user@gmail.com', 'password')
if imap:
    emails = fetch_unread_emails(imap, max_emails=5)
    for email_id, msg in emails:
        sender = get_sender_email(msg)
        subject = decode_email_subject(msg)
        body = extract_email_body(msg)
        # ... process ...
        mark_as_read(imap, email_id)
    imap.logout()

# POP3
pop3 = connect_to_pop3('pop.gmail.com', 995, 'user@gmail.com', 'password')
if pop3:
    emails = fetch_pop3_emails(pop3, max_emails=5)
    for msg_num, msg in emails:
        # ... process ...
        delete_pop3_message(pop3, msg_num)
    pop3.quit()
```

### Validation Functions

```python
from e2nb_core import validate_url, validate_phone_number, validate_email, sanitize_twiml

validate_url('https://example.com')        # True
validate_phone_number('+15551234567')       # True
validate_email('user@example.com')          # True
sanitize_twiml('<script>alert("x")</script>')  # 'scriptalert("x")/script'
```

---

## Troubleshooting

### Email Connection Failures

| Symptom | Cause | Solution |
|---------|-------|----------|
| Authentication failed | Wrong credentials | Verify username/password. For Gmail with 2FA, use an App Password. |
| Connection timed out | Network or firewall issue | Check server hostname, port, and network connectivity. Try increasing `connection_timeout`. |
| SSL certificate error | Expired or self-signed cert | Update system CA certificates, or set `verify_ssl = False` (not recommended for production). |
| POP3 not working | POP3 disabled on server | Enable POP3 in your mail provider settings (e.g., Gmail: Settings > Forwarding and POP/IMAP). |
| IMAP UNSEEN not finding emails | Server-specific behavior | Some servers require a different IMAP folder. Check if emails are in INBOX. |

### Gmail-Specific Setup

1. **Enable IMAP**: Gmail Settings > See all settings > Forwarding and POP/IMAP > Enable IMAP
2. **2FA users**: Generate an App Password at https://myaccount.google.com/apppasswords
3. **Less secure apps** (legacy accounts without 2FA): This option has been removed by Google. Use App Passwords instead.
4. Use the App Password as the `password` value in config.ini

### SMTP Receiver Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Address already in use" | Port conflict | Change the port or stop the conflicting service. Use `lsof -i :2525` to find what's using the port. |
| Not receiving emails | Firewall blocking | Ensure inbound connections are allowed on the configured port. |
| Authentication failures | Wrong credentials | Verify `use_auth`, `username`, and `password` settings match what the sending client uses. |
| aiosmtpd not found | Package not installed | Run `pip install aiosmtpd` |

### Notification Failures

| Service | Common Issues |
|---------|---------------|
| **Twilio SMS/Voice/WhatsApp** | Invalid credentials; unverified phone number (trial accounts); insufficient balance; wrong number format (must be E.164) |
| **Slack** | Invalid token; bot not invited to channel; missing `chat:write` permission |
| **Telegram** | Invalid bot token; user hasn't started the bot (send `/start` to the bot first); invalid chat ID |
| **Discord** | Invalid or deleted webhook URL; URL must start with `https://discord.com/api/webhooks/` |
| **SMTP** | Wrong server/port; TLS mismatch (port 587 needs STARTTLS, port 465 needs implicit SSL); blocked port by ISP |
| **Webhook** | Endpoint not responding; wrong HTTP method; firewall blocking outbound requests |

### Headless Mode Diagnostics

```bash
# Check if the service is running
sudo systemctl status e2nb

# View recent logs
sudo journalctl -u e2nb -n 100

# Follow logs in real-time
sudo journalctl -u e2nb -f

# Test configuration without starting the daemon
python e2nb-headless.py -c /etc/e2nb/config.ini --test

# Run with verbose logging for debugging
python e2nb-headless.py -c /etc/e2nb/config.ini -v

# Reload configuration on running daemon
sudo systemctl reload e2nb
# or
kill -HUP $(pgrep -f e2nb-headless)
```

### State File Issues

If monitoring is producing duplicate notifications or missing events:

```bash
# View current state
python -c "import json; print(json.dumps(json.load(open('e2nb_state.json')), indent=2))"

# Reset state (will re-process items on next cycle)
rm e2nb_state.json
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and test thoroughly
4. Commit with clear messages: `git commit -m "Add new feature"`
5. Push to your branch: `git push origin feature/new-feature`
6. Open a Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.

---

**Author**: Seth Morrow | **Version**: 1.0.0 | **Repository**: https://github.com/morroware/e2nb
