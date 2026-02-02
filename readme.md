# E2NB (Email to Notification Blaster)

A Python application that monitors multiple sources (Email via IMAP/POP3, SMTP receiver, RSS feeds, web pages, HTTP endpoints) and forwards notifications through multiple channels: SMS, Voice, WhatsApp, Slack, Telegram, Discord, SMTP email, and custom webhooks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

## Table of Contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Monitoring Sources](#monitoring-sources)
- [Notification Channels](#notification-channels)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Architecture

```
e2nb/
├── e2nb_core.py        # Shared core module (config, email, notifications, monitoring)
├── e2nb.py             # GUI version (Tkinter)
├── e2nb-headless.py    # Headless daemon version
├── config.ini          # Configuration file
└── requirements.txt    # Python dependencies
```

**Core Module (`e2nb_core.py`)** contains:
- Configuration management with data classes
- IMAP and POP3 email operations
- SMTP receiver (local SMTP server for push-based email)
- RSS feed monitoring
- Web page change detection
- HTTP endpoint monitoring
- Notification service implementations (8 channels)
- Input validation and sanitization
- HTTP retry logic with exponential backoff
- Atomic state file writes
- Custom exception hierarchy

## Requirements

- Python 3.8 or higher
- Email account with IMAP or POP3 access (or use the SMTP receiver)
- API credentials for desired notification services

### Dependencies

```
twilio>=8.0.0         # SMS, Voice, WhatsApp
slack_sdk>=3.20.0     # Slack notifications
requests>=2.28.0      # HTTP requests
urllib3>=2.0.0        # Retry logic
feedparser>=6.0.0     # RSS/Atom feed parsing
beautifulsoup4>=4.12.0 # HTML parsing (web monitoring, RSS content)
aiosmtpd>=1.4.0       # SMTP receiver
```

GUI version additionally requires `tkinter` (included with most Python installations).

## Installation

```bash
# Clone repository
git clone https://github.com/morroware/e2nb.git
cd e2nb

# Install dependencies
pip install -r requirements.txt

# Run (creates default config.ini on first run)
python e2nb.py          # GUI version
python e2nb-headless.py # Headless version
```

## Configuration

Configuration is stored in `config.ini`. The file is created automatically on first run with default values.

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
filter_emails = user@example.com, @trusted-domain.com
```

| Setting | Description | Default |
|---------|-------------|---------|
| `protocol` | Email protocol: `imap` or `pop3` | imap |
| `imap_server` | IMAP server hostname | imap.gmail.com |
| `imap_port` | IMAP SSL port | 993 |
| `pop3_server` | POP3 server hostname | pop.gmail.com |
| `pop3_port` | POP3 SSL port | 995 |
| `username` | Email address | (empty) |
| `password` | Email password or app-specific password | (empty) |
| `filter_emails` | Comma-separated allowed senders or domains (prefix domains with @) | (empty) |

### General Settings

```ini
[Settings]
max_sms_length = 1600
check_interval = 60
```

| Setting | Description | Default |
|---------|-------------|---------|
| `max_sms_length` | Maximum characters for SMS messages | 1600 |
| `check_interval` | Seconds between email checks | 60 |

## Monitoring Sources

E2NB supports five monitoring sources. All sources are configured in the **Sources** section of the GUI sidebar.

### Email (IMAP)

Traditional pull-based email monitoring. Connects to your mail server via IMAP SSL, checks for unread messages at the configured interval, and forwards them to your notification channels.

### Email (POP3)

Alternative pull-based email monitoring via POP3 SSL. Useful for mail servers that don't support IMAP. Select POP3 in the protocol setting and configure your POP3 server details.

### SMTP Receiver

A local SMTP server that listens for incoming emails. Instead of polling a remote server, emails are pushed directly to E2NB. This is useful for receiving forwarded mail from other servers or services.

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
| `enabled` | Enable the local SMTP receiver | False |
| `host` | Listen address | 0.0.0.0 |
| `port` | Listen port | 2525 |
| `use_auth` | Require SMTP authentication | False |
| `username` | Auth username (if `use_auth` is True) | (empty) |
| `password` | Auth password (if `use_auth` is True) | (empty) |
| `filter_emails` | Comma-separated allowed senders or domains | (empty) |

Requires the `aiosmtpd` package.

### RSS Feeds

Monitor RSS/Atom feeds for new items. Each new feed entry triggers a notification.

```ini
[RSS]
enabled = False
feeds = []
check_interval = 300
max_age_hours = 24
max_items_per_check = 10
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable RSS monitoring | False |
| `feeds` | JSON array of feed URLs | [] |
| `check_interval` | Seconds between feed checks | 300 |
| `max_age_hours` | Ignore items older than this | 24 |
| `max_items_per_check` | Max new items to process per check | 10 |

### Web Page Monitor

Detect changes on web pages. E2NB fetches pages periodically and notifies you when content changes.

```ini
[WebMonitor]
enabled = False
pages = []
check_interval = 300
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable web page monitoring | False |
| `pages` | JSON array of page URLs to watch | [] |
| `check_interval` | Seconds between checks | 300 |

### HTTP Endpoint Monitor

Monitor HTTP endpoints for availability. Sends a notification when an endpoint goes down or comes back up.

```ini
[HttpMonitor]
enabled = False
endpoints = []
check_interval = 60
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable HTTP endpoint monitoring | False |
| `endpoints` | JSON array of endpoint URLs | [] |
| `check_interval` | Seconds between checks | 60 |

## Notification Channels

Each notification channel has an `enabled` flag. Set to `True` to activate.

### Twilio SMS

```ini
[Twilio]
enabled = True
account_sid = ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
auth_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
from_number = +15551234567
destination_number = +15559876543, +15551111111
```

Multiple destination numbers supported (comma-separated).

### Twilio Voice

```ini
[Voice]
enabled = True
account_sid = ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
auth_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
from_number = +15551234567
destination_number = +15559876543
```

Uses TwiML to read email content via text-to-speech.

### Twilio WhatsApp

```ini
[WhatsApp]
enabled = True
account_sid = ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
auth_token = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
from_number = whatsapp:+14155238886
to_number = whatsapp:+15559876543
```

Numbers must include `whatsapp:` prefix.

### Slack

```ini
[Slack]
enabled = True
token = xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx
channel = #notifications
```

Requires a Slack Bot Token with `chat:write` scope.

### Telegram

```ini
[Telegram]
enabled = True
bot_token = 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
chat_id = -1001234567890
```

Messages are truncated to 4096 characters (Telegram API limit). Create a bot via [@BotFather](https://t.me/botfather).

### Discord

```ini
[Discord]
enabled = True
webhook_url = https://discord.com/api/webhooks/xxxxxxxxxxxx/xxxxxxxxxxxx
```

Messages are truncated to 2000 characters (Discord API limit). Create webhook in Channel Settings > Integrations > Webhooks.

### SMTP (Email Forwarding)

Forward notifications as emails via an SMTP server.

```ini
[SMTP]
enabled = False
smtp_server = smtp.gmail.com
smtp_port = 587
use_tls = True
username =
password =
from_address =
to_addresses =
subject_prefix = [E2NB]
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable SMTP email notifications | False |
| `smtp_server` | Outbound SMTP server | smtp.gmail.com |
| `smtp_port` | SMTP port | 587 |
| `use_tls` | Use STARTTLS | True |
| `username` | SMTP username | (empty) |
| `password` | SMTP password | (empty) |
| `from_address` | Sender address | (empty) |
| `to_addresses` | Comma-separated recipient addresses | (empty) |
| `subject_prefix` | Prefix added to email subjects | [E2NB] |

### Custom Webhook

```ini
[CustomWebhook]
enabled = True
webhook_url = https://api.example.com/webhook
```

Sends POST request with JSON payload:

```json
{
  "subject": "Email Subject",
  "body": "Email body content",
  "sender": "sender@example.com",
  "timestamp": "2024-12-05T10:15:30.000000"
}
```

## Usage

### GUI Version

```bash
python e2nb.py
```

The GUI sidebar is organized into four sections:

- **Sources**: Email (IMAP/POP3), SMTP Receiver, RSS Feeds, Web Monitor, HTTP Monitor
- **Notifications**: SMS, Voice, WhatsApp, Slack, Telegram, Discord, SMTP, Webhook
- **Configuration**: General settings
- **Monitor**: Start/stop monitoring, real-time logs

Features:
- Protocol selection (IMAP/POP3) with dynamic form fields
- Real-time log display with color-coded severity levels
- Status indicator showing monitoring state
- Connection test functionality for both IMAP and POP3
- Settings persistence to config.ini

Controls:
- **Start Monitoring**: Begin monitoring all enabled sources
- **Stop Monitoring**: Gracefully stop monitoring
- **Save Settings**: Write current configuration to config.ini
- **Tools > Test Email Connection**: Verify email credentials (IMAP or POP3)
- **Tools > Clear Logs**: Clear the log display

### Headless Version

```bash
# Basic usage
python e2nb-headless.py

# Custom configuration file
python e2nb-headless.py -c /etc/e2nb/config.ini

# Custom log file
python e2nb-headless.py -l /var/log/e2nb.log

# Verbose (debug) logging
python e2nb-headless.py -v

# Disable console output (log to file only)
python e2nb-headless.py --no-console

# Test configuration and exit
python e2nb-headless.py --test

# Show version
python e2nb-headless.py --version
```

#### Command-Line Arguments

| Argument | Description |
|----------|-------------|
| `-c, --config` | Path to configuration file (default: config.ini) |
| `-l, --log-file` | Path to log file (default: email_monitor.log) |
| `-v, --verbose` | Enable debug-level logging |
| `--no-console` | Disable console output |
| `--test` | Validate configuration and test connections |
| `--version` | Display version and exit |

#### Signal Handling

| Signal | Action |
|--------|--------|
| `SIGINT` (Ctrl+C) | Graceful shutdown |
| `SIGTERM` | Graceful shutdown |
| `SIGHUP` | Reload configuration |

#### Running as a Systemd Service

Create `/etc/systemd/system/e2nb.service`:

```ini
[Unit]
Description=E2NB Email Monitor
After=network.target

[Service]
Type=simple
User=e2nb
WorkingDirectory=/opt/e2nb
ExecStart=/usr/bin/python3 /opt/e2nb/e2nb-headless.py -c /etc/e2nb/config.ini -l /var/log/e2nb.log --no-console
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable e2nb
sudo systemctl start e2nb
sudo systemctl status e2nb

# Reload configuration without restart
sudo systemctl reload e2nb
```

## API Reference

### Core Classes

#### NotificationDispatcher

Handles routing notifications to all enabled channels.

```python
from e2nb_core import NotificationDispatcher, load_config

config = load_config()
dispatcher = NotificationDispatcher(config)

if dispatcher.has_any_enabled():
    results = dispatcher.dispatch(notification, callback=on_result)
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

#### SmtpReceiver

Local SMTP server for receiving emails via push.

```python
from e2nb_core import SmtpReceiver, SmtpReceiverConfig

config = SmtpReceiverConfig(enabled=True, host='0.0.0.0', port=2525)
receiver = SmtpReceiver(config, callback=on_email_received)
receiver.start()
# ...
receiver.stop()
```

### Configuration Classes

```python
from e2nb_core import (
    EmailConfig,       # IMAP/POP3 email settings
    TwilioConfig,      # SMS and Voice
    SlackConfig,       # Slack
    TelegramConfig,    # Telegram
    DiscordConfig,     # Discord
    WebhookConfig,     # Custom webhooks
    SmtpReceiverConfig, # Local SMTP receiver
    AppSettings        # General settings
)
```

### Email Operations

```python
from e2nb_core import (
    # IMAP
    connect_to_imap, fetch_unread_emails, mark_as_read,
    # POP3
    connect_to_pop3, fetch_pop3_emails, delete_pop3_message,
    # Shared
    extract_email_body, decode_email_subject, get_sender_email, check_email_filter
)

# IMAP
imap = connect_to_imap('imap.gmail.com', 993, 'user@gmail.com', 'password')
emails = fetch_unread_emails(imap, max_emails=5)
imap.logout()

# POP3
pop3 = connect_to_pop3('pop.gmail.com', 995, 'user@gmail.com', 'password')
emails = fetch_pop3_emails(pop3, max_emails=5)
pop3.quit()
```

### Validation Functions

```python
from e2nb_core import validate_url, validate_phone_number, validate_email, sanitize_twiml

validate_url('https://example.com')      # True
validate_phone_number('+15551234567')     # True
validate_email('user@example.com')        # True
safe_text = sanitize_twiml('<b>hello</b>')  # "hello"
```

## Logging

### Log Format

```
[YYYY-MM-DD HH:MM:SS] LEVEL: Message
```

### Log Levels

| Level | Description |
|-------|-------------|
| DEBUG | Detailed diagnostic information (verbose mode only) |
| INFO | General operational messages |
| WARNING | Non-critical issues |
| ERROR | Failures requiring attention |

## Troubleshooting

### Email Connection Failures

| Issue | Solution |
|-------|----------|
| IMAP authentication failed | Verify username/password; use app-specific password if 2FA enabled |
| POP3 authentication failed | Same as IMAP; also verify POP3 is enabled in mail server settings |
| Connection timeout | Check network connectivity; verify server hostname and port |
| SSL certificate error | Ensure system CA certificates are up to date |

### Gmail-Specific Issues

1. Enable IMAP/POP in Gmail settings (Settings > See all settings > Forwarding and POP/IMAP)
2. If using 2FA, generate an App Password at https://myaccount.google.com/apppasswords
3. Use the App Password in the `password` field

### SMTP Receiver Issues

| Issue | Solution |
|-------|----------|
| Port already in use | Change the `port` setting or stop the conflicting service |
| Not receiving emails | Verify firewall allows inbound connections on the configured port |
| Authentication failures | Check `use_auth`, `username`, and `password` settings |

### Notification Failures

| Service | Common Issues |
|---------|---------------|
| Twilio | Invalid credentials; unverified phone number; insufficient balance |
| Slack | Invalid token; bot not in channel; missing permissions |
| Telegram | Invalid bot token; bot not started by user; invalid chat ID |
| Discord | Invalid webhook URL; webhook deleted |
| SMTP | Invalid credentials; TLS required but not enabled; blocked port |

### Headless Mode Issues

```bash
# Check service status
sudo systemctl status e2nb

# View recent logs
sudo journalctl -u e2nb -n 50

# Test configuration
python e2nb-headless.py --test

# Run with verbose logging
python e2nb-headless.py -v
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and test thoroughly
4. Commit with clear messages: `git commit -m "Add new feature"`
5. Push to branch: `git push origin feature/new-feature`
6. Open a Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Author: Seth Morrow | Version: 1.0.0
