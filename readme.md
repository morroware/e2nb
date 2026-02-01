# E2NB (Email to Notification Blaster)

A Python application that monitors email inboxes via IMAP and forwards notifications through multiple channels: SMS, Voice, WhatsApp, Slack, Telegram, Discord, and custom webhooks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

## Table of Contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [GUI Version](#gui-version)
- [Headless Version](#headless-version)
- [Notification Channels](#notification-channels)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Architecture

E2NB consists of three main components:

```
e2nb/
├── e2nb_core.py        # Shared core module (config, IMAP, notifications)
├── e2nb.py             # GUI version (Tkinter)
├── e2nb-headless.py    # Headless daemon version
├── config.ini          # Configuration file
└── requirements.txt    # Python dependencies
```

**Core Module (`e2nb_core.py`)** contains:
- Configuration management with data classes
- IMAP connection and email operations
- Notification service implementations
- Input validation and sanitization
- HTTP retry logic with exponential backoff
- Custom exception hierarchy

## Requirements

- Python 3.8 or higher
- IMAP-enabled email account
- API credentials for desired notification services

### Dependencies

```
twilio>=8.0.0       # SMS, Voice, WhatsApp
slack_sdk>=3.20.0   # Slack notifications
requests>=2.28.0    # HTTP requests
urllib3>=2.0.0      # Retry logic
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
imap_server = imap.gmail.com
imap_port = 993
username = your.email@gmail.com
password = your-app-specific-password
filter_emails = user@example.com, @trusted-domain.com
```

| Setting | Description | Default |
|---------|-------------|---------|
| `imap_server` | IMAP server hostname | imap.gmail.com |
| `imap_port` | IMAP SSL port | 993 |
| `username` | Email address | (empty) |
| `password` | Email password or app-specific password | (empty) |
| `filter_emails` | Comma-separated list of allowed senders or domains (prefix domains with @) | (empty) |

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

## Usage

### GUI Version

```bash
python e2nb.py
```

Features:
- Tabbed interface for configuration
- Real-time log display with color-coded severity levels
- Status indicator showing monitoring state
- Connection test functionality
- Settings persistence to config.ini

Controls:
- **Start Monitoring**: Begin email monitoring loop
- **Stop Monitoring**: Gracefully stop monitoring
- **Save Settings**: Write current configuration to config.ini
- **Tools > Test Email Connection**: Verify IMAP credentials
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
| `--test` | Validate configuration and test IMAP connection |
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

Create a bot via [@BotFather](https://t.me/botfather). Get chat ID via [@userinfobot](https://t.me/userinfobot).

### Discord

```ini
[Discord]
enabled = True
webhook_url = https://discord.com/api/webhooks/xxxxxxxxxxxx/xxxxxxxxxxxx
```

Create webhook in Channel Settings > Integrations > Webhooks.

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

## API Reference

### Core Classes

#### NotificationDispatcher

Handles routing notifications to all enabled channels.

```python
from e2nb_core import NotificationDispatcher, load_config

config = load_config()
dispatcher = NotificationDispatcher(config)

# Check if any method is enabled
if dispatcher.has_any_enabled():
    results = dispatcher.dispatch(notification, callback=on_result)
```

#### EmailNotification

Data class representing an email ready for notification.

```python
from e2nb_core import EmailNotification

notification = EmailNotification(
    email_id=b'123',
    sender='user@example.com',
    subject='Test Subject',
    body='Email body content'
)

# Get combined message
message = notification.notification_message  # "Test Subject: Email body content"

# Truncate for SMS
sms_text = notification.truncate_for_sms(160)
```

#### NotificationResult

Result object returned by notification functions.

```python
result = send_sms_via_twilio(...)

if result.success:
    print(f"Sent via {result.service}: {result.sid}")
else:
    print(f"Failed: {result.message}")
```

### Configuration Classes

```python
from e2nb_core import (
    EmailConfig,
    TwilioConfig,
    SlackConfig,
    TelegramConfig,
    DiscordConfig,
    WebhookConfig,
    AppSettings
)

config = load_config()

email = EmailConfig.from_config(config)
twilio = TwilioConfig.from_config(config, 'Twilio')
slack = SlackConfig.from_config(config)
```

### Validation Functions

```python
from e2nb_core import validate_url, validate_phone_number, validate_email, sanitize_twiml

validate_url('https://example.com')  # True
validate_phone_number('+15551234567')  # True
validate_email('user@example.com')  # True

safe_text = sanitize_twiml('<script>alert("xss")</script>')
```

### IMAP Operations

```python
from e2nb_core import (
    connect_to_imap,
    fetch_unread_emails,
    extract_email_body,
    decode_email_subject,
    get_sender_email,
    mark_as_read,
    check_email_filter
)

imap = connect_to_imap('imap.gmail.com', 993, 'user@gmail.com', 'password')
emails = fetch_unread_emails(imap, max_emails=5)

for email_id, msg in emails:
    sender = get_sender_email(msg)
    subject = decode_email_subject(msg)
    body = extract_email_body(msg)

    if check_email_filter(sender, ['@allowed-domain.com']):
        # Process email
        mark_as_read(imap, email_id)

imap.logout()
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

### Example Output

```
[2024-12-05 10:15:30] INFO: E2NB Daemon v1.0.0 starting...
[2024-12-05 10:15:30] INFO: Configuration loaded from config.ini
[2024-12-05 10:15:30] INFO: Enabled notification methods: SMS, Slack, Discord
[2024-12-05 10:15:31] INFO: Connected to IMAP server imap.gmail.com:993
[2024-12-05 10:15:32] INFO: Found 2 unread email(s)
[2024-12-05 10:15:32] INFO: Processing email from user@example.com: Meeting Reminder...
[2024-12-05 10:15:33] INFO: [SMS] Notification sent: Sent to +15559876543
[2024-12-05 10:15:33] INFO: [Slack] Notification sent: Posted to #notifications
[2024-12-05 10:15:34] INFO: Marked email 456 as read
```

## Troubleshooting

### IMAP Connection Failures

| Issue | Solution |
|-------|----------|
| Authentication failed | Verify username/password; use app-specific password if 2FA enabled |
| Connection timeout | Check network connectivity; verify server hostname and port |
| SSL certificate error | Ensure system CA certificates are up to date |

### Gmail-Specific Issues

1. Enable "Less secure app access" or use App Passwords
2. Enable IMAP in Gmail settings (Settings > See all settings > Forwarding and POP/IMAP)
3. If using 2FA, generate an App Password at https://myaccount.google.com/apppasswords

### Notification Failures

| Service | Common Issues |
|---------|---------------|
| Twilio | Invalid credentials; unverified phone number; insufficient balance |
| Slack | Invalid token; bot not in channel; missing permissions |
| Telegram | Invalid bot token; bot not started by user; invalid chat ID |
| Discord | Invalid webhook URL; webhook deleted |

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
