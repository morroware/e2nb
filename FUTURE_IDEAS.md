# E2NB Future Ideas and Roadmap

This document outlines potential new integrations, features, and improvements for E2NB (Email to Notification Blaster). These suggestions are based on common monitoring and notification use cases, enterprise requirements, and emerging industry standards.

---

## Table of Contents

- [New Notification Integrations](#new-notification-integrations)
  - [Incident Management Platforms](#incident-management-platforms)
  - [Chat & Collaboration](#chat--collaboration)
  - [Push Notification Services](#push-notification-services)
  - [Cloud Provider Services](#cloud-provider-services)
- [New Monitoring Sources](#new-monitoring-sources)
- [Core Feature Enhancements](#core-feature-enhancements)
  - [Message Processing](#message-processing)
  - [Delivery & Reliability](#delivery--reliability)
  - [Security & Compliance](#security--compliance)
  - [Operations & Management](#operations--management)
- [User Interface Improvements](#user-interface-improvements)
- [API & Integration](#api--integration)
- [Enterprise Features](#enterprise-features)
- [Implementation Priority Matrix](#implementation-priority-matrix)

---

## New Notification Integrations

### Incident Management Platforms

These integrations are critical for enterprise environments where on-call rotations and incident response are required.

#### PagerDuty
**Priority: High**

Integration with PagerDuty for incident creation and management.

```ini
[PagerDuty]
enabled = True
routing_key = your-integration-key
severity = critical  # info, warning, error, critical
dedup_key_prefix = e2nb
```

**Features to implement:**
- Create incidents via Events API v2
- Support for all severity levels
- Automatic deduplication key generation
- Resolve/acknowledge incidents programmatically
- Link to source event in incident details

#### Opsgenie (Atlassian)
**Priority: High**

Integration with Opsgenie for alerting and on-call management.

```ini
[Opsgenie]
enabled = True
api_key = your-api-key
priority = P3  # P1-P5
team = infrastructure
tags = monitoring, e2nb
```

**Features to implement:**
- Create alerts via Opsgenie REST API
- Priority mapping from notification rules
- Team routing
- Custom tags and details
- Acknowledge/close alerts

#### Splunk On-Call (VictorOps)
**Priority: Medium**

Integration with Splunk On-Call for incident routing.

```ini
[SplunkOnCall]
enabled = True
api_key = your-api-key
routing_key = default
message_type = CRITICAL  # INFO, WARNING, CRITICAL, RECOVERY
```

### Chat & Collaboration

#### Google Chat
**Priority: High**

Integration with Google Workspace Chat for team notifications.

```ini
[GoogleChat]
enabled = True
webhook_url = https://chat.googleapis.com/v1/spaces/xxx/messages?key=xxx&token=xxx
use_cards = True
thread_key =  # Optional: group related messages
```

**Features to implement:**
- Webhook-based posting
- Card message format
- Thread support for grouping related notifications
- @mention support via user email

#### Webex (Cisco)
**Priority: Medium**

Integration with Cisco Webex Teams.

```ini
[Webex]
enabled = True
bot_token = your-bot-token
room_id = your-room-id
# Or use webhook
webhook_url = https://webexapis.com/v1/webhooks/incoming/xxx
```

#### Mattermost
**Priority: Medium**

Integration with Mattermost (open source Slack alternative).

```ini
[Mattermost]
enabled = True
webhook_url = https://your-mattermost.com/hooks/xxx
channel = town-square
username = E2NB Bot
icon_url = https://example.com/icon.png
```

**Features to implement:**
- Incoming webhook support
- Channel override per message
- Custom username and icon
- Attachment formatting

#### Matrix
**Priority: Medium**

Integration with Matrix protocol for decentralized, federated chat.

```ini
[Matrix]
enabled = True
homeserver = https://matrix.org
access_token = your-access-token
room_id = !roomid:matrix.org
formatted = True  # Use HTML formatting
```

**Features to implement:**
- Client-server API v3
- HTML/Markdown message formatting
- Room alias support
- End-to-end encryption (optional)

#### Rocket.Chat
**Priority: Low**

Integration with Rocket.Chat (open source team chat).

```ini
[RocketChat]
enabled = True
webhook_url = https://your-rocket.chat/hooks/xxx
channel = #general
```

#### IRC
**Priority: Low**

Integration with IRC networks for legacy systems.

```ini
[IRC]
enabled = True
server = irc.libera.chat
port = 6697
use_ssl = True
nickname = e2nb-bot
channel = #notifications
nickserv_password =
```

### Push Notification Services

#### Gotify
**Priority: Medium**

Integration with Gotify (self-hosted push notifications).

```ini
[Gotify]
enabled = True
server_url = https://gotify.your-domain.com
app_token = your-app-token
priority = 5  # 0-10
```

**Features to implement:**
- Message posting via REST API
- Priority levels
- Markdown content support
- Click-through URLs

#### Simplepush
**Priority: Low**

Integration with Simplepush (simple push notifications).

```ini
[Simplepush]
enabled = True
key = your-key
event =  # Optional event name
```

#### Pushbullet
**Priority: Low**

Integration with Pushbullet for cross-device notifications.

```ini
[Pushbullet]
enabled = True
api_key = your-api-key
device_iden =  # Optional specific device
channel_tag =  # Optional channel
```

### Cloud Provider Services

#### AWS SNS
**Priority: High**

Integration with Amazon Simple Notification Service.

```ini
[AWSSNS]
enabled = True
topic_arn = arn:aws:sns:us-east-1:123456789:my-topic
region = us-east-1
access_key_id = your-access-key
secret_access_key = your-secret-key
# Or use IAM role (leave keys empty)
```

**Features to implement:**
- Publish to SNS topics
- Message attributes support
- Subject line for email subscriptions
- SMS via SNS (alternative to Twilio)
- IAM role authentication

#### Azure Notification Hubs
**Priority: Medium**

Integration with Azure Notification Hubs for mobile push.

```ini
[AzureNotification]
enabled = True
connection_string = your-connection-string
hub_name = your-hub-name
```

#### Firebase Cloud Messaging (FCM)
**Priority: Medium**

Integration with Firebase for mobile and web push notifications.

```ini
[Firebase]
enabled = True
credentials_file = /path/to/service-account.json
# Or inline credentials
project_id = your-project-id
topic = notifications  # or device tokens
```

#### Google Cloud Pub/Sub
**Priority: Low**

Integration with Google Cloud Pub/Sub for event streaming.

```ini
[GCPPubSub]
enabled = True
credentials_file = /path/to/service-account.json
project_id = your-project-id
topic = notifications
```

---

## New Monitoring Sources

### Database Monitoring
**Priority: Medium**

Monitor database query results for specific conditions.

```ini
[DatabaseMonitor]
enabled = True
check_interval = 300

[DatabaseMonitor.order_alerts]
type = postgresql  # postgresql, mysql, sqlite, mssql
connection_string = postgresql://user:pass@host:5432/db
query = SELECT COUNT(*) FROM orders WHERE status = 'failed' AND created_at > NOW() - INTERVAL '5 minutes'
threshold = 0
operator = gt  # gt, lt, eq, ne, gte, lte
```

**Supported databases:**
- PostgreSQL
- MySQL/MariaDB
- SQLite
- Microsoft SQL Server
- Oracle (via cx_Oracle)

### Log File Monitoring
**Priority: High**

Monitor log files for specific patterns.

```ini
[LogMonitor]
enabled = True
check_interval = 60

[LogMonitor.app_errors]
path = /var/log/app/error.log
pattern = ERROR|CRITICAL
# Or multiline pattern
multiline_pattern = Exception.*\n(\s+at.*\n)+
tail_mode = True  # Only check new lines
max_age_seconds = 300
```

### Message Queue Monitoring
**Priority: Medium**

Monitor message queues for depth, age, and health.

```ini
[QueueMonitor]
enabled = True

[QueueMonitor.rabbitmq]
type = rabbitmq
url = amqp://guest:guest@localhost:5672/
queue = important-tasks
max_depth = 1000
max_age_seconds = 3600

[QueueMonitor.redis]
type = redis
url = redis://localhost:6379/0
list_key = task_queue
max_length = 500

[QueueMonitor.sqs]
type = aws_sqs
queue_url = https://sqs.us-east-1.amazonaws.com/123456789/my-queue
max_messages = 100
```

### Docker/Container Monitoring
**Priority: Medium**

Monitor Docker containers and orchestration platforms.

```ini
[DockerMonitor]
enabled = True
socket = unix:///var/run/docker.sock
# Or TCP
host = tcp://localhost:2375

[DockerMonitor.web_app]
container_name = my-web-app
# Or container ID pattern
container_pattern = web-app-*
check_health = True
alert_on_restart = True
alert_on_exit = True
```

### Certificate Expiry Monitoring
**Priority: High**

Monitor SSL/TLS certificate expiration dates.

```ini
[CertMonitor]
enabled = True
check_interval = 86400  # Daily

[CertMonitor.main_site]
host = www.example.com
port = 443
warn_days = 30  # Warn 30 days before expiry
critical_days = 7  # Critical 7 days before

[CertMonitor.internal_api]
host = api.internal.example.com
port = 443
verify_chain = True
```

### DNS Monitoring
**Priority: Low**

Monitor DNS records for changes or expected values.

```ini
[DnsMonitor]
enabled = True
check_interval = 300

[DnsMonitor.main_domain]
domain = example.com
record_type = A
expected_value = 1.2.3.4
nameserver = 8.8.8.8  # Optional custom nameserver
```

### Prometheus/Metrics Monitoring
**Priority: Medium**

Query Prometheus for alerting conditions.

```ini
[PrometheusMonitor]
enabled = True
url = http://prometheus:9090
check_interval = 60

[PrometheusMonitor.high_cpu]
query = 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
severity = warning
```

---

## Core Feature Enhancements

### Message Processing

#### Message Templating
**Priority: High**

Customizable notification formats using templates.

```ini
[Templates]
enabled = True

[Templates.default]
subject = [{source_type}] {subject}
body = Source: {source_name}
       Time: {timestamp}
       Severity: {severity}

       {body}

[Templates.slack]
# Slack-specific with Block Kit
format = blocks
header = {subject}
body = *From:* {sender}\n*Time:* {timestamp}\n\n{body}
```

**Template variables:**
- `{subject}`, `{body}`, `{sender}`
- `{source_type}`, `{source_name}`
- `{timestamp}`, `{timestamp_utc}`, `{timestamp_local}`
- `{severity}`, `{severity_emoji}`
- `{metadata.key}` for custom metadata

#### Content Transformation
**Priority: Medium**

Transform notification content before delivery.

```ini
[Transform]
# Strip HTML tags
strip_html = True
# Convert HTML to Markdown
html_to_markdown = True
# Truncate long messages
max_body_length = 4000
# Redact sensitive data
redact_patterns = \b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b, \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b
redact_replacement = [REDACTED]
```

#### Deduplication
**Priority: High**

Prevent duplicate notifications within a time window.

```ini
[Deduplication]
enabled = True
window_seconds = 300  # 5 minute window
# Fields to use for deduplication
key_fields = source_type, sender, subject
# Or use content hash
use_content_hash = True
```

#### Notification Batching/Digests
**Priority: Medium**

Batch multiple notifications into periodic digests.

```ini
[Batching]
enabled = True
interval_seconds = 3600  # Hourly digest
min_notifications = 3    # Only batch if >= 3 notifications
max_notifications = 50   # Split into multiple digests if > 50
# Time-based batching
schedule = 0 9,12,17 * * *  # 9am, noon, 5pm cron
# Immediate for high severity
bypass_severity = critical, error
```

### Delivery & Reliability

#### Message Queue Persistence
**Priority: High**

Queue notifications for reliable delivery with persistence.

```ini
[Queue]
enabled = True
backend = sqlite  # sqlite, redis, rabbitmq
# SQLite
database = /var/lib/e2nb/queue.db
# Redis
# redis_url = redis://localhost:6379/0
# RabbitMQ
# rabbitmq_url = amqp://guest:guest@localhost:5672/

retry_max_attempts = 5
retry_backoff_base = 60  # seconds
retry_backoff_max = 3600  # 1 hour max
```

#### Per-Channel Retry Policies
**Priority: Medium**

Configure retry behavior per notification channel.

```ini
[Twilio]
enabled = True
# ... existing config ...
retry_attempts = 3
retry_delay = 30
retry_on_status = 429, 500, 502, 503, 504

[Slack]
enabled = True
# ... existing config ...
retry_attempts = 5
retry_delay = 10
circuit_breaker_threshold = 10  # Open circuit after 10 failures
circuit_breaker_reset = 300     # Try again after 5 minutes
```

#### Rate Limiting
**Priority: High**

Prevent notification flooding.

```ini
[RateLimiting]
enabled = True
# Global limits
global_per_minute = 60
global_per_hour = 500

# Per-channel limits
[RateLimiting.sms]
per_minute = 10
per_hour = 100
per_day = 500

[RateLimiting.voice]
per_minute = 2
per_hour = 20

# Per-recipient limits
[RateLimiting.per_recipient]
per_hour = 10
cooldown_seconds = 60
```

#### Quiet Hours / Maintenance Windows
**Priority: Medium**

Suppress or queue notifications during specified periods.

```ini
[QuietHours]
enabled = True
# Time-based
start = 22:00
end = 08:00
timezone = America/New_York
days = mon,tue,wed,thu,fri  # Weekdays only

# Or cron-based windows
windows = 0 22 * * * - 0 8 * * *, 0 0 * * 0  # 10pm-8am + all day Sunday

# Action during quiet hours
action = queue  # queue, drop, or allow_critical
allow_severity = critical
```

#### Escalation Policies
**Priority: Medium**

Escalate unacknowledged notifications.

```ini
[Escalation]
enabled = True

[Escalation.critical]
severity = critical
# Level 1: Immediate
level_1_channels = slack, sms
level_1_delay = 0
# Level 2: After 5 minutes
level_2_channels = voice
level_2_delay = 300
level_2_recipients = +15551234567
# Level 3: After 15 minutes
level_3_channels = pagerduty
level_3_delay = 900
```

### Security & Compliance

#### Credential Encryption
**Priority: High**

Encrypt sensitive configuration values at rest.

```ini
[Security]
encryption_enabled = True
encryption_key_file = /etc/e2nb/encryption.key
# Or use environment variable
# encryption_key_env = E2NB_ENCRYPTION_KEY
# Or use a secrets manager
# secrets_backend = aws_secrets_manager
# secrets_prefix = e2nb/

# Encrypted values use ENC() wrapper
[Twilio]
auth_token = ENC(base64-encrypted-value)
```

**Key management options:**
- File-based key
- Environment variable
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault

#### Audit Logging
**Priority: Medium**

Comprehensive audit trail for compliance.

```ini
[Audit]
enabled = True
log_file = /var/log/e2nb/audit.log
# What to log
log_config_changes = True
log_notifications_sent = True
log_notifications_failed = True
log_authentication = True
# Format
format = json  # json or text
# Retention
max_size_mb = 100
max_files = 10
```

#### TLS/mTLS for Webhooks
**Priority: Medium**

Mutual TLS authentication for webhook endpoints.

```ini
[Webhook.secure_endpoint]
webhook_url = https://secure-api.example.com/webhook
client_cert = /etc/e2nb/client.crt
client_key = /etc/e2nb/client.key
ca_cert = /etc/e2nb/ca.crt
verify_hostname = True
```

### Operations & Management

#### Health Check Endpoint
**Priority: High**

HTTP endpoint for monitoring E2NB itself.

```ini
[HealthCheck]
enabled = True
host = 127.0.0.1
port = 8080
path = /health
# Include component checks
check_email_connection = True
check_smtp_receiver = True
check_notification_channels = True
# Authentication
basic_auth_user = healthcheck
basic_auth_pass = secret
```

**Response format:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "components": {
    "email": {"status": "healthy", "last_check": "2024-01-15T10:00:00Z"},
    "smtp_receiver": {"status": "healthy", "port": 2525},
    "slack": {"status": "healthy", "last_success": "2024-01-15T09:55:00Z"},
    "twilio": {"status": "degraded", "error": "Rate limited"}
  },
  "stats": {
    "notifications_sent_24h": 150,
    "notifications_failed_24h": 3,
    "avg_delivery_time_ms": 450
  }
}
```

#### Prometheus Metrics Export
**Priority: Medium**

Export metrics in Prometheus format.

```ini
[Metrics]
enabled = True
host = 0.0.0.0
port = 9090
path = /metrics
```

**Metrics exported:**
- `e2nb_notifications_total{channel, status}`
- `e2nb_notifications_duration_seconds{channel}`
- `e2nb_source_checks_total{source_type, status}`
- `e2nb_queue_depth`
- `e2nb_rate_limit_hits_total{channel}`

#### Statistics Dashboard Data
**Priority: Medium**

Track and expose notification statistics.

```ini
[Statistics]
enabled = True
database = /var/lib/e2nb/stats.db
retention_days = 90
# Track per-channel stats
track_delivery_time = True
track_failures = True
track_retries = True
```

---

## User Interface Improvements

### Web Dashboard
**Priority: High**

Browser-based configuration and monitoring interface.

**Features:**
- Real-time log streaming via WebSocket
- Configuration editor with validation
- Notification history with search
- Statistics and charts
- Test notification buttons
- Mobile-responsive design

```ini
[WebUI]
enabled = True
host = 0.0.0.0
port = 8080
# Authentication
auth_required = True
username = admin
password_hash = bcrypt-hash
# Or OAuth2
# oauth2_provider = google
# oauth2_client_id = xxx
# oauth2_allowed_domains = example.com
# HTTPS
ssl_cert = /etc/e2nb/cert.pem
ssl_key = /etc/e2nb/key.pem
```

### Mobile App
**Priority: Low**

Native mobile app for iOS/Android.

**Features:**
- Push notifications when E2NB sends alerts
- View notification history
- Quick configuration changes
- Test notifications
- Status monitoring

### Desktop Notifications
**Priority: Low**

Native desktop notifications for GUI mode.

```ini
[DesktopNotifications]
enabled = True
sound = True
# Platform-specific
# Windows: uses win10toast
# macOS: uses pync
# Linux: uses notify-send
```

---

## API & Integration

### REST API
**Priority: High**

RESTful API for programmatic control.

```ini
[API]
enabled = True
host = 0.0.0.0
port = 8081
# Authentication
api_key_required = True
api_keys = key1:admin, key2:readonly
# Rate limiting
rate_limit_per_minute = 100
```

**Endpoints:**
- `GET /api/v1/status` - Service status
- `GET /api/v1/config` - Current configuration
- `PUT /api/v1/config` - Update configuration
- `POST /api/v1/notifications` - Send a notification
- `GET /api/v1/notifications` - List notification history
- `GET /api/v1/stats` - Statistics
- `POST /api/v1/test/{channel}` - Test a channel

### Webhook Input
**Priority: Medium**

Accept notifications from external systems via webhook.

```ini
[WebhookInput]
enabled = True
host = 0.0.0.0
port = 8082
path = /webhook/receive
# Authentication
auth_type = bearer  # bearer, basic, hmac
auth_token = your-secret-token
# For HMAC
# hmac_secret = your-hmac-secret
# hmac_header = X-Signature
```

**Payload format:**
```json
{
  "subject": "Alert Title",
  "body": "Alert details...",
  "sender": "external-system",
  "severity": "warning",
  "metadata": {
    "source": "prometheus",
    "alert_name": "HighCPU"
  }
}
```

### CLI Improvements
**Priority: Medium**

Enhanced command-line interface.

```bash
# Send a test notification
e2nb send --channel slack --message "Test message"

# Check service health
e2nb health

# Validate configuration
e2nb validate -c /etc/e2nb/config.ini

# Show statistics
e2nb stats --last 24h

# Tail logs
e2nb logs -f

# Manage channels
e2nb channel list
e2nb channel test slack
e2nb channel enable telegram
e2nb channel disable sms
```

---

## Enterprise Features

### High Availability
**Priority: Medium**

Clustered deployment for high availability.

```ini
[Cluster]
enabled = True
node_id = node-1
# Discovery
discovery = consul  # consul, etcd, kubernetes
consul_url = http://consul:8500
service_name = e2nb

# Leader election
leader_election = True
# Shared state
state_backend = redis
redis_url = redis://redis:6379/0
```

### Multi-Tenancy
**Priority: Low**

Support multiple isolated tenants.

```ini
[MultiTenancy]
enabled = True
tenant_id_header = X-Tenant-ID
# Per-tenant configuration directory
config_directory = /etc/e2nb/tenants/
# Per-tenant state
state_directory = /var/lib/e2nb/tenants/
```

### LDAP/Active Directory Integration
**Priority: Low**

Authenticate users via LDAP/AD.

```ini
[LDAP]
enabled = True
server = ldap://ldap.example.com
base_dn = dc=example,dc=com
bind_dn = cn=e2nb,ou=services,dc=example,dc=com
bind_password = secret
user_filter = (&(objectClass=user)(sAMAccountName={username}))
group_filter = (&(objectClass=group)(member={user_dn}))
admin_group = CN=E2NB Admins,OU=Groups,DC=example,DC=com
```

---

## Implementation Priority Matrix

| Feature | Priority | Complexity | Impact | Suggested Version |
|---------|----------|------------|--------|-------------------|
| PagerDuty Integration | High | Low | High | 1.1.0 |
| Opsgenie Integration | High | Low | High | 1.1.0 |
| Google Chat Integration | High | Low | Medium | 1.1.0 |
| Message Templating | High | Medium | High | 1.2.0 |
| Deduplication | High | Medium | High | 1.2.0 |
| Rate Limiting | High | Medium | High | 1.2.0 |
| Health Check Endpoint | High | Low | Medium | 1.1.0 |
| Message Queue Persistence | High | High | High | 1.3.0 |
| Credential Encryption | High | Medium | High | 1.2.0 |
| REST API | High | High | High | 2.0.0 |
| Certificate Monitoring | High | Low | Medium | 1.1.0 |
| Log File Monitoring | High | Medium | Medium | 1.2.0 |
| Web Dashboard | High | High | High | 2.0.0 |
| AWS SNS | High | Medium | Medium | 1.2.0 |
| Mattermost | Medium | Low | Medium | 1.1.0 |
| Matrix | Medium | Medium | Low | 1.3.0 |
| Gotify | Medium | Low | Low | 1.2.0 |
| Webex | Medium | Low | Medium | 1.2.0 |
| Per-Channel Retry Policies | Medium | Medium | Medium | 1.2.0 |
| Quiet Hours | Medium | Low | Medium | 1.2.0 |
| Escalation Policies | Medium | Medium | High | 1.3.0 |
| Prometheus Metrics | Medium | Low | Medium | 1.2.0 |
| Audit Logging | Medium | Low | Medium | 1.2.0 |
| Database Monitoring | Medium | High | Medium | 1.3.0 |
| Docker Monitoring | Medium | Medium | Medium | 1.3.0 |
| Firebase/FCM | Medium | Medium | Medium | 1.3.0 |
| Webhook Input | Medium | Medium | Medium | 1.2.0 |
| Notification Batching | Medium | Medium | Medium | 1.3.0 |
| Azure Notifications | Medium | Medium | Low | 1.3.0 |
| Splunk On-Call | Medium | Low | Low | 1.2.0 |
| CLI Improvements | Medium | Low | Medium | 1.2.0 |
| Rocket.Chat | Low | Low | Low | 1.4.0 |
| IRC | Low | Medium | Low | 1.4.0 |
| Simplepush | Low | Low | Low | 1.4.0 |
| Pushbullet | Low | Low | Low | 1.4.0 |
| DNS Monitoring | Low | Low | Low | 1.4.0 |
| GCP Pub/Sub | Low | Medium | Low | 1.4.0 |
| Mobile App | Low | High | Medium | 2.x |
| Desktop Notifications | Low | Low | Low | 1.4.0 |
| Multi-Tenancy | Low | High | Low | 2.x |
| LDAP/AD Integration | Low | Medium | Low | 2.x |
| High Availability | Medium | High | Medium | 2.x |

---

## Contributing

If you'd like to help implement any of these features:

1. Check the [GitHub Issues](https://github.com/morroware/e2nb/issues) for existing discussions
2. Open an issue to discuss your implementation approach
3. Fork the repository and create a feature branch
4. Submit a pull request with tests and documentation

---

## Feedback

Have ideas not listed here? We'd love to hear them!

- Open a [GitHub Issue](https://github.com/morroware/e2nb/issues/new?template=feature_request.md)
- Start a [GitHub Discussion](https://github.com/morroware/e2nb/discussions)

---

*Last updated: 2024*
