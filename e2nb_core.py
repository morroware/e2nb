#!/usr/bin/env python3
"""
E2NB Core Module - Shared functionality for Email to Notification Blaster

This module contains all shared functionality used by both the GUI and headless
versions of E2NB, including configuration management, email operations, and
notification services.

Author: Seth Morrow
Date: Dec 2024
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import configparser
import hashlib
import imaplib
import json
import poplib
import logging
import os
import re
import smtplib
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import email as email_module
from email.header import decode_header
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
from html import escape as html_escape
from typing import Any, Callable, List, Optional, Tuple, Dict, Set
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Optional imports with graceful fallback
try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    TwilioClient = None

try:
    from slack_sdk import WebClient as SlackWebClient
    from slack_sdk.errors import SlackApiError
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
    SlackWebClient = None
    SlackApiError = Exception

try:
    import feedparser
    FEEDPARSER_AVAILABLE = True
except ImportError:
    FEEDPARSER_AVAILABLE = False
    feedparser = None

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    BeautifulSoup = None

try:
    from aiosmtpd.controller import Controller as SmtpdController
    from aiosmtpd.smtp import SMTP as AIOSMTP
    AIOSMTPD_AVAILABLE = True
except ImportError:
    AIOSMTPD_AVAILABLE = False
    SmtpdController = None

# Version information
__version__ = "1.0.0"
__author__ = "Seth Morrow"

# Constants
CONFIG_FILE_PATH = 'config.ini'
LOG_FILE_PATH = 'email_monitor.log'
STATE_FILE_PATH = 'e2nb_state.json'
DEFAULT_CHECK_INTERVAL = 60
DEFAULT_MAX_SMS_LENGTH = 1600
DEFAULT_IMAP_PORT = 993
MAX_EMAILS_PER_CHECK = 5
DEFAULT_TIMEOUT = 30
MAX_RETRY_ATTEMPTS = 3
RETRY_BACKOFF_FACTOR = 0.5
DEFAULT_RSS_MAX_AGE_HOURS = 24
DEFAULT_RSS_MAX_ITEMS = 10
DEFAULT_WEB_CHECK_INTERVAL = 300

# Logger setup
logger = logging.getLogger(__name__)


# =============================================================================
# Custom Exceptions
# =============================================================================

class E2NBError(Exception):
    """Base exception for E2NB errors."""
    pass


class ConfigurationError(E2NBError):
    """Raised when there's a configuration problem."""
    pass


class E2NBConnectionError(E2NBError):
    """Raised when connection to a service fails."""
    pass


class NotificationError(E2NBError):
    """Raised when a notification fails to send."""
    pass


class ValidationError(E2NBError):
    """Raised when input validation fails."""
    pass


# =============================================================================
# Data Classes for Configuration
# =============================================================================

DEFAULT_POP3_PORT = 995

@dataclass
class EmailConfig:
    """Email server configuration."""
    protocol: str = "imap"  # 'imap' or 'pop3'
    imap_server: str = "imap.gmail.com"
    imap_port: int = DEFAULT_IMAP_PORT
    pop3_server: str = "pop.gmail.com"
    pop3_port: int = DEFAULT_POP3_PORT
    username: str = ""
    password: str = ""
    filter_emails: List[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'EmailConfig':
        """Create EmailConfig from ConfigParser."""
        section = config['Email'] if 'Email' in config else {}
        filter_str = section.get('filter_emails', '')
        filters = [f.strip().lower() for f in filter_str.split(',') if f.strip()]
        return cls(
            protocol=section.get('protocol', 'imap').lower(),
            imap_server=section.get('imap_server', 'imap.gmail.com'),
            imap_port=int(section.get('imap_port', DEFAULT_IMAP_PORT)),
            pop3_server=section.get('pop3_server', 'pop.gmail.com'),
            pop3_port=int(section.get('pop3_port', str(DEFAULT_POP3_PORT))),
            username=section.get('username', ''),
            password=section.get('password', ''),
            filter_emails=filters
        )


@dataclass
class TwilioConfig:
    """Twilio notification configuration."""
    enabled: bool = False
    account_sid: str = ""
    auth_token: str = ""
    from_number: str = ""
    destination_numbers: List[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: configparser.ConfigParser, section: str) -> 'TwilioConfig':
        """Create TwilioConfig from ConfigParser section."""
        if section not in config:
            return cls()
        sect = config[section]
        dest_key = 'to_number' if section == 'WhatsApp' else 'destination_number'
        dest_str = sect.get(dest_key, '')
        destinations = [n.strip() for n in dest_str.split(',') if n.strip()]
        return cls(
            enabled=sect.getboolean('enabled', fallback=False),
            account_sid=sect.get('account_sid', ''),
            auth_token=sect.get('auth_token', ''),
            from_number=sect.get('from_number', ''),
            destination_numbers=destinations
        )


@dataclass
class SlackConfig:
    """Slack notification configuration."""
    enabled: bool = False
    token: str = ""
    channel: str = ""

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'SlackConfig':
        """Create SlackConfig from ConfigParser."""
        if 'Slack' not in config:
            return cls()
        section = config['Slack']
        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            token=section.get('token', ''),
            channel=section.get('channel', '')
        )


@dataclass
class TelegramConfig:
    """Telegram notification configuration."""
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'TelegramConfig':
        """Create TelegramConfig from ConfigParser."""
        if 'Telegram' not in config:
            return cls()
        section = config['Telegram']
        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            bot_token=section.get('bot_token', ''),
            chat_id=section.get('chat_id', '')
        )


@dataclass
class DiscordConfig:
    """Discord notification configuration."""
    enabled: bool = False
    webhook_url: str = ""

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'DiscordConfig':
        """Create DiscordConfig from ConfigParser."""
        if 'Discord' not in config:
            return cls()
        section = config['Discord']
        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            webhook_url=section.get('webhook_url', '')
        )


@dataclass
class WebhookConfig:
    """Custom webhook configuration."""
    enabled: bool = False
    webhook_url: str = ""

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'WebhookConfig':
        """Create WebhookConfig from ConfigParser."""
        if 'CustomWebhook' not in config:
            return cls()
        section = config['CustomWebhook']
        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            webhook_url=section.get('webhook_url', '')
        )


@dataclass
class SmtpConfig:
    """SMTP email notification configuration."""
    enabled: bool = False
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""
    from_address: str = ""
    to_addresses: List[str] = field(default_factory=list)
    subject_prefix: str = "[E2NB]"

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'SmtpConfig':
        """Create SmtpConfig from ConfigParser."""
        if 'SMTP' not in config:
            return cls()
        section = config['SMTP']
        to_str = section.get('to_addresses', '')
        to_addresses = [addr.strip() for addr in to_str.split(',') if addr.strip()]
        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            smtp_server=section.get('smtp_server', 'smtp.gmail.com'),
            smtp_port=int(section.get('smtp_port', '587')),
            use_tls=section.getboolean('use_tls', fallback=True),
            username=section.get('username', ''),
            password=section.get('password', ''),
            from_address=section.get('from_address', ''),
            to_addresses=to_addresses,
            subject_prefix=section.get('subject_prefix', '[E2NB]')
        )


@dataclass
class SmtpReceiverConfig:
    """SMTP receiver configuration for receiving emails via SMTP."""
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 2525
    use_auth: bool = False
    username: str = ""
    password: str = ""
    filter_emails: List[str] = field(default_factory=list)

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'SmtpReceiverConfig':
        """Create SmtpReceiverConfig from ConfigParser."""
        if 'SmtpReceiver' not in config:
            return cls()
        section = config['SmtpReceiver']
        filter_str = section.get('filter_emails', '')
        filters = [f.strip().lower() for f in filter_str.split(',') if f.strip()]
        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            host=section.get('host', '0.0.0.0'),
            port=int(section.get('port', '2525')),
            use_auth=section.getboolean('use_auth', fallback=False),
            username=section.get('username', ''),
            password=section.get('password', ''),
            filter_emails=filters
        )


# =============================================================================
# Monitoring Source Configurations
# =============================================================================

@dataclass
class RssFeedConfig:
    """RSS/Atom feed monitoring configuration."""
    enabled: bool = False
    feeds: List[Dict[str, Any]] = field(default_factory=list)
    check_interval: int = 300  # 5 minutes default
    max_age_hours: int = DEFAULT_RSS_MAX_AGE_HOURS
    max_items_per_check: int = DEFAULT_RSS_MAX_ITEMS

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'RssFeedConfig':
        """Create RssFeedConfig from ConfigParser."""
        if 'RSS' not in config:
            return cls()
        section = config['RSS']

        # Parse feeds from JSON string
        feeds_str = section.get('feeds', '[]')
        try:
            feeds = json.loads(feeds_str)
        except json.JSONDecodeError:
            feeds = []

        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            feeds=feeds,
            check_interval=int(section.get('check_interval', '300')),
            max_age_hours=int(section.get('max_age_hours', str(DEFAULT_RSS_MAX_AGE_HOURS))),
            max_items_per_check=int(section.get('max_items_per_check', str(DEFAULT_RSS_MAX_ITEMS)))
        )


@dataclass
class WebMonitorConfig:
    """Web page change detection configuration."""
    enabled: bool = False
    pages: List[Dict[str, Any]] = field(default_factory=list)
    check_interval: int = DEFAULT_WEB_CHECK_INTERVAL

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'WebMonitorConfig':
        """Create WebMonitorConfig from ConfigParser."""
        if 'WebMonitor' not in config:
            return cls()
        section = config['WebMonitor']

        # Parse pages from JSON string
        pages_str = section.get('pages', '[]')
        try:
            pages = json.loads(pages_str)
        except json.JSONDecodeError:
            pages = []

        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            pages=pages,
            check_interval=int(section.get('check_interval', str(DEFAULT_WEB_CHECK_INTERVAL)))
        )


@dataclass
class HttpEndpointConfig:
    """HTTP endpoint monitoring configuration."""
    enabled: bool = False
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    check_interval: int = 60

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'HttpEndpointConfig':
        """Create HttpEndpointConfig from ConfigParser."""
        if 'HttpMonitor' not in config:
            return cls()
        section = config['HttpMonitor']

        # Parse endpoints from JSON string
        endpoints_str = section.get('endpoints', '[]')
        try:
            endpoints = json.loads(endpoints_str)
        except json.JSONDecodeError:
            endpoints = []

        return cls(
            enabled=section.getboolean('enabled', fallback=False),
            endpoints=endpoints,
            check_interval=int(section.get('check_interval', '60'))
        )


# =============================================================================
# Generic Monitor Event
# =============================================================================

@dataclass
class MonitorEvent:
    """
    Generic event from any monitoring source.

    This unified event class allows all monitoring sources (email, RSS, web, HTTP)
    to produce events that can be dispatched through the same notification channels.
    """
    source_type: str  # 'email', 'rss', 'web', 'http'
    source_name: str  # User-defined name or identifier
    title: str  # Event title/subject
    body: str  # Event details/content
    timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "info"  # 'info', 'warning', 'error', 'critical'
    url: Optional[str] = None  # Optional link to source
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def notification_message(self) -> str:
        """Get combined title and body for notification."""
        return f"[{self.source_type.upper()}] {self.title}: {self.body}"

    def truncate_for_sms(self, max_length: int) -> str:
        """Get truncated message for SMS."""
        msg = self.notification_message
        if len(msg) > max_length:
            return msg[:max_length - 3] + "..."
        return msg

    def to_email_notification(self) -> 'EmailNotification':
        """Convert to EmailNotification for backward compatibility."""
        return EmailNotification(
            email_id=self.metadata.get('id', b'0'),
            sender=self.source_name,
            subject=f"[{self.source_type.upper()}] {self.title}",
            body=self.body,
            timestamp=self.timestamp
        )


@dataclass
class AppSettings:
    """Application settings."""
    max_sms_length: int = DEFAULT_MAX_SMS_LENGTH
    check_interval: int = DEFAULT_CHECK_INTERVAL

    @classmethod
    def from_config(cls, config: configparser.ConfigParser) -> 'AppSettings':
        """Create AppSettings from ConfigParser."""
        if 'Settings' not in config:
            return cls()
        section = config['Settings']
        return cls(
            max_sms_length=int(section.get('max_sms_length', DEFAULT_MAX_SMS_LENGTH)),
            check_interval=int(section.get('check_interval', DEFAULT_CHECK_INTERVAL))
        )


# =============================================================================
# Validation Functions
# =============================================================================

def validate_url(url: str, schemes: Optional[List[str]] = None) -> bool:
    """
    Validate a URL string.

    Args:
        url: The URL to validate.
        schemes: Allowed URL schemes. Defaults to ['http', 'https'].

    Returns:
        True if URL is valid, False otherwise.
    """
    if schemes is None:
        schemes = ['http', 'https']

    if not url:
        return False

    try:
        parsed = urlparse(url)
        return all([
            parsed.scheme in schemes,
            parsed.netloc,
            len(url) < 2048  # Reasonable URL length limit
        ])
    except Exception:
        return False


def validate_phone_number(number: str) -> bool:
    """
    Validate a phone number format.

    Args:
        number: Phone number string.

    Returns:
        True if format is valid, False otherwise.
    """
    if not number:
        return False

    # Remove common formatting characters
    cleaned = re.sub(r'[\s\-\(\)]', '', number)

    # Check for whatsapp: prefix
    if cleaned.lower().startswith('whatsapp:'):
        cleaned = cleaned[9:]

    # Should start with + and contain only digits after
    pattern = r'^\+?[1-9]\d{6,14}$'
    return bool(re.match(pattern, cleaned))


def validate_email(email_addr: str) -> bool:
    """
    Validate an email address format.

    Args:
        email_addr: Email address string.

    Returns:
        True if format is valid, False otherwise.
    """
    if not email_addr:
        return False

    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email_addr))


def sanitize_twiml(text: str) -> str:
    """
    Sanitize text for safe inclusion in TwiML.

    Args:
        text: Raw text to sanitize.

    Returns:
        Sanitized text safe for TwiML.
    """
    # Remove any potential SSML/HTML injection first
    sanitized = re.sub(r'<[^>]+>', '', text)
    # Then HTML escape for XML safety
    sanitized = html_escape(sanitized)
    # Limit length to prevent abuse
    return sanitized[:3000]


def sanitize_markdown(text: str) -> str:
    """
    Sanitize text for Markdown formatting.

    Args:
        text: Raw text to sanitize.

    Returns:
        Sanitized text safe for Markdown.
    """
    # Escape special Markdown characters
    special_chars = ['*', '_', '`', '[', ']', '(', ')', '#', '+', '-', '.', '!']
    for char in special_chars:
        text = text.replace(char, '\\' + char)
    return text


# =============================================================================
# HTTP Session with Retry
# =============================================================================

def create_http_session(
    retries: int = MAX_RETRY_ATTEMPTS,
    backoff_factor: float = RETRY_BACKOFF_FACTOR,
    status_forcelist: Optional[List[int]] = None
) -> requests.Session:
    """
    Create an HTTP session with retry logic.

    Args:
        retries: Number of retry attempts.
        backoff_factor: Backoff factor between retries.
        status_forcelist: HTTP status codes to retry on.

    Returns:
        Configured requests.Session object.
    """
    if status_forcelist is None:
        status_forcelist = [429, 500, 502, 503, 504]

    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


# =============================================================================
# Configuration Management
# =============================================================================

def load_config(config_file: str = CONFIG_FILE_PATH) -> configparser.ConfigParser:
    """
    Load configuration from INI file.

    Args:
        config_file: Path to the configuration file.

    Returns:
        ConfigParser instance with loaded configuration.

    Raises:
        ConfigurationError: If configuration cannot be loaded.
    """
    config = configparser.ConfigParser()

    try:
        if not os.path.exists(config_file):
            logger.info(f"Config file not found. Creating default at {config_file}")
            create_default_config(config_file)
        config.read(config_file)
        return config
    except Exception as e:
        raise ConfigurationError(f"Failed to load configuration: {e}")


def save_config(config: configparser.ConfigParser, config_file: str = CONFIG_FILE_PATH) -> None:
    """
    Save configuration to INI file.

    Args:
        config: ConfigParser instance to save.
        config_file: Path to the configuration file.

    Raises:
        ConfigurationError: If configuration cannot be saved.
    """
    try:
        with open(config_file, 'w') as file:
            config.write(file)
        logger.info(f"Configuration saved to {config_file}")
    except Exception as e:
        raise ConfigurationError(f"Failed to save configuration: {e}")


def create_default_config(config_file: str = CONFIG_FILE_PATH) -> None:
    """
    Create a default configuration file.

    Args:
        config_file: Path to the configuration file.
    """
    config = configparser.ConfigParser()

    config['Email'] = {
        'protocol': 'imap',
        'imap_server': 'imap.gmail.com',
        'imap_port': str(DEFAULT_IMAP_PORT),
        'pop3_server': 'pop.gmail.com',
        'pop3_port': str(DEFAULT_POP3_PORT),
        'username': '',
        'password': '',
        'filter_emails': ''
    }

    config['Settings'] = {
        'max_sms_length': str(DEFAULT_MAX_SMS_LENGTH),
        'check_interval': str(DEFAULT_CHECK_INTERVAL)
    }

    config['Twilio'] = {
        'enabled': 'False',
        'account_sid': '',
        'auth_token': '',
        'from_number': '',
        'destination_number': ''
    }

    config['Voice'] = {
        'enabled': 'False',
        'account_sid': '',
        'auth_token': '',
        'from_number': '',
        'destination_number': ''
    }

    config['WhatsApp'] = {
        'enabled': 'False',
        'account_sid': '',
        'auth_token': '',
        'from_number': '',
        'to_number': ''
    }

    config['Slack'] = {
        'enabled': 'False',
        'token': '',
        'channel': ''
    }

    config['Telegram'] = {
        'enabled': 'False',
        'bot_token': '',
        'chat_id': ''
    }

    config['Discord'] = {
        'enabled': 'False',
        'webhook_url': ''
    }

    config['CustomWebhook'] = {
        'enabled': 'False',
        'webhook_url': ''
    }

    config['SMTP'] = {
        'enabled': 'False',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': '587',
        'use_tls': 'True',
        'username': '',
        'password': '',
        'from_address': '',
        'to_addresses': '',
        'subject_prefix': '[E2NB]'
    }

    config['SmtpReceiver'] = {
        'enabled': 'False',
        'host': '0.0.0.0',
        'port': '2525',
        'use_auth': 'False',
        'username': '',
        'password': '',
        'filter_emails': ''
    }

    # Monitoring Sources
    config['RSS'] = {
        'enabled': 'False',
        'feeds': '[]',
        'check_interval': '300',
        'max_age_hours': str(DEFAULT_RSS_MAX_AGE_HOURS),
        'max_items_per_check': str(DEFAULT_RSS_MAX_ITEMS)
    }

    config['WebMonitor'] = {
        'enabled': 'False',
        'pages': '[]',
        'check_interval': str(DEFAULT_WEB_CHECK_INTERVAL)
    }

    config['HttpMonitor'] = {
        'enabled': 'False',
        'endpoints': '[]',
        'check_interval': '60'
    }

    with open(config_file, 'w') as file:
        config.write(file)


# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(
    log_file: str = LOG_FILE_PATH,
    level: int = logging.INFO,
    console: bool = True
) -> None:
    """
    Configure logging for the application.

    Args:
        log_file: Path to the log file.
        level: Logging level.
        console: Whether to also log to console.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    root_logger.handlers.clear()

    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Console handler
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)


# =============================================================================
# Email Operations
# =============================================================================

def connect_to_imap(
    server: str,
    port: int,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT
) -> Optional[imaplib.IMAP4_SSL]:
    """
    Establish a secure connection to an IMAP server.

    Args:
        server: IMAP server address.
        port: IMAP server port.
        username: Email username.
        password: Email password.
        timeout: Connection timeout in seconds.

    Returns:
        Authenticated IMAP connection or None on failure.
    """
    try:
        imap = imaplib.IMAP4_SSL(server, port, timeout=timeout)
        imap.login(username, password)
        logger.info(f"Connected to IMAP server {server}:{port}")
        return imap
    except imaplib.IMAP4.error as e:
        logger.error(f"IMAP authentication failed for {server}:{port}: {e}")
        return None
    except TimeoutError:
        logger.error(f"Connection to {server}:{port} timed out")
        return None
    except Exception as e:
        logger.error(f"Failed to connect to IMAP server {server}:{port}: {e}")
        return None


def fetch_unread_emails(
    imap: imaplib.IMAP4_SSL,
    max_emails: int = MAX_EMAILS_PER_CHECK
) -> List[Tuple[bytes, Message]]:
    """
    Retrieve unread emails from the inbox.

    Args:
        imap: Authenticated IMAP connection.
        max_emails: Maximum number of emails to fetch.

    Returns:
        List of tuples containing (email_id, email_message).
    """
    try:
        imap.select("inbox")
        status, messages = imap.search(None, 'UNSEEN')

        if status != "OK":
            logger.info("No unread emails found.")
            return []

        email_ids = messages[0].split()
        if not email_ids:
            logger.debug("Inbox search returned empty results.")
            return []

        # Sort by ID descending (most recent first) and limit
        email_ids = sorted([int(eid) for eid in email_ids], reverse=True)[:max_emails]
        email_ids = [str(eid).encode() for eid in email_ids]

        emails = []
        for email_id in email_ids:
            res, msg_data = imap.fetch(email_id, "(RFC822)")
            for response in msg_data:
                if isinstance(response, tuple):
                    msg = email_module.message_from_bytes(response[1])
                    emails.append((email_id, msg))

        return emails
    except Exception as e:
        logger.error(f"Failed to fetch emails: {e}")
        return []


def connect_to_pop3(
    server: str,
    port: int,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT
) -> Optional[poplib.POP3_SSL]:
    """
    Establish a secure connection to a POP3 server.

    Args:
        server: POP3 server address.
        port: POP3 server port.
        username: Email username.
        password: Email password.
        timeout: Connection timeout in seconds.

    Returns:
        Authenticated POP3 connection or None on failure.
    """
    try:
        pop3 = poplib.POP3_SSL(server, port, timeout=timeout)
        pop3.user(username)
        pop3.pass_(password)
        logger.info(f"Connected to POP3 server {server}:{port}")
        return pop3
    except poplib.error_proto as e:
        logger.error(f"POP3 authentication failed for {server}:{port}: {e}")
        return None
    except TimeoutError:
        logger.error(f"Connection to {server}:{port} timed out")
        return None
    except Exception as e:
        logger.error(f"Failed to connect to POP3 server {server}:{port}: {e}")
        return None


def fetch_pop3_emails(
    pop3: poplib.POP3_SSL,
    max_emails: int = MAX_EMAILS_PER_CHECK
) -> List[Tuple[int, Message]]:
    """
    Retrieve emails from a POP3 server.

    POP3 does not have an 'unread' concept, so we fetch the most recent
    messages. The caller should track which messages have been seen.

    Args:
        pop3: Authenticated POP3 connection.
        max_emails: Maximum number of emails to fetch.

    Returns:
        List of tuples containing (message_number, email_message).
    """
    try:
        count, _ = pop3.stat()
        if count == 0:
            return []

        # Fetch most recent messages (highest numbers = newest)
        start = max(1, count - max_emails + 1)
        emails = []
        for msg_num in range(count, start - 1, -1):
            try:
                resp, lines, octets = pop3.retr(msg_num)
                raw = b'\r\n'.join(lines)
                msg = email_module.message_from_bytes(raw)
                emails.append((msg_num, msg))
            except Exception as e:
                logger.error(f"Failed to fetch POP3 message {msg_num}: {e}")

        return emails
    except Exception as e:
        logger.error(f"Failed to fetch POP3 emails: {e}")
        return []


def delete_pop3_message(pop3: poplib.POP3_SSL, msg_num: int) -> bool:
    """
    Mark a POP3 message for deletion (deleted on quit).

    Args:
        pop3: Authenticated POP3 connection.
        msg_num: Message number to delete.

    Returns:
        True if successful, False otherwise.
    """
    try:
        pop3.dele(msg_num)
        logger.info(f"Marked POP3 message {msg_num} for deletion")
        return True
    except Exception as e:
        logger.error(f"Failed to delete POP3 message {msg_num}: {e}")
        return False


def test_pop3_connection(config: EmailConfig) -> Tuple[bool, str]:
    """
    Test POP3 connection with provided configuration.

    Args:
        config: Email configuration to test.

    Returns:
        Tuple of (success, message).
    """
    try:
        pop3 = connect_to_pop3(
            config.pop3_server,
            config.pop3_port,
            config.username,
            config.password
        )
        if pop3:
            count, size = pop3.stat()
            pop3.quit()
            return True, f"Connected to POP3 server ({count} messages, {size} bytes)"
        return False, "Failed to connect to POP3 server"
    except Exception as e:
        return False, f"POP3 connection error: {e}"


def extract_email_body(msg: Message) -> str:
    """
    Extract plain text body from an email message.

    Args:
        msg: Email message object.

    Returns:
        Plain text body of the email.
    """
    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = part.get("Content-Disposition")

                if content_type == "text/plain" and not content_disposition:
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode("utf-8", errors='ignore')
            return ""
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode("utf-8", errors='ignore')
            return ""
    except Exception as e:
        logger.error(f"Failed to extract email body: {e}")
        return ""


def decode_email_subject(msg: Message) -> str:
    """
    Decode email subject handling various encodings.

    Args:
        msg: Email message object.

    Returns:
        Decoded subject string.
    """
    try:
        subject_header = msg.get("Subject", "")
        if not subject_header:
            return "(No Subject)"

        decoded_parts = decode_header(subject_header)
        subject_parts = []

        for content, encoding in decoded_parts:
            if isinstance(content, bytes):
                subject_parts.append(content.decode(encoding or "utf-8", errors='ignore'))
            else:
                subject_parts.append(content)

        return "".join(subject_parts)
    except Exception as e:
        logger.error(f"Failed to decode subject: {e}")
        return "(Decoding Error)"


def get_sender_email(msg: Message) -> str:
    """
    Extract sender email address from message.

    Args:
        msg: Email message object.

    Returns:
        Sender's email address (lowercase).
    """
    sender = msg.get("From", "")
    if sender:
        _, email_addr = parseaddr(sender)
        return email_addr.lower()
    return ""


def mark_as_read(imap: imaplib.IMAP4_SSL, email_id: bytes) -> bool:
    """
    Mark an email as read on the IMAP server.

    Args:
        imap: Authenticated IMAP connection.
        email_id: The email ID to mark as read.

    Returns:
        True if successful, False otherwise.
    """
    try:
        imap.store(email_id, '+FLAGS', '\\Seen')
        logger.info(f"Marked email {email_id.decode()} as read")
        return True
    except Exception as e:
        logger.error(f"Failed to mark email {email_id.decode()} as read: {e}")
        return False


def check_email_filter(sender_email: str, filters: List[str]) -> bool:
    """
    Check if an email passes the configured filters.

    Args:
        sender_email: Sender's email address.
        filters: List of email filter patterns.

    Returns:
        True if email passes filters (or no filters configured).
    """
    if not filters:
        return True

    sender_lower = sender_email.lower()

    for filter_entry in filters:
        if filter_entry.startswith('@'):
            # Domain filter
            domain = filter_entry[1:]
            if sender_lower.endswith(f"@{domain}"):
                return True
        else:
            # Exact email match
            if sender_lower == filter_entry:
                return True

    return False


# =============================================================================
# Notification Services
# =============================================================================

class NotificationResult:
    """Result of a notification attempt."""

    def __init__(self, success: bool, service: str, message: str = "", sid: str = ""):
        self.success = success
        self.service = service
        self.message = message
        self.sid = sid

    def __bool__(self) -> bool:
        return self.success

    def __repr__(self) -> str:
        status = "SUCCESS" if self.success else "FAILED"
        return f"NotificationResult({self.service}: {status})"


def send_sms_via_twilio(
    account_sid: str,
    auth_token: str,
    from_number: str,
    to_number: str,
    body: str
) -> NotificationResult:
    """
    Send an SMS message using Twilio.

    Args:
        account_sid: Twilio account SID.
        auth_token: Twilio authentication token.
        from_number: Twilio phone number to send from.
        to_number: Recipient's phone number.
        body: Message body.

    Returns:
        NotificationResult with success status and message SID.
    """
    if not TWILIO_AVAILABLE:
        return NotificationResult(False, "SMS", "Twilio SDK not installed")

    if not validate_phone_number(to_number):
        return NotificationResult(False, "SMS", f"Invalid phone number: {to_number}")

    try:
        client = TwilioClient(account_sid, auth_token)
        message = client.messages.create(
            body=body,
            from_=from_number,
            to=to_number
        )
        logger.info(f"Sent SMS to {to_number} with SID: {message.sid}")
        return NotificationResult(True, "SMS", f"Sent to {to_number}", message.sid)
    except Exception as e:
        logger.error(f"Failed to send SMS to {to_number}: {e}")
        return NotificationResult(False, "SMS", str(e))


def make_voice_call(
    account_sid: str,
    auth_token: str,
    from_number: str,
    to_number: str,
    message: str
) -> NotificationResult:
    """
    Make a voice call using Twilio.

    Args:
        account_sid: Twilio account SID.
        auth_token: Twilio authentication token.
        from_number: Twilio phone number to call from.
        to_number: Recipient's phone number.
        message: Message to be read during the call.

    Returns:
        NotificationResult with success status and call SID.
    """
    if not TWILIO_AVAILABLE:
        return NotificationResult(False, "Voice", "Twilio SDK not installed")

    if not validate_phone_number(to_number):
        return NotificationResult(False, "Voice", f"Invalid phone number: {to_number}")

    try:
        # Sanitize message to prevent TwiML injection
        safe_message = sanitize_twiml(message)

        client = TwilioClient(account_sid, auth_token)
        call = client.calls.create(
            twiml=f'<Response><Say>{safe_message}</Say></Response>',
            from_=from_number,
            to=to_number
        )
        logger.info(f"Initiated voice call to {to_number} with SID: {call.sid}")
        return NotificationResult(True, "Voice", f"Called {to_number}", call.sid)
    except Exception as e:
        logger.error(f"Failed to make voice call to {to_number}: {e}")
        return NotificationResult(False, "Voice", str(e))


def send_whatsapp_message(
    account_sid: str,
    auth_token: str,
    from_number: str,
    to_number: str,
    body: str
) -> NotificationResult:
    """
    Send a WhatsApp message using Twilio.

    Args:
        account_sid: Twilio account SID.
        auth_token: Twilio authentication token.
        from_number: Twilio WhatsApp-enabled number.
        to_number: Recipient's WhatsApp number.
        body: Message body.

    Returns:
        NotificationResult with success status and message SID.
    """
    if not TWILIO_AVAILABLE:
        return NotificationResult(False, "WhatsApp", "Twilio SDK not installed")

    try:
        client = TwilioClient(account_sid, auth_token)
        message = client.messages.create(
            body=body,
            from_=from_number,
            to=to_number
        )
        logger.info(f"Sent WhatsApp message to {to_number} with SID: {message.sid}")
        return NotificationResult(True, "WhatsApp", f"Sent to {to_number}", message.sid)
    except Exception as e:
        logger.error(f"Failed to send WhatsApp message to {to_number}: {e}")
        return NotificationResult(False, "WhatsApp", str(e))


def send_slack_message(
    token: str,
    channel: str,
    subject: str,
    body: str
) -> NotificationResult:
    """
    Send a message to a Slack channel.

    Args:
        token: Slack API token.
        channel: Slack channel name.
        subject: Message subject.
        body: Message body.

    Returns:
        NotificationResult with success status and message timestamp.
    """
    if not SLACK_AVAILABLE:
        return NotificationResult(False, "Slack", "Slack SDK not installed")

    if not token or not channel:
        return NotificationResult(False, "Slack", "Token or channel not configured")

    # Ensure channel has # prefix
    if not channel.startswith('#'):
        channel = f'#{channel}'

    try:
        client = SlackWebClient(token=token)
        formatted_body = f"*{subject}*\n{body}"

        response = client.chat_postMessage(
            channel=channel,
            text=formatted_body,
            parse='full'
        )

        timestamp = response.get("ts", "")
        logger.info(f"Sent Slack message with timestamp: {timestamp}")
        return NotificationResult(True, "Slack", f"Posted to {channel}", timestamp)
    except SlackApiError as e:
        error_msg = e.response.get('error', str(e)) if hasattr(e, 'response') else str(e)
        logger.error(f"Failed to send Slack message: {error_msg}")
        return NotificationResult(False, "Slack", error_msg)
    except Exception as e:
        logger.error(f"Unexpected error sending Slack message: {e}")
        return NotificationResult(False, "Slack", str(e))


def send_telegram_message(
    bot_token: str,
    chat_id: str,
    subject: str,
    body: str,
    session: Optional[requests.Session] = None
) -> NotificationResult:
    """
    Send a message to a Telegram chat.

    Args:
        bot_token: Telegram bot token.
        chat_id: Telegram chat ID.
        subject: Message subject.
        body: Message body.
        session: Optional requests session for connection pooling.

    Returns:
        NotificationResult with success status.
    """
    if not bot_token or not chat_id:
        return NotificationResult(False, "Telegram", "Bot token or chat ID not configured")

    try:
        message = f"*{subject}*\n{body}"
        # Telegram message limit is 4096 characters
        if len(message) > 4096:
            message = message[:4093] + "..."
        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        params = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'Markdown'
        }

        http_session = session or create_http_session()
        response = http_session.post(url, data=params, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 200:
            logger.info("Sent Telegram message")
            return NotificationResult(True, "Telegram", "Message sent")
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            logger.error(f"Failed to send Telegram message: {error_msg}")
            return NotificationResult(False, "Telegram", error_msg)
    except Exception as e:
        logger.error(f"Failed to send Telegram message: {e}")
        return NotificationResult(False, "Telegram", str(e))


def send_discord_message(
    webhook_url: str,
    subject: str,
    body: str,
    session: Optional[requests.Session] = None
) -> NotificationResult:
    """
    Send a message to a Discord channel via webhook.

    Args:
        webhook_url: Discord webhook URL.
        subject: Message subject.
        body: Message body.
        session: Optional requests session for connection pooling.

    Returns:
        NotificationResult with success status.
    """
    if not validate_url(webhook_url):
        return NotificationResult(False, "Discord", "Invalid webhook URL")

    try:
        content = f"**{subject}**\n{body}"
        # Discord message limit is 2000 characters
        if len(content) > 2000:
            content = content[:1997] + "..."
        data = {"content": content}

        http_session = session or create_http_session()
        response = http_session.post(webhook_url, json=data, timeout=DEFAULT_TIMEOUT)

        if response.status_code in [200, 204]:
            logger.info("Sent Discord message")
            return NotificationResult(True, "Discord", "Message sent")
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            logger.error(f"Failed to send Discord message: {error_msg}")
            return NotificationResult(False, "Discord", error_msg)
    except Exception as e:
        logger.error(f"Failed to send Discord message: {e}")
        return NotificationResult(False, "Discord", str(e))


def send_custom_webhook(
    webhook_url: str,
    payload: Dict[str, Any],
    session: Optional[requests.Session] = None
) -> NotificationResult:
    """
    Send a payload to a custom webhook.

    Args:
        webhook_url: Webhook URL.
        payload: Data to send.
        session: Optional requests session for connection pooling.

    Returns:
        NotificationResult with success status.
    """
    if not validate_url(webhook_url):
        return NotificationResult(False, "Webhook", "Invalid webhook URL")

    try:
        http_session = session or create_http_session()
        response = http_session.post(webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)

        if response.status_code in [200, 201, 202, 204]:
            logger.info("Sent custom webhook")
            return NotificationResult(True, "Webhook", "Payload delivered")
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            logger.error(f"Failed to send custom webhook: {error_msg}")
            return NotificationResult(False, "Webhook", error_msg)
    except Exception as e:
        logger.error(f"Failed to send custom webhook: {e}")
        return NotificationResult(False, "Webhook", str(e))


def send_email_notification(
    smtp_server: str,
    smtp_port: int,
    username: str,
    password: str,
    from_address: str,
    to_address: str,
    subject: str,
    body: str,
    sender_email: str,
    use_tls: bool = True,
    subject_prefix: str = "[E2NB]"
) -> NotificationResult:
    """
    Send an email notification via SMTP.

    Args:
        smtp_server: SMTP server hostname.
        smtp_port: SMTP server port.
        username: SMTP authentication username.
        password: SMTP authentication password.
        from_address: Sender email address.
        to_address: Recipient email address.
        subject: Original email subject.
        body: Original email body.
        sender_email: Original sender's email address.
        use_tls: Whether to use TLS encryption.
        subject_prefix: Prefix to add to subject line.

    Returns:
        NotificationResult with success status.
    """
    if not validate_email(to_address):
        return NotificationResult(False, "Email", f"Invalid recipient address: {to_address}")

    if not validate_email(from_address):
        return NotificationResult(False, "Email", f"Invalid sender address: {from_address}")

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"{subject_prefix} {subject}"
        msg['From'] = formataddr(("E2NB Notification", from_address))
        msg['To'] = to_address

        # Plain text version
        text_body = f"""E2NB Email Notification
{'=' * 40}

From: {sender_email}
Subject: {subject}

{'=' * 40}
{body}
{'=' * 40}

This notification was sent by E2NB - Email to Notification Blaster.
"""

        # HTML version
        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #3b82f6; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0; font-size: 18px; }}
        .content {{ background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0; }}
        .meta {{ background: #fff; padding: 12px; border-radius: 4px; margin-bottom: 16px; border-left: 4px solid #3b82f6; }}
        .meta strong {{ color: #1e40af; }}
        .body {{ background: #fff; padding: 16px; border-radius: 4px; white-space: pre-wrap; font-family: monospace; font-size: 13px; }}
        .footer {{ background: #f1f5f9; padding: 12px; text-align: center; font-size: 12px; color: #64748b; border-radius: 0 0 8px 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>E2NB Email Notification</h1>
        </div>
        <div class="content">
            <div class="meta">
                <strong>From:</strong> {html_escape(sender_email)}<br>
                <strong>Subject:</strong> {html_escape(subject)}
            </div>
            <div class="body">{html_escape(body)}</div>
        </div>
        <div class="footer">
            Sent by E2NB - Email to Notification Blaster
        </div>
    </div>
</body>
</html>
"""

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        # Connect and send
        if use_tls and smtp_port == 465:
            # SSL connection (port 465)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=DEFAULT_TIMEOUT) as server:
                server.login(username, password)
                server.sendmail(from_address, to_address, msg.as_string())
        else:
            # STARTTLS connection (port 587) or no TLS
            with smtplib.SMTP(smtp_server, smtp_port, timeout=DEFAULT_TIMEOUT) as server:
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                server.login(username, password)
                server.sendmail(from_address, to_address, msg.as_string())

        logger.info(f"Sent email notification to {to_address}")
        return NotificationResult(True, "Email", f"Sent to {to_address}")
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP authentication failed: {e}")
        return NotificationResult(False, "Email", "Authentication failed")
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending to {to_address}: {e}")
        return NotificationResult(False, "Email", str(e))
    except Exception as e:
        logger.error(f"Failed to send email notification to {to_address}: {e}")
        return NotificationResult(False, "Email", str(e))


# =============================================================================
# Email Processing
# =============================================================================

@dataclass
class EmailNotification:
    """Represents an email ready for notification."""
    email_id: bytes
    sender: str
    subject: str
    body: str
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def notification_message(self) -> str:
        """Get combined subject and body for notification."""
        return f"{self.subject}: {self.body}"

    def truncate_for_sms(self, max_length: int) -> str:
        """Get truncated message for SMS."""
        msg = self.notification_message
        if len(msg) > max_length:
            return msg[:max_length - 3] + "..."
        return msg


class NotificationDispatcher:
    """Handles dispatching notifications to all configured channels."""

    def __init__(self, config: configparser.ConfigParser):
        self.settings = AppSettings.from_config(config)
        self.twilio_sms = TwilioConfig.from_config(config, 'Twilio')
        self.twilio_voice = TwilioConfig.from_config(config, 'Voice')
        self.twilio_whatsapp = TwilioConfig.from_config(config, 'WhatsApp')
        self.slack = SlackConfig.from_config(config)
        self.telegram = TelegramConfig.from_config(config)
        self.discord = DiscordConfig.from_config(config)
        self.webhook = WebhookConfig.from_config(config)
        self.smtp = SmtpConfig.from_config(config)
        self.http_session = create_http_session()

    def has_any_enabled(self) -> bool:
        """Check if any notification method is enabled."""
        return any([
            self.twilio_sms.enabled,
            self.twilio_voice.enabled,
            self.twilio_whatsapp.enabled,
            self.slack.enabled,
            self.telegram.enabled,
            self.discord.enabled,
            self.webhook.enabled,
            self.smtp.enabled
        ])

    def dispatch(
        self,
        notification: EmailNotification,
        callback: Optional[Callable[[NotificationResult], None]] = None
    ) -> List[NotificationResult]:
        """
        Send notification to all enabled channels.

        Args:
            notification: Email notification to send.
            callback: Optional callback for each result.

        Returns:
            List of NotificationResult objects.
        """
        results = []

        # SMS via Twilio
        if self.twilio_sms.enabled:
            sms_body = notification.truncate_for_sms(self.settings.max_sms_length)
            for to_number in self.twilio_sms.destination_numbers:
                result = send_sms_via_twilio(
                    self.twilio_sms.account_sid,
                    self.twilio_sms.auth_token,
                    self.twilio_sms.from_number,
                    to_number,
                    sms_body
                )
                results.append(result)
                if callback:
                    callback(result)

        # Voice calls via Twilio
        if self.twilio_voice.enabled:
            for to_number in self.twilio_voice.destination_numbers:
                result = make_voice_call(
                    self.twilio_voice.account_sid,
                    self.twilio_voice.auth_token,
                    self.twilio_voice.from_number,
                    to_number,
                    notification.notification_message
                )
                results.append(result)
                if callback:
                    callback(result)

        # WhatsApp via Twilio
        if self.twilio_whatsapp.enabled:
            for to_number in self.twilio_whatsapp.destination_numbers:
                result = send_whatsapp_message(
                    self.twilio_whatsapp.account_sid,
                    self.twilio_whatsapp.auth_token,
                    self.twilio_whatsapp.from_number,
                    to_number,
                    notification.notification_message
                )
                results.append(result)
                if callback:
                    callback(result)

        # Slack
        if self.slack.enabled:
            result = send_slack_message(
                self.slack.token,
                self.slack.channel,
                notification.subject,
                notification.body
            )
            results.append(result)
            if callback:
                callback(result)

        # Telegram
        if self.telegram.enabled:
            result = send_telegram_message(
                self.telegram.bot_token,
                self.telegram.chat_id,
                notification.subject,
                notification.body,
                self.http_session
            )
            results.append(result)
            if callback:
                callback(result)

        # Discord
        if self.discord.enabled:
            result = send_discord_message(
                self.discord.webhook_url,
                notification.subject,
                notification.body,
                self.http_session
            )
            results.append(result)
            if callback:
                callback(result)

        # Custom Webhook
        if self.webhook.enabled:
            payload = {
                'subject': notification.subject,
                'body': notification.body,
                'sender': notification.sender,
                'timestamp': notification.timestamp.isoformat()
            }
            result = send_custom_webhook(
                self.webhook.webhook_url,
                payload,
                self.http_session
            )
            results.append(result)
            if callback:
                callback(result)

        # SMTP Email
        if self.smtp.enabled:
            for to_address in self.smtp.to_addresses:
                result = send_email_notification(
                    self.smtp.smtp_server,
                    self.smtp.smtp_port,
                    self.smtp.username,
                    self.smtp.password,
                    self.smtp.from_address,
                    to_address,
                    notification.subject,
                    notification.body,
                    notification.sender,
                    self.smtp.use_tls,
                    self.smtp.subject_prefix
                )
                results.append(result)
                if callback:
                    callback(result)

        return results


def test_imap_connection(config: EmailConfig) -> Tuple[bool, str]:
    """
    Test IMAP connection with provided configuration.

    Args:
        config: Email configuration to test.

    Returns:
        Tuple of (success, message).
    """
    try:
        imap = connect_to_imap(
            config.imap_server,
            config.imap_port,
            config.username,
            config.password
        )
        if imap:
            imap.logout()
            return True, f"Successfully connected to {config.imap_server}"
        return False, "Connection failed - check credentials"
    except Exception as e:
        return False, str(e)


def test_smtp_connection(config: SmtpConfig) -> Tuple[bool, str]:
    """
    Test SMTP connection with provided configuration.

    Args:
        config: SMTP configuration to test.

    Returns:
        Tuple of (success, message).
    """
    try:
        if config.use_tls and config.smtp_port == 465:
            # SSL connection (port 465)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(config.smtp_server, config.smtp_port, context=context, timeout=DEFAULT_TIMEOUT) as server:
                server.login(config.username, config.password)
                return True, f"Successfully connected to {config.smtp_server}:{config.smtp_port} (SSL)"
        else:
            # STARTTLS connection (port 587) or no TLS
            with smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=DEFAULT_TIMEOUT) as server:
                server.ehlo()
                if config.use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                server.login(config.username, config.password)
                tls_status = "TLS" if config.use_tls else "no TLS"
                return True, f"Successfully connected to {config.smtp_server}:{config.smtp_port} ({tls_status})"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed - check username and password"
    except smtplib.SMTPConnectError:
        return False, f"Could not connect to {config.smtp_server}:{config.smtp_port}"
    except TimeoutError:
        return False, f"Connection to {config.smtp_server}:{config.smtp_port} timed out"
    except Exception as e:
        return False, str(e)


# =============================================================================
# State Management for Monitoring Sources
# =============================================================================

class MonitorState:
    """
    Manages persistent state for monitoring sources.

    Tracks which items have been seen to avoid duplicate notifications.
    State is persisted to a JSON file.
    """

    def __init__(self, state_file: str = STATE_FILE_PATH):
        self.state_file = state_file
        self._state: Dict[str, Any] = {
            'seen_rss_items': {},  # feed_url -> set of item IDs
            'web_page_hashes': {},  # page_url -> content hash
            'http_endpoint_status': {},  # endpoint_url -> last status
            'last_updated': None
        }
        self._load()

    def _load(self):
        """Load state from file."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    loaded = json.load(f)
                    # Convert lists back to sets for seen_rss_items
                    if 'seen_rss_items' in loaded:
                        loaded['seen_rss_items'] = {
                            k: set(v) for k, v in loaded['seen_rss_items'].items()
                        }
                    self._state.update(loaded)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load state file: {e}")

    def save(self):
        """Save state to file atomically."""
        try:
            # Convert sets to lists for JSON serialization
            state_to_save = self._state.copy()
            if 'seen_rss_items' in state_to_save:
                state_to_save['seen_rss_items'] = {
                    k: list(v) for k, v in state_to_save['seen_rss_items'].items()
                }
            state_to_save['last_updated'] = datetime.now().isoformat()

            # Write to temp file then rename for atomicity
            tmp_file = self.state_file + '.tmp'
            with open(tmp_file, 'w') as f:
                json.dump(state_to_save, f, indent=2)
            os.replace(tmp_file, self.state_file)
        except IOError as e:
            logger.error(f"Could not save state file: {e}")

    def is_rss_item_seen(self, feed_url: str, item_id: str) -> bool:
        """Check if an RSS item has been seen before."""
        seen = self._state.get('seen_rss_items', {}).get(feed_url, set())
        return item_id in seen

    def mark_rss_item_seen(self, feed_url: str, item_id: str):
        """Mark an RSS item as seen."""
        if feed_url not in self._state['seen_rss_items']:
            self._state['seen_rss_items'][feed_url] = set()
        self._state['seen_rss_items'][feed_url].add(item_id)

    def get_web_page_hash(self, url: str) -> Optional[str]:
        """Get stored hash for a web page."""
        return self._state.get('web_page_hashes', {}).get(url)

    def set_web_page_hash(self, url: str, content_hash: str):
        """Store hash for a web page."""
        if 'web_page_hashes' not in self._state:
            self._state['web_page_hashes'] = {}
        self._state['web_page_hashes'][url] = content_hash

    def get_http_status(self, url: str) -> Optional[Dict[str, Any]]:
        """Get last known status for an HTTP endpoint."""
        return self._state.get('http_endpoint_status', {}).get(url)

    def set_http_status(self, url: str, status: Dict[str, Any]):
        """Store status for an HTTP endpoint."""
        if 'http_endpoint_status' not in self._state:
            self._state['http_endpoint_status'] = {}
        self._state['http_endpoint_status'][url] = status

    def cleanup_old_rss_items(self, feed_url: str, max_items: int = 1000):
        """Limit stored RSS items to prevent unbounded growth."""
        if feed_url in self._state.get('seen_rss_items', {}):
            items = self._state['seen_rss_items'][feed_url]
            if len(items) > max_items:
                # Convert to list, keep recent items, convert back to set
                items_list = list(items)
                self._state['seen_rss_items'][feed_url] = set(items_list[-max_items:])


# =============================================================================
# RSS Feed Monitoring
# =============================================================================

def fetch_rss_feed(
    feed_url: str,
    session: Optional[requests.Session] = None
) -> Tuple[bool, Optional[Any], str]:
    """
    Fetch and parse an RSS/Atom feed.

    Args:
        feed_url: URL of the RSS/Atom feed.
        session: Optional requests session.

    Returns:
        Tuple of (success, parsed_feed, error_message).
    """
    if not FEEDPARSER_AVAILABLE:
        return False, None, "feedparser library not installed"

    if not validate_url(feed_url):
        return False, None, f"Invalid feed URL: {feed_url}"

    try:
        http_session = session or create_http_session()
        response = http_session.get(feed_url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        feed = feedparser.parse(response.content)

        if feed.bozo and not feed.entries:
            return False, None, f"Feed parsing error: {feed.bozo_exception}"

        return True, feed, ""
    except requests.RequestException as e:
        return False, None, f"Failed to fetch feed: {e}"
    except Exception as e:
        return False, None, f"Error parsing feed: {e}"


def get_rss_item_id(entry: Any) -> str:
    """
    Get a unique identifier for an RSS entry.

    Args:
        entry: Feedparser entry object.

    Returns:
        Unique identifier string.
    """
    # Try various ID fields in order of preference
    if hasattr(entry, 'id') and entry.id:
        return entry.id
    if hasattr(entry, 'link') and entry.link:
        return entry.link
    if hasattr(entry, 'title') and entry.title:
        # Hash of title + published date as fallback
        pub_date = getattr(entry, 'published', '') or getattr(entry, 'updated', '')
        return hashlib.md5(f"{entry.title}{pub_date}".encode()).hexdigest()
    return hashlib.md5(str(entry).encode()).hexdigest()


def get_rss_entry_date(entry: Any) -> Optional[datetime]:
    """
    Extract publication date from an RSS entry.

    Args:
        entry: Feedparser entry object.

    Returns:
        Datetime object or None if not available.
    """
    for date_field in ['published_parsed', 'updated_parsed', 'created_parsed']:
        parsed_date = getattr(entry, date_field, None)
        if parsed_date:
            try:
                return datetime(*parsed_date[:6])
            except (TypeError, ValueError):
                continue
    return None


def check_rss_feeds(
    config: RssFeedConfig,
    state: MonitorState,
    session: Optional[requests.Session] = None
) -> List[MonitorEvent]:
    """
    Check RSS feeds for new items.

    Args:
        config: RSS feed configuration.
        state: Monitor state for tracking seen items.
        session: Optional requests session.

    Returns:
        List of MonitorEvent objects for new items.
    """
    if not config.enabled or not config.feeds:
        return []

    if not FEEDPARSER_AVAILABLE:
        logger.warning("feedparser not installed, skipping RSS monitoring")
        return []

    events = []
    max_age = timedelta(hours=config.max_age_hours)
    now = datetime.now()

    for feed_config in config.feeds:
        feed_url = feed_config.get('url', '')
        feed_name = feed_config.get('name', feed_url)
        keywords = [k.lower() for k in feed_config.get('keywords', [])]

        if not feed_url:
            continue

        success, feed, error = fetch_rss_feed(feed_url, session)
        if not success:
            logger.warning(f"Failed to fetch RSS feed '{feed_name}': {error}")
            continue

        items_found = 0
        for entry in feed.entries:
            if items_found >= config.max_items_per_check:
                break

            item_id = get_rss_item_id(entry)

            # Skip if already seen
            if state.is_rss_item_seen(feed_url, item_id):
                continue

            # Check age if date available
            pub_date = get_rss_entry_date(entry)
            if pub_date and (now - pub_date) > max_age:
                # Item is too old, but mark as seen to avoid checking again
                state.mark_rss_item_seen(feed_url, item_id)
                continue

            # Extract content
            title = getattr(entry, 'title', 'No Title')
            summary = getattr(entry, 'summary', '') or getattr(entry, 'description', '')
            link = getattr(entry, 'link', '')

            # Clean up summary (remove HTML tags if present)
            if summary and BS4_AVAILABLE:
                try:
                    soup = BeautifulSoup(summary, 'html.parser')
                    summary = soup.get_text(separator=' ', strip=True)
                except Exception:
                    pass
            elif summary:
                # Basic HTML tag removal
                summary = re.sub(r'<[^>]+>', '', summary)

            # Truncate summary
            if len(summary) > 500:
                summary = summary[:497] + "..."

            # Apply keyword filter if specified
            if keywords:
                text_to_check = f"{title} {summary}".lower()
                if not any(kw in text_to_check for kw in keywords):
                    state.mark_rss_item_seen(feed_url, item_id)
                    continue

            # Create event
            event = MonitorEvent(
                source_type='rss',
                source_name=feed_name,
                title=title,
                body=summary,
                timestamp=pub_date or now,
                severity='info',
                url=link,
                metadata={
                    'id': item_id.encode() if isinstance(item_id, str) else item_id,
                    'feed_url': feed_url,
                    'author': getattr(entry, 'author', '')
                }
            )
            events.append(event)
            state.mark_rss_item_seen(feed_url, item_id)
            items_found += 1
            logger.info(f"New RSS item from '{feed_name}': {title}")

        # Cleanup old items to prevent unbounded growth
        state.cleanup_old_rss_items(feed_url)

    return events


def test_rss_feed(feed_url: str) -> Tuple[bool, str]:
    """
    Test an RSS feed URL.

    Args:
        feed_url: URL of the RSS/Atom feed.

    Returns:
        Tuple of (success, message).
    """
    if not FEEDPARSER_AVAILABLE:
        return False, "feedparser library not installed (pip install feedparser)"

    success, feed, error = fetch_rss_feed(feed_url)
    if not success:
        return False, error

    entry_count = len(feed.entries)
    feed_title = feed.feed.get('title', 'Unknown')
    return True, f"Feed '{feed_title}' has {entry_count} entries"


# =============================================================================
# Web Page Change Detection
# =============================================================================

def fetch_web_page(
    url: str,
    css_selector: Optional[str] = None,
    session: Optional[requests.Session] = None
) -> Tuple[bool, str, str]:
    """
    Fetch a web page and optionally extract content using a CSS selector.

    Args:
        url: URL of the web page.
        css_selector: Optional CSS selector to extract specific content.
        session: Optional requests session.

    Returns:
        Tuple of (success, content, error_message).
    """
    if not validate_url(url):
        return False, "", f"Invalid URL: {url}"

    try:
        http_session = session or create_http_session()
        response = http_session.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()

        content = response.text

        # Extract specific content if selector provided
        if css_selector and BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(content, 'html.parser')
                elements = soup.select(css_selector)
                if elements:
                    content = '\n'.join(elem.get_text(strip=True) for elem in elements)
                else:
                    return False, "", f"CSS selector '{css_selector}' matched no elements"
            except Exception as e:
                return False, "", f"CSS selector error: {e}"

        return True, content, ""
    except requests.RequestException as e:
        return False, "", f"Failed to fetch page: {e}"
    except Exception as e:
        return False, "", f"Error: {e}"


def compute_content_hash(content: str) -> str:
    """Compute SHA256 hash of content."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def check_web_pages(
    config: WebMonitorConfig,
    state: MonitorState,
    session: Optional[requests.Session] = None
) -> List[MonitorEvent]:
    """
    Check web pages for changes.

    Args:
        config: Web monitor configuration.
        state: Monitor state for tracking page hashes.
        session: Optional requests session.

    Returns:
        List of MonitorEvent objects for changed pages.
    """
    if not config.enabled or not config.pages:
        return []

    events = []

    for page_config in config.pages:
        url = page_config.get('url', '')
        name = page_config.get('name', url)
        css_selector = page_config.get('selector', None)
        notify_on_error = page_config.get('notify_on_error', True)

        if not url:
            continue

        success, content, error = fetch_web_page(url, css_selector, session)

        if not success:
            if notify_on_error:
                # Check if this is a new error (status changed from OK)
                last_status = state.get_http_status(url)
                if last_status and last_status.get('ok', True):
                    event = MonitorEvent(
                        source_type='web',
                        source_name=name,
                        title=f"Page Error: {name}",
                        body=f"Failed to fetch page: {error}",
                        severity='error',
                        url=url,
                        metadata={'error': error}
                    )
                    events.append(event)
                    logger.warning(f"Web page '{name}' error: {error}")
            state.set_http_status(url, {'ok': False, 'error': error})
            continue

        # Compute hash of content
        content_hash = compute_content_hash(content)
        previous_hash = state.get_web_page_hash(url)

        if previous_hash is None:
            # First time seeing this page, store hash but don't notify
            state.set_web_page_hash(url, content_hash)
            state.set_http_status(url, {'ok': True})
            logger.info(f"Web page '{name}' - initial hash stored")
            continue

        if content_hash != previous_hash:
            # Page changed
            event = MonitorEvent(
                source_type='web',
                source_name=name,
                title=f"Page Changed: {name}",
                body=f"The monitored page has been updated.",
                severity='info',
                url=url,
                metadata={
                    'id': content_hash.encode(),
                    'previous_hash': previous_hash,
                    'new_hash': content_hash
                }
            )
            events.append(event)
            state.set_web_page_hash(url, content_hash)
            logger.info(f"Web page '{name}' changed")

        state.set_http_status(url, {'ok': True})

    return events


# =============================================================================
# HTTP Endpoint Monitoring
# =============================================================================

def check_http_endpoint(
    url: str,
    method: str = 'GET',
    expected_status: int = 200,
    expected_text: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    session: Optional[requests.Session] = None
) -> Tuple[bool, int, float, str]:
    """
    Check an HTTP endpoint.

    Args:
        url: Endpoint URL.
        method: HTTP method.
        expected_status: Expected HTTP status code.
        expected_text: Optional text that should be in response.
        timeout: Request timeout.
        session: Optional requests session.

    Returns:
        Tuple of (success, status_code, response_time, error_message).
    """
    if not validate_url(url):
        return False, 0, 0.0, f"Invalid URL: {url}"

    try:
        http_session = session or create_http_session()
        start_time = time.time()
        response = http_session.request(method.upper(), url, timeout=timeout)
        response_time = time.time() - start_time

        status_ok = response.status_code == expected_status
        text_ok = True

        if expected_text and expected_text not in response.text:
            text_ok = False

        if status_ok and text_ok:
            return True, response.status_code, response_time, ""
        elif not status_ok:
            return False, response.status_code, response_time, f"Expected status {expected_status}, got {response.status_code}"
        else:
            return False, response.status_code, response_time, f"Expected text not found in response"

    except requests.Timeout:
        return False, 0, timeout, f"Request timed out after {timeout}s"
    except requests.RequestException as e:
        return False, 0, 0.0, f"Request failed: {e}"
    except Exception as e:
        return False, 0, 0.0, f"Error: {e}"


def check_http_endpoints(
    config: HttpEndpointConfig,
    state: MonitorState,
    session: Optional[requests.Session] = None
) -> List[MonitorEvent]:
    """
    Check HTTP endpoints for availability and status.

    Args:
        config: HTTP endpoint configuration.
        state: Monitor state for tracking endpoint status.
        session: Optional requests session.

    Returns:
        List of MonitorEvent objects for status changes.
    """
    if not config.enabled or not config.endpoints:
        return []

    events = []

    for endpoint_config in config.endpoints:
        url = endpoint_config.get('url', '')
        name = endpoint_config.get('name', url)
        method = endpoint_config.get('method', 'GET')
        expected_status = endpoint_config.get('expected_status', 200)
        expected_text = endpoint_config.get('expected_text', None)
        timeout = endpoint_config.get('timeout', DEFAULT_TIMEOUT)

        if not url:
            continue

        success, status_code, response_time, error = check_http_endpoint(
            url, method, expected_status, expected_text, timeout, session
        )

        # Get previous status
        last_status = state.get_http_status(f"http:{url}")
        was_ok = last_status.get('ok', True) if last_status else True

        # Detect status changes
        if success and not was_ok:
            # Recovered
            event = MonitorEvent(
                source_type='http',
                source_name=name,
                title=f"Endpoint Recovered: {name}",
                body=f"Endpoint is back online. Status: {status_code}, Response time: {response_time:.2f}s",
                severity='info',
                url=url,
                metadata={
                    'id': f"recovery-{datetime.now().isoformat()}".encode(),
                    'status_code': status_code,
                    'response_time': response_time
                }
            )
            events.append(event)
            logger.info(f"HTTP endpoint '{name}' recovered")

        elif not success and was_ok:
            # New failure
            event = MonitorEvent(
                source_type='http',
                source_name=name,
                title=f"Endpoint Down: {name}",
                body=f"Endpoint check failed: {error}",
                severity='error',
                url=url,
                metadata={
                    'id': f"failure-{datetime.now().isoformat()}".encode(),
                    'status_code': status_code,
                    'error': error
                }
            )
            events.append(event)
            logger.warning(f"HTTP endpoint '{name}' down: {error}")

        # Update state
        state.set_http_status(f"http:{url}", {
            'ok': success,
            'status_code': status_code,
            'response_time': response_time,
            'error': error if not success else None,
            'last_check': datetime.now().isoformat()
        })

    return events


def test_http_endpoint(url: str, method: str = 'GET', expected_status: int = 200) -> Tuple[bool, str]:
    """
    Test an HTTP endpoint.

    Args:
        url: Endpoint URL.
        method: HTTP method.
        expected_status: Expected status code.

    Returns:
        Tuple of (success, message).
    """
    success, status_code, response_time, error = check_http_endpoint(
        url, method, expected_status
    )

    if success:
        return True, f"Endpoint OK - Status: {status_code}, Response time: {response_time:.2f}s"
    else:
        return False, f"Endpoint check failed: {error}"


# =============================================================================
# SMTP Receiver (Email monitoring via SMTP)
# =============================================================================

class _SmtpHandler:
    """aiosmtpd handler that processes incoming emails."""

    def __init__(
        self,
        callback: Callable[[EmailNotification], None],
        filters: List[str],
        use_auth: bool = False,
        username: str = "",
        password: str = "",
    ):
        self._callback = callback
        self._filters = filters
        self._use_auth = use_auth
        self._username = username
        self._password = password

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        try:
            msg = email_module.message_from_bytes(envelope.content)
            sender = get_sender_email(msg)

            # Apply filters
            if self._filters and not check_email_filter(sender, self._filters):
                logger.debug(f"SMTP receiver: email from {sender} filtered out")
                return '250 OK'

            subject = decode_email_subject(msg)
            body = extract_email_body(msg)

            notification = EmailNotification(
                email_id=hashlib.md5(envelope.content[:1024]).hexdigest().encode(),
                sender=sender,
                subject=subject,
                body=body,
            )

            logger.info(f"SMTP receiver: received email from {sender}: {subject[:60]}")
            self._callback(notification)

        except Exception as e:
            logger.error(f"SMTP receiver: error processing email: {e}")

        return '250 OK'


class _SmtpAuthenticator:
    """Simple authenticator for the SMTP receiver."""

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def __call__(self, server, session, envelope, mechanism, auth_data):
        try:
            if mechanism == 'LOGIN' or mechanism == 'PLAIN':
                login = auth_data.login.decode() if isinstance(auth_data.login, bytes) else auth_data.login
                pwd = auth_data.password.decode() if isinstance(auth_data.password, bytes) else auth_data.password
                if login == self._username and pwd == self._password:
                    return True
            return False
        except Exception:
            return False


class SmtpReceiver:
    """
    SMTP server that receives emails and dispatches notifications.

    Runs an aiosmtpd server on a configurable port. Other mail systems
    can forward/relay emails to this server, which then processes them
    through the notification pipeline.
    """

    def __init__(
        self,
        config: SmtpReceiverConfig,
        callback: Callable[[EmailNotification], None],
    ):
        self._config = config
        self._callback = callback
        self._controller = None
        self._thread = None
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> Tuple[bool, str]:
        """Start the SMTP receiver server."""
        if not AIOSMTPD_AVAILABLE:
            return False, "aiosmtpd not installed (pip install aiosmtpd)"

        if self._running:
            return False, "SMTP receiver already running"

        try:
            handler = _SmtpHandler(
                callback=self._callback,
                filters=self._config.filter_emails,
                use_auth=self._config.use_auth,
                username=self._config.username,
                password=self._config.password,
            )

            kwargs = {
                'handler': handler,
                'hostname': self._config.host,
                'port': self._config.port,
            }

            if self._config.use_auth and self._config.username:
                kwargs['authenticator'] = _SmtpAuthenticator(
                    self._config.username, self._config.password
                )
                kwargs['auth_require_tls'] = False

            self._controller = SmtpdController(**kwargs)
            self._controller.start()
            self._running = True

            addr = f"{self._config.host}:{self._config.port}"
            logger.info(f"SMTP receiver started on {addr}")
            return True, f"SMTP receiver listening on {addr}"

        except OSError as e:
            msg = f"Failed to start SMTP receiver: {e}"
            logger.error(msg)
            return False, msg
        except Exception as e:
            msg = f"Failed to start SMTP receiver: {e}"
            logger.error(msg)
            return False, msg

    def stop(self):
        """Stop the SMTP receiver server."""
        if self._controller and self._running:
            try:
                self._controller.stop()
            except Exception as e:
                logger.error(f"Error stopping SMTP receiver: {e}")
            self._running = False
            logger.info("SMTP receiver stopped")

    def __del__(self):
        self.stop()


def test_smtp_receiver_port(host: str, port: int) -> Tuple[bool, str]:
    """
    Test if an SMTP receiver can bind to the given host:port.

    Args:
        host: Hostname to bind to.
        port: Port to bind to.

    Returns:
        Tuple of (success, message).
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.bind((host, port))
        sock.close()
        return True, f"Port {port} is available"
    except OSError as e:
        return False, f"Cannot bind to {host}:{port}: {e}"
