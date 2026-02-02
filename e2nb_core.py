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

import configparser
import imaplib
import logging
import os
import re
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.header import decode_header
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
from html import escape as html_escape
from typing import Any, Callable, List, Optional, Tuple, Dict
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

# Version information
__version__ = "1.0.0"
__author__ = "Seth Morrow"

# Constants
CONFIG_FILE_PATH = 'config.ini'
LOG_FILE_PATH = 'email_monitor.log'
DEFAULT_CHECK_INTERVAL = 60
DEFAULT_MAX_SMS_LENGTH = 1600
DEFAULT_IMAP_PORT = 993
MAX_EMAILS_PER_CHECK = 5
DEFAULT_TIMEOUT = 30
MAX_RETRY_ATTEMPTS = 3
RETRY_BACKOFF_FACTOR = 0.5

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


class ConnectionError(E2NBError):
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

@dataclass
class EmailConfig:
    """Email server configuration."""
    imap_server: str = "imap.gmail.com"
    imap_port: int = DEFAULT_IMAP_PORT
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
            imap_server=section.get('imap_server', 'imap.gmail.com'),
            imap_port=int(section.get('imap_port', DEFAULT_IMAP_PORT)),
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
    # HTML escape for XML safety
    sanitized = html_escape(text)
    # Remove any potential SSML injection
    sanitized = re.sub(r'<[^>]+>', '', sanitized)
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
        'imap_server': 'imap.gmail.com',
        'imap_port': str(DEFAULT_IMAP_PORT),
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
                    import email as email_module
                    msg = email_module.message_from_bytes(response[1])
                    emails.append((email_id, msg))

        return emails
    except Exception as e:
        logger.error(f"Failed to fetch emails: {e}")
        return []


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
        data = {"content": f"**{subject}**\n{body}"}

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
