#!/usr/bin/env python3
"""
E2NB - Email to Notification Blaster (Headless Version)

A professional email monitoring daemon that forwards notifications through
multiple channels including SMS, Voice, WhatsApp, Slack, Telegram, Discord,
and custom webhooks. Designed for server deployment and automation.

Author: Seth Morrow
Date: Dec 2024
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import signal
import sys
import threading
import time
from typing import Optional

# Import shared core module
from e2nb_core import (
    __version__,
    load_config,
    setup_logging,
    connect_to_imap,
    connect_to_pop3,
    fetch_unread_emails,
    fetch_unread_emails_by_uid,
    fetch_pop3_emails,
    delete_pop3_message,
    extract_email_body,
    decode_email_subject,
    get_sender_email,
    mark_as_read,
    mark_as_read_by_uid,
    check_email_filter,
    refresh_oauth2_token,
    EmailNotification,
    NotificationDispatcher,
    NotificationResult,
    EmailConfig,
    SmtpReceiverConfig,
    SmtpReceiver,
    TeamsConfig,
    PushoverConfig,
    NtfyConfig,
    NotificationRulesConfig,
    RssFeedConfig,
    WebMonitorConfig,
    HttpEndpointConfig,
    MonitorState,
    check_rss_feeds,
    check_web_pages,
    check_http_endpoints,
    ConfigurationError,
    AIOSMTPD_AVAILABLE,
    DEFAULT_CHECK_INTERVAL,
    DEFAULT_IMAP_PORT,
    DEFAULT_POP3_PORT,
    CONFIG_FILE_PATH,
    LOG_FILE_PATH,
    safe_int,
    logger,
)


class EmailMonitorDaemon:
    """
    Headless email monitoring daemon.

    Monitors an email inbox for unread messages and dispatches notifications
    to configured channels. Designed for server deployment with proper
    signal handling and logging.
    """

    def __init__(self, config_file: str = CONFIG_FILE_PATH):
        """
        Initialize the daemon.

        Args:
            config_file: Path to the configuration file.
        """
        self.config_file = config_file
        self.config = None
        self.dispatcher: Optional[NotificationDispatcher] = None
        self.running = False
        self.stop_event = threading.Event()
        self.reload_event = threading.Event()  # Signals config reload to monitor loop
        self.monitor_thread: Optional[threading.Thread] = None
        self.smtp_receiver: Optional[SmtpReceiver] = None
        self._config_lock = threading.Lock()  # Thread safety for config reload
        self._smtp_receiver_config: Optional[SmtpReceiverConfig] = None  # Track SMTP config

    def load_configuration(self, is_reload: bool = False) -> bool:
        """
        Load and validate configuration.

        Validates the new configuration fully before swapping it in.
        If validation fails, the existing config/dispatcher remain active.

        Args:
            is_reload: Whether this is a configuration reload (triggers SMTP reconciliation).

        Returns:
            True if configuration is valid, False otherwise.
        """
        try:
            new_config = load_config(self.config_file)
            new_dispatcher = NotificationDispatcher(new_config)

            # Validate new configuration BEFORE swapping
            if not self._validate_configuration(new_config, new_dispatcher):
                # Validation failed - close the new dispatcher and keep existing config
                try:
                    new_dispatcher.close()
                except Exception:
                    pass
                logging.error("New configuration failed validation; keeping existing configuration.")
                return False

            # Validation passed - atomically swap configuration (thread-safe)
            old_dispatcher = self.dispatcher
            with self._config_lock:
                self.config = new_config
                self.dispatcher = new_dispatcher

            # Close old dispatcher to free resources
            if old_dispatcher is not None:
                try:
                    old_dispatcher.close()
                except Exception as e:
                    logging.debug(f"Error closing old dispatcher: {e}")

            # Reconcile SMTP receiver on reload
            if is_reload:
                self._reconcile_smtp_receiver(new_config)
                # Signal monitor loop to refresh source configs
                self.reload_event.set()

            return True
        except ConfigurationError as e:
            logging.error(f"Configuration error: {e}")
            return False
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            return False

    def _reconcile_smtp_receiver(self, new_config) -> None:
        """
        Reconcile SMTP receiver state after configuration reload.

        Starts, stops, or restarts the SMTP receiver based on config changes.
        """
        new_smtp_config = SmtpReceiverConfig.from_config(new_config)
        old_smtp_config = self._smtp_receiver_config

        # Check if SMTP receiver settings changed
        config_changed = (
            old_smtp_config is None or
            new_smtp_config.enabled != old_smtp_config.enabled or
            new_smtp_config.host != old_smtp_config.host or
            new_smtp_config.port != old_smtp_config.port or
            new_smtp_config.use_auth != old_smtp_config.use_auth or
            new_smtp_config.username != old_smtp_config.username or
            new_smtp_config.password != old_smtp_config.password
        )

        if not config_changed:
            return

        # Stop existing receiver if running
        if self.smtp_receiver and self.smtp_receiver.is_running:
            logging.info("Stopping SMTP receiver for reconfiguration...")
            self.smtp_receiver.stop()
            self.smtp_receiver = None

        # Start new receiver if enabled
        if new_smtp_config.enabled:
            if not AIOSMTPD_AVAILABLE:
                logging.error("SMTP receiver enabled but aiosmtpd not installed")
            else:
                self.smtp_receiver = SmtpReceiver(
                    config=new_smtp_config,
                    callback=self._on_smtp_received,
                )
                success, msg = self.smtp_receiver.start()
                if success:
                    logging.info(f"SMTP receiver restarted: {msg}")
                else:
                    logging.error(f"Failed to restart SMTP receiver: {msg}")

        self._smtp_receiver_config = new_smtp_config

    def _validate_configuration(self, config=None, dispatcher=None) -> bool:
        """
        Validate a configuration.

        Args:
            config: Config to validate (defaults to self.config for backward compat).
            dispatcher: Dispatcher to validate (defaults to self.dispatcher).

        Returns:
            True if configuration is valid, False otherwise.
        """
        config = config or self.config
        dispatcher = dispatcher or self.dispatcher

        # Check notification methods
        if not dispatcher.has_any_enabled():
            logging.error(
                "No notification methods enabled. "
                "Please enable at least one method in config.ini."
            )
            return False

        # Check email settings - email source is required unless SMTP receiver or
        # other monitoring sources (RSS, Web, HTTP) are enabled
        smtp_receiver_enabled = config.getboolean('SmtpReceiver', 'enabled', fallback=False)
        rss_enabled = config.getboolean('RSS', 'enabled', fallback=False)
        web_enabled = config.getboolean('WebMonitor', 'enabled', fallback=False)
        http_enabled = config.getboolean('HttpMonitor', 'enabled', fallback=False)
        has_other_sources = smtp_receiver_enabled or rss_enabled or web_enabled or http_enabled

        if not has_other_sources:
            email_section = config['Email'] if 'Email' in config else {}
            protocol = email_section.get('protocol', 'imap').lower()

            # Validate based on selected protocol
            if protocol == 'pop3':
                required_fields = ['pop3_server', 'pop3_port', 'username', 'password']
            else:
                required_fields = ['imap_server', 'imap_port', 'username', 'password']

            for field in required_fields:
                if not email_section.get(field):
                    logging.error(
                        f"Missing required email configuration: {field}. "
                        "Please check config.ini. "
                        "(Or enable SmtpReceiver/RSS/Web/HTTP monitoring as an alternative.)"
                    )
                    return False

        # Validate check interval
        raw_interval = config.get('Settings', 'check_interval', fallback=str(DEFAULT_CHECK_INTERVAL))
        check_interval = safe_int(raw_interval, DEFAULT_CHECK_INTERVAL, min_val=10, max_val=86400)
        try:
            if check_interval != int(raw_interval):
                logging.warning(f"Invalid check_interval '{raw_interval}' in config.ini, using {check_interval} seconds")
        except ValueError:
            logging.warning(f"Invalid check_interval '{raw_interval}' in config.ini, using {check_interval} seconds")

        return True

    def start(self) -> bool:
        """
        Start the monitoring daemon.

        Returns:
            True if started successfully, False otherwise.
        """
        if self.running:
            logging.warning("Daemon is already running")
            return False

        if not self.config:
            if not self.load_configuration():
                return False

        self.running = True
        self.stop_event.clear()

        logging.info(f"E2NB Daemon v{__version__} starting...")
        logging.info(f"Configuration loaded from {self.config_file}")

        # Log enabled notification methods
        enabled_methods = []
        if self.config.getboolean('Twilio', 'enabled', fallback=False):
            enabled_methods.append('SMS')
        if self.config.getboolean('Voice', 'enabled', fallback=False):
            enabled_methods.append('Voice')
        if self.config.getboolean('WhatsApp', 'enabled', fallback=False):
            enabled_methods.append('WhatsApp')
        if self.config.getboolean('Slack', 'enabled', fallback=False):
            slack_label = 'Slack'
            if self.config.get('Slack', 'dm_users', fallback=''):
                slack_label += ' (+DMs)'
            if self.config.get('Slack', 'mention_users', fallback=''):
                slack_label += ' (+mentions)'
            enabled_methods.append(slack_label)
        if self.config.getboolean('Telegram', 'enabled', fallback=False):
            enabled_methods.append('Telegram')
        if self.config.getboolean('Discord', 'enabled', fallback=False):
            enabled_methods.append('Discord')
        if self.config.getboolean('Teams', 'enabled', fallback=False):
            enabled_methods.append('Teams')
        if self.config.getboolean('Pushover', 'enabled', fallback=False):
            enabled_methods.append('Pushover')
        if self.config.getboolean('Ntfy', 'enabled', fallback=False):
            enabled_methods.append('Ntfy')
        if self.config.getboolean('CustomWebhook', 'enabled', fallback=False):
            enabled_methods.append('Webhook')
        if self.config.getboolean('SMTP', 'enabled', fallback=False):
            enabled_methods.append('Email (SMTP)')
        if self.config.getboolean('NotificationRules', 'enabled', fallback=False):
            enabled_methods.append('Routing Rules')

        logging.info(f"Enabled notification methods: {', '.join(enabled_methods)}")

        # Start SMTP receiver if enabled
        smtp_recv_config = SmtpReceiverConfig.from_config(self.config)
        self._smtp_receiver_config = smtp_recv_config  # Track initial config for reload reconciliation
        if smtp_recv_config.enabled:
            if not AIOSMTPD_AVAILABLE:
                logging.error("SMTP receiver enabled but aiosmtpd not installed (pip install aiosmtpd)")
                return False

            self.smtp_receiver = SmtpReceiver(
                config=smtp_recv_config,
                callback=self._on_smtp_received,
            )
            success, msg = self.smtp_receiver.start()
            if success:
                logging.info(msg)
            else:
                logging.error(msg)
                return False

        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="EmailMonitor",
            daemon=True
        )
        self.monitor_thread.start()

        return True

    def stop(self):
        """Stop the monitoring daemon gracefully."""
        if not self.running:
            logging.warning("Daemon is not running")
            return

        logging.info("Stopping E2NB daemon...")
        self.running = False
        self.stop_event.set()

        # Stop SMTP receiver
        if self.smtp_receiver and self.smtp_receiver.is_running:
            self.smtp_receiver.stop()

        # Wait for monitor thread to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=10)
            if self.monitor_thread.is_alive():
                logging.warning("Monitor thread did not stop cleanly")

        # Close dispatcher to free HTTP session resources
        if self.dispatcher is not None:
            try:
                self.dispatcher.close()
            except Exception as e:
                logging.debug(f"Error closing dispatcher: {e}")

        logging.info("E2NB daemon stopped")

    def _on_smtp_received(self, notification: EmailNotification):
        """Handle an email received via the SMTP receiver."""
        logging.info(f"[SMTP Receiver] Email from {notification.sender}: {notification.subject[:60]}")
        self._dispatch_notification(notification)

    def _monitor_loop(self):
        """Main monitoring loop with per-source interval tracking and UID-based IMAP."""
        # Initialize state for monitoring sources
        monitor_state = MonitorState()

        # Load monitoring source configs (will be refreshed on reload)
        rss_config = RssFeedConfig.from_config(self.config)
        web_config = WebMonitorConfig.from_config(self.config)
        http_config = HttpEndpointConfig.from_config(self.config)

        # Track per-source next-run timestamps for respecting individual check_intervals
        next_run_times = {
            'email': 0.0,  # Email uses global check_interval
            'rss': 0.0,
            'web': 0.0,
            'http': 0.0,
        }

        def _log_enabled_sources():
            """Log enabled monitoring sources."""
            sources = []
            if rss_config.enabled:
                sources.append(f"RSS ({len(rss_config.feeds)} feeds, {rss_config.check_interval}s)")
            if web_config.enabled:
                sources.append(f"Web ({len(web_config.pages)} pages, {web_config.check_interval}s)")
            if http_config.enabled:
                sources.append(f"HTTP ({len(http_config.endpoints)} endpoints, {http_config.check_interval}s)")
            if sources:
                logging.info(f"Enabled monitoring sources: {', '.join(sources)}")

        _log_enabled_sources()

        while not self.stop_event.is_set():
            imap = None
            pop3 = None
            check_interval = DEFAULT_CHECK_INTERVAL  # Default in case of early exception
            try:
                # Check for config reload signal
                if self.reload_event.is_set():
                    self.reload_event.clear()
                    # Refresh monitoring source configs
                    with self._config_lock:
                        rss_config = RssFeedConfig.from_config(self.config)
                        web_config = WebMonitorConfig.from_config(self.config)
                        http_config = HttpEndpointConfig.from_config(self.config)
                    logging.info("Monitoring source configs refreshed after reload")
                    _log_enabled_sources()

                # Get configuration values (thread-safe access)
                with self._config_lock:
                    config = self.config
                    dispatcher = self.dispatcher

                # Build EmailConfig for full TLS/OAuth2 support
                email_config = EmailConfig.from_config(config)

                check_interval = safe_int(
                    config.get('Settings', 'check_interval', fallback=str(DEFAULT_CHECK_INTERVAL)),
                    DEFAULT_CHECK_INTERVAL,
                    min_val=10,
                    max_val=86400
                )

                current_time = time.time()

                # =====================================================
                # Check Email (IMAP or POP3) with full TLS/OAuth2 support
                # =====================================================
                if current_time >= next_run_times['email']:
                    if email_config.username and email_config.protocol == 'imap':
                        # Get OAuth2 access token if enabled
                        oauth2_token = ""
                        if email_config.oauth2_enabled:
                            success, token, error = refresh_oauth2_token(
                                email_config.oauth2_client_id,
                                email_config.oauth2_client_secret,
                                email_config.oauth2_refresh_token,
                                email_config.oauth2_token_url or "https://oauth2.googleapis.com/token"
                            )
                            if success:
                                oauth2_token = token
                            else:
                                logging.error(f"OAuth2 token refresh failed: {error}")

                        imap = connect_to_imap(
                            email_config.imap_server,
                            email_config.imap_port,
                            email_config.username,
                            email_config.password,
                            timeout=email_config.connection_timeout,
                            tls_mode=email_config.tls_mode,
                            verify_ssl=email_config.verify_ssl,
                            ca_bundle=email_config.ca_bundle,
                            oauth2_access_token=oauth2_token
                        )

                        if imap:
                            # Use UID-based fetching for persistent tracking across restarts
                            imap_key_server = email_config.imap_server
                            imap_key_user = email_config.username
                            last_uid = monitor_state.get_imap_last_uid(imap_key_server, imap_key_user)

                            unread_emails, highest_uid = fetch_unread_emails_by_uid(
                                imap,
                                max_emails=email_config.max_emails_per_check,
                                last_seen_uid=last_uid
                            )
                            email_count = len(unread_emails)

                            if email_count > 0:
                                logging.info(f"Found {email_count} new unread email(s)")
                            else:
                                logging.debug("No new unread emails found")

                            for uid, msg in unread_emails:
                                if self.stop_event.is_set():
                                    break
                                success = self._process_email_by_uid(imap, uid, msg, email_config.filter_emails)
                                if success:
                                    # Update last seen UID only after successful dispatch
                                    monitor_state.set_imap_last_uid(imap_key_server, imap_key_user, uid)
                        else:
                            logging.warning("Failed to connect to IMAP server")

                    elif email_config.username and email_config.protocol == 'pop3':
                        # Get OAuth2 access token if enabled
                        oauth2_token = ""
                        if email_config.oauth2_enabled:
                            success, token, error = refresh_oauth2_token(
                                email_config.oauth2_client_id,
                                email_config.oauth2_client_secret,
                                email_config.oauth2_refresh_token,
                                email_config.oauth2_token_url or "https://oauth2.googleapis.com/token"
                            )
                            if success:
                                oauth2_token = token
                            else:
                                logging.error(f"OAuth2 token refresh failed: {error}")

                        pop3 = connect_to_pop3(
                            email_config.pop3_server,
                            email_config.pop3_port,
                            email_config.username,
                            email_config.password,
                            timeout=email_config.connection_timeout,
                            tls_mode=email_config.tls_mode,
                            verify_ssl=email_config.verify_ssl,
                            ca_bundle=email_config.ca_bundle,
                            oauth2_access_token=oauth2_token
                        )

                        if pop3:
                            pop3_emails = fetch_pop3_emails(pop3)
                            email_count = len(pop3_emails)

                            if email_count > 0:
                                logging.info(f"Found {email_count} email(s) via POP3")

                            for msg_num, msg in pop3_emails:
                                if self.stop_event.is_set():
                                    break
                                sender = get_sender_email(msg)
                                if email_config.filter_emails and not check_email_filter(sender, email_config.filter_emails):
                                    continue
                                subject = decode_email_subject(msg)
                                body = extract_email_body(msg)

                                # Create hash to track this message and avoid duplicates
                                msg_hash = hashlib.md5(
                                    f"{sender}{subject}{body[:500]}".encode()
                                ).hexdigest()

                                # Skip if already processed
                                if monitor_state.is_pop3_message_seen(msg_hash):
                                    continue

                                notification = EmailNotification(
                                    email_id=str(msg_num).encode(),
                                    sender=sender,
                                    subject=subject,
                                    body=body
                                )

                                # Dispatch and only delete/mark seen on success
                                success = self._dispatch_notification(notification)
                                if success:
                                    monitor_state.mark_pop3_message_seen(msg_hash)
                                    delete_pop3_message(pop3, msg_num)

                            # Cleanup old tracked messages
                            monitor_state.cleanup_old_pop3_messages()
                        else:
                            logging.warning("Failed to connect to POP3 server")

                    next_run_times['email'] = current_time + check_interval

                # =====================================================
                # Check RSS Feeds (respecting per-source check_interval)
                # =====================================================
                if rss_config.enabled and current_time >= next_run_times['rss']:
                    rss_events = check_rss_feeds(rss_config, monitor_state)
                    for event in rss_events:
                        if self.stop_event.is_set():
                            break
                        logging.info(f"[RSS] New item from '{event.source_name}': {event.title}")
                        notification = event.to_email_notification()
                        self._dispatch_notification(notification)
                    next_run_times['rss'] = current_time + rss_config.check_interval

                # =====================================================
                # Check Web Pages (respecting per-source check_interval)
                # =====================================================
                if web_config.enabled and current_time >= next_run_times['web']:
                    web_events = check_web_pages(web_config, monitor_state)
                    for event in web_events:
                        if self.stop_event.is_set():
                            break
                        logging.info(f"[Web] {event.title}")
                        notification = event.to_email_notification()
                        self._dispatch_notification(notification)
                    next_run_times['web'] = current_time + web_config.check_interval

                # =====================================================
                # Check HTTP Endpoints (respecting per-source check_interval)
                # =====================================================
                if http_config.enabled and current_time >= next_run_times['http']:
                    http_events = check_http_endpoints(http_config, monitor_state)
                    for event in http_events:
                        if self.stop_event.is_set():
                            break
                        if event.severity == 'error':
                            logging.warning(f"[HTTP] {event.title}")
                        else:
                            logging.info(f"[HTTP] {event.title}")
                        notification = event.to_email_notification()
                        self._dispatch_notification(notification)
                    next_run_times['http'] = current_time + http_config.check_interval

                # Save monitoring state
                monitor_state.save()

            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}", exc_info=True)
            finally:
                # Clean up connections
                if imap:
                    try:
                        imap.logout()
                        logging.debug("Logged out from IMAP server")
                    except Exception as e:
                        logging.debug(f"Error during IMAP logout: {e}")
                if pop3:
                    try:
                        pop3.quit()
                        logging.debug("Disconnected from POP3 server")
                    except Exception as e:
                        logging.debug(f"Error during POP3 quit: {e}")

                # Calculate sleep time as minimum of all pending intervals
                if not self.stop_event.is_set():
                    current_time = time.time()
                    pending_intervals = []
                    if email_config.username:
                        pending_intervals.append(max(0, next_run_times['email'] - current_time))
                    if rss_config.enabled:
                        pending_intervals.append(max(0, next_run_times['rss'] - current_time))
                    if web_config.enabled:
                        pending_intervals.append(max(0, next_run_times['web'] - current_time))
                    if http_config.enabled:
                        pending_intervals.append(max(0, next_run_times['http'] - current_time))

                    # Sleep until the next source needs to run (minimum 1 second)
                    sleep_time = max(1, min(pending_intervals)) if pending_intervals else check_interval
                    logging.debug(f"Sleeping for {sleep_time:.1f} seconds until next check")
                    self.stop_event.wait(sleep_time)

    def _process_email_by_uid(self, imap, uid: int, msg, filter_emails: list) -> bool:
        """
        Process a single email using UID.

        Args:
            imap: IMAP connection.
            uid: Email UID.
            msg: Email message object.
            filter_emails: List of email filter patterns.

        Returns:
            True if notification was sent successfully, False otherwise.
        """
        # Extract sender
        sender_email = get_sender_email(msg)

        # Apply filters
        if filter_emails and not check_email_filter(sender_email, filter_emails):
            logging.info(f"Email from {sender_email} does not match filters. Skipping.")
            return False

        # Extract email content
        subject = decode_email_subject(msg)
        body = extract_email_body(msg)

        logging.info(f"Processing email UID {uid} from {sender_email}: {subject[:60]}...")

        # Create notification
        notification = EmailNotification(
            email_id=str(uid).encode(),
            sender=sender_email,
            subject=subject,
            body=body
        )

        # Dispatch notifications
        results = self.dispatcher.dispatch(
            notification,
            callback=self._on_notification_result
        )

        # Check results
        success_count = sum(1 for r in results if r.success)
        failure_count = len(results) - success_count

        if success_count > 0:
            logging.info(
                f"Notifications sent: {success_count} success, {failure_count} failed"
            )
            # Mark email as read using UID
            if mark_as_read_by_uid(imap, uid):
                logging.info(f"Marked email UID {uid} as read")
            else:
                logging.warning(f"Failed to mark email UID {uid} as read")
            return True
        else:
            logging.warning(
                f"No notifications were sent successfully for email UID {uid}"
            )
            return False

    def _dispatch_notification(self, notification: EmailNotification) -> bool:
        """
        Dispatch a notification to all enabled channels.

        Args:
            notification: The notification to dispatch.

        Returns:
            True if at least one notification was sent successfully.
        """
        results = self.dispatcher.dispatch(notification, callback=self._on_notification_result)
        success_count = sum(1 for r in results if r.success)
        failure_count = len(results) - success_count
        if results:
            logging.info(f"Notifications sent: {success_count} success, {failure_count} failed")
        return success_count > 0

    def _process_email(self, imap, email_id: bytes, msg, filter_emails: list):
        """
        Process a single email.

        Args:
            imap: IMAP connection.
            email_id: Email ID.
            msg: Email message object.
            filter_emails: List of email filter patterns.
        """
        # Extract sender
        sender_email = get_sender_email(msg)

        # Apply filters
        if filter_emails and not check_email_filter(sender_email, filter_emails):
            logging.info(f"Email from {sender_email} does not match filters. Skipping.")
            return

        # Extract email content
        subject = decode_email_subject(msg)
        body = extract_email_body(msg)

        logging.info(f"Processing email from {sender_email}: {subject[:60]}...")

        # Create notification
        notification = EmailNotification(
            email_id=email_id,
            sender=sender_email,
            subject=subject,
            body=body
        )

        # Dispatch notifications
        results = self.dispatcher.dispatch(
            notification,
            callback=self._on_notification_result
        )

        # Check results
        success_count = sum(1 for r in results if r.success)
        failure_count = len(results) - success_count

        if success_count > 0:
            logging.info(
                f"Notifications sent: {success_count} success, {failure_count} failed"
            )
            # Mark email as read
            if mark_as_read(imap, email_id):
                logging.info(f"Marked email {email_id.decode()} as read")
            else:
                logging.warning(f"Failed to mark email {email_id.decode()} as read")
        else:
            logging.warning(
                f"No notifications were sent successfully for email {email_id.decode()}"
            )

    def _on_notification_result(self, result: NotificationResult):
        """
        Callback for notification results.

        Args:
            result: The notification result.
        """
        if result.success:
            logging.info(f"[{result.service}] Notification sent: {result.message}")
        else:
            logging.error(f"[{result.service}] Notification failed: {result.message}")


class SignalHandler:
    """Handles Unix signals for graceful shutdown."""

    def __init__(self, daemon: EmailMonitorDaemon):
        self.daemon = daemon
        self._setup_signals()

    def _setup_signals(self):
        """Set up signal handlers."""
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        # Handle SIGHUP for config reload (Unix only)
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_reload)

    def _handle_signal(self, signum: int, frame):
        """
        Handle shutdown signals.

        Args:
            signum: Signal number.
            frame: Current stack frame.
        """
        signal_name = signal.Signals(signum).name
        logging.info(f"Received {signal_name} signal. Initiating shutdown...")
        self.daemon.stop()
        sys.exit(0)

    def _handle_reload(self, signum: int, frame):
        """
        Handle configuration reload signal.

        Args:
            signum: Signal number.
            frame: Current stack frame.
        """
        logging.info("Received SIGHUP. Reloading configuration...")
        try:
            if self.daemon.load_configuration(is_reload=True):
                logging.info("Configuration reloaded successfully")
            else:
                logging.error("Failed to reload configuration")
        except Exception as e:
            logging.error(f"Error reloading configuration: {e}")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description=f"E2NB Email Monitor Daemon v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Start with default config
  %(prog)s -c /etc/e2nb/config.ini  Use custom config file
  %(prog)s -l /var/log/e2nb.log     Use custom log file
  %(prog)s -v                       Enable verbose logging
  %(prog)s --test                   Test configuration and exit

Signals:
  SIGINT/SIGTERM  - Graceful shutdown
  SIGHUP          - Reload configuration

For more information: https://github.com/morroware/e2nb
        """
    )

    parser.add_argument(
        '-c', '--config',
        default=CONFIG_FILE_PATH,
        help=f'Path to configuration file (default: {CONFIG_FILE_PATH})'
    )

    parser.add_argument(
        '-l', '--log-file',
        default=LOG_FILE_PATH,
        help=f'Path to log file (default: {LOG_FILE_PATH})'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose (debug) logging'
    )

    parser.add_argument(
        '--no-console',
        action='store_true',
        help='Disable console logging (log to file only)'
    )

    parser.add_argument(
        '--test',
        action='store_true',
        help='Test configuration and exit'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'E2NB v{__version__}'
    )

    return parser.parse_args()


def test_configuration(config_file: str) -> bool:
    """
    Test configuration validity.

    Args:
        config_file: Path to configuration file.

    Returns:
        True if configuration is valid, False otherwise.
    """
    def _cleanup(daemon):
        """Clean up dispatcher resources."""
        if daemon.dispatcher is not None:
            daemon.dispatcher.close()

    print(f"Testing configuration from: {config_file}")
    print("-" * 50)

    daemon = EmailMonitorDaemon(config_file)

    if not daemon.load_configuration():
        print("\nConfiguration test FAILED")
        _cleanup(daemon)
        return False

    # Test IMAP connection (only if SMTP receiver is not the sole email source)
    email_config = EmailConfig.from_config(daemon.config)
    smtp_recv_enabled = daemon.config.getboolean('SmtpReceiver', 'enabled', fallback=False)

    if email_config.username:
        # Get OAuth2 token if enabled
        oauth2_token = ""
        if email_config.oauth2_enabled:
            print("\nRefreshing OAuth2 token...")
            success, token, error = refresh_oauth2_token(
                email_config.oauth2_client_id,
                email_config.oauth2_client_secret,
                email_config.oauth2_refresh_token,
                email_config.oauth2_token_url or "https://oauth2.googleapis.com/token"
            )
            if success:
                oauth2_token = token
                print("  OAuth2 token refreshed successfully")
            else:
                print(f"  WARNING: OAuth2 token refresh failed: {error}")

        protocol = email_config.protocol
        if protocol == 'pop3':
            print(f"\nTesting POP3 connection...")
            pop3 = connect_to_pop3(
                email_config.pop3_server,
                email_config.pop3_port,
                email_config.username,
                email_config.password,
                timeout=email_config.connection_timeout,
                tls_mode=email_config.tls_mode,
                verify_ssl=email_config.verify_ssl,
                ca_bundle=email_config.ca_bundle,
                oauth2_access_token=oauth2_token
            )
            if pop3:
                print(f"  Connected to {email_config.pop3_server}:{email_config.pop3_port}")
                pop3.quit()
            else:
                print(f"  FAILED to connect to {email_config.pop3_server}:{email_config.pop3_port}")
                if not smtp_recv_enabled:
                    print("\nConfiguration test FAILED")
                    _cleanup(daemon)
                    return False
                else:
                    print("  (SMTP receiver is enabled as alternative)")
        else:
            print("\nTesting IMAP connection...")
            imap = connect_to_imap(
                email_config.imap_server,
                email_config.imap_port,
                email_config.username,
                email_config.password,
                timeout=email_config.connection_timeout,
                tls_mode=email_config.tls_mode,
                verify_ssl=email_config.verify_ssl,
                ca_bundle=email_config.ca_bundle,
                oauth2_access_token=oauth2_token
            )
            if imap:
                print(f"  Connected to {email_config.imap_server}:{email_config.imap_port}")
                imap.logout()
            else:
                print(f"  FAILED to connect to {email_config.imap_server}:{email_config.imap_port}")
                if not smtp_recv_enabled:
                    print("\nConfiguration test FAILED")
                    _cleanup(daemon)
                    return False
                else:
                    print("  (SMTP receiver is enabled as alternative)")
    elif not smtp_recv_enabled:
        print("\nNo email source configured (IMAP or SMTP Receiver)")
        print("\nConfiguration test FAILED")
        _cleanup(daemon)
        return False

    # Show enabled notifications
    print("\nEnabled notification methods:")
    methods = [
        ('Twilio SMS', 'Twilio', 'enabled'),
        ('Twilio Voice', 'Voice', 'enabled'),
        ('Twilio WhatsApp', 'WhatsApp', 'enabled'),
        ('Slack', 'Slack', 'enabled'),
        ('Telegram', 'Telegram', 'enabled'),
        ('Discord', 'Discord', 'enabled'),
        ('Microsoft Teams', 'Teams', 'enabled'),
        ('Pushover', 'Pushover', 'enabled'),
        ('Ntfy', 'Ntfy', 'enabled'),
        ('Custom Webhook', 'CustomWebhook', 'enabled'),
        ('Email (SMTP)', 'SMTP', 'enabled'),
    ]

    for name, section, key in methods:
        enabled = daemon.config.getboolean(section, key, fallback=False)
        status = "ENABLED" if enabled else "disabled"
        print(f"  {name}: {status}")

    # SMTP Receiver
    smtp_recv_enabled = daemon.config.getboolean('SmtpReceiver', 'enabled', fallback=False)
    print(f"\nSMTP Receiver: {'ENABLED' if smtp_recv_enabled else 'disabled'}")
    if smtp_recv_enabled:
        host = daemon.config.get('SmtpReceiver', 'host', fallback='0.0.0.0')
        port = daemon.config.get('SmtpReceiver', 'port', fallback='2525')
        print(f"  Listening on {host}:{port}")

    # Notification rules
    rules_enabled = daemon.config.getboolean('NotificationRules', 'enabled', fallback=False)
    print(f"\nNotification Rules: {'ENABLED' if rules_enabled else 'disabled'}")
    if rules_enabled:
        rules_config = NotificationRulesConfig.from_config(daemon.config)
        active_rules = [r for r in rules_config.rules if r.enabled]
        print(f"  Active rules: {len(active_rules)}")
        for rule in active_rules:
            print(f"    - {rule.name}")

    # Show enabled monitoring sources
    print("\nEnabled monitoring sources:")
    sources = [
        ('RSS Feeds', 'RSS', 'enabled'),
        ('Web Pages', 'WebMonitor', 'enabled'),
        ('HTTP Endpoints', 'HttpMonitor', 'enabled'),
    ]

    for name, section, key in sources:
        enabled = daemon.config.getboolean(section, key, fallback=False)
        status = "ENABLED" if enabled else "disabled"
        print(f"  {name}: {status}")

    print("\n" + "-" * 50)
    print("Configuration test PASSED")

    _cleanup(daemon)
    return True


def main():
    """Main entry point."""
    args = parse_arguments()

    # Handle test mode
    if args.test:
        success = test_configuration(args.config)
        sys.exit(0 if success else 1)

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(
        log_file=args.log_file,
        level=log_level,
        console=not args.no_console
    )

    logging.info("=" * 60)
    logging.info(f"E2NB Email Monitor Daemon v{__version__}")
    logging.info("=" * 60)

    # Create and start daemon
    daemon = EmailMonitorDaemon(args.config)

    # Setup signal handling
    signal_handler = SignalHandler(daemon)

    # Start the daemon
    if not daemon.start():
        logging.error("Failed to start daemon. Exiting.")
        sys.exit(1)

    # Keep main thread alive
    try:
        while daemon.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received")
        daemon.stop()
        sys.exit(0)


if __name__ == '__main__':
    main()
