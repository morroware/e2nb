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
    fetch_pop3_emails,
    delete_pop3_message,
    extract_email_body,
    decode_email_subject,
    get_sender_email,
    mark_as_read,
    check_email_filter,
    EmailNotification,
    NotificationDispatcher,
    NotificationResult,
    EmailConfig,
    SmtpReceiverConfig,
    SmtpReceiver,
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
        self.monitor_thread: Optional[threading.Thread] = None
        self.smtp_receiver: Optional[SmtpReceiver] = None
        self._config_lock = threading.Lock()  # Thread safety for config reload

    def load_configuration(self) -> bool:
        """
        Load and validate configuration.

        Validates the new configuration fully before swapping it in.
        If validation fails, the existing config/dispatcher remain active.

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

            return True
        except ConfigurationError as e:
            logging.error(f"Configuration error: {e}")
            return False
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            return False

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
            enabled_methods.append('Slack')
        if self.config.getboolean('Telegram', 'enabled', fallback=False):
            enabled_methods.append('Telegram')
        if self.config.getboolean('Discord', 'enabled', fallback=False):
            enabled_methods.append('Discord')
        if self.config.getboolean('CustomWebhook', 'enabled', fallback=False):
            enabled_methods.append('Webhook')
        if self.config.getboolean('SMTP', 'enabled', fallback=False):
            enabled_methods.append('Email (SMTP)')

        logging.info(f"Enabled notification methods: {', '.join(enabled_methods)}")

        # Start SMTP receiver if enabled
        smtp_recv_config = SmtpReceiverConfig.from_config(self.config)
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
        """Main monitoring loop."""
        # Initialize state for monitoring sources
        monitor_state = MonitorState()

        # Load monitoring source configs
        rss_config = RssFeedConfig.from_config(self.config)
        web_config = WebMonitorConfig.from_config(self.config)
        http_config = HttpEndpointConfig.from_config(self.config)

        # Log enabled sources
        sources = []
        if rss_config.enabled:
            sources.append(f"RSS ({len(rss_config.feeds)} feeds)")
        if web_config.enabled:
            sources.append(f"Web ({len(web_config.pages)} pages)")
        if http_config.enabled:
            sources.append(f"HTTP ({len(http_config.endpoints)} endpoints)")
        if sources:
            logging.info(f"Enabled monitoring sources: {', '.join(sources)}")

        while not self.stop_event.is_set():
            imap = None
            pop3 = None
            check_interval = DEFAULT_CHECK_INTERVAL  # Default in case of early exception
            try:
                # Get configuration values (thread-safe access)
                with self._config_lock:
                    config = self.config
                    dispatcher = self.dispatcher

                check_interval = safe_int(
                    config.get('Settings', 'check_interval', fallback=str(DEFAULT_CHECK_INTERVAL)),
                    DEFAULT_CHECK_INTERVAL,
                    min_val=10,
                    max_val=86400
                )
                filter_emails = [
                    f.strip().lower()
                    for f in config.get('Email', 'filter_emails', fallback='').split(',')
                    if f.strip()
                ]

                email_username = config.get('Email', 'username', fallback='')
                protocol = config.get('Email', 'protocol', fallback='imap').lower()

                # =====================================================
                # Check Email (IMAP or POP3)
                # =====================================================
                if email_username and protocol == 'imap':
                    imap = connect_to_imap(
                        config.get('Email', 'imap_server'),
                        safe_int(config.get('Email', 'imap_port'), DEFAULT_IMAP_PORT, min_val=1, max_val=65535),
                        email_username,
                        config.get('Email', 'password')
                    )

                    if imap:
                        unread_emails = fetch_unread_emails(imap)
                        email_count = len(unread_emails)

                        if email_count > 0:
                            logging.info(f"Found {email_count} unread email(s)")
                        else:
                            logging.debug("No unread emails found")

                        for email_id, msg in unread_emails:
                            if self.stop_event.is_set():
                                break
                            self._process_email(imap, email_id, msg, filter_emails)
                    else:
                        logging.warning("Failed to connect to IMAP server")

                elif email_username and protocol == 'pop3':
                    pop3 = connect_to_pop3(
                        config.get('Email', 'pop3_server'),
                        safe_int(config.get('Email', 'pop3_port'), DEFAULT_POP3_PORT, min_val=1, max_val=65535),
                        email_username,
                        config.get('Email', 'password')
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
                            if filter_emails and not check_email_filter(sender, filter_emails):
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

                # =====================================================
                # Check RSS Feeds
                # =====================================================
                if rss_config.enabled:
                    rss_events = check_rss_feeds(rss_config, monitor_state)
                    for event in rss_events:
                        if self.stop_event.is_set():
                            break
                        logging.info(f"[RSS] New item from '{event.source_name}': {event.title}")
                        notification = event.to_email_notification()
                        self._dispatch_notification(notification)

                # =====================================================
                # Check Web Pages
                # =====================================================
                if web_config.enabled:
                    web_events = check_web_pages(web_config, monitor_state)
                    for event in web_events:
                        if self.stop_event.is_set():
                            break
                        logging.info(f"[Web] {event.title}")
                        notification = event.to_email_notification()
                        self._dispatch_notification(notification)

                # =====================================================
                # Check HTTP Endpoints
                # =====================================================
                if http_config.enabled:
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

                # Wait for next check cycle
                if not self.stop_event.is_set():
                    logging.debug(f"Sleeping for {check_interval} seconds")
                    self.stop_event.wait(check_interval)

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
            if self.daemon.load_configuration():
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
        protocol = email_config.protocol
        if protocol == 'pop3':
            print(f"\nTesting POP3 connection...")
            pop3 = connect_to_pop3(
                email_config.pop3_server,
                email_config.pop3_port,
                email_config.username,
                email_config.password
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
                email_config.password
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
