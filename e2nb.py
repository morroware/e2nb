#!/usr/bin/env python3
"""
E2NB - Email to Notification Blaster (GUI Version)

A professional email monitoring application that forwards notifications through
multiple channels including SMS, Voice, WhatsApp, Slack, Telegram, Discord,
and custom webhooks.

Author: Seth Morrow
Date: Dec 2024
Version: 1.0.0
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import tkinter.font as tkFont
from datetime import datetime
from typing import Optional, Callable, Any

# Import shared core module
from e2nb_core import (
    __version__,
    load_config,
    save_config,
    connect_to_imap,
    fetch_unread_emails,
    extract_email_body,
    decode_email_subject,
    get_sender_email,
    mark_as_read,
    check_email_filter,
    EmailNotification,
    NotificationDispatcher,
    NotificationResult,
    EmailConfig,
    test_imap_connection,
    DEFAULT_CHECK_INTERVAL,
    DEFAULT_MAX_SMS_LENGTH,
    DEFAULT_IMAP_PORT,
)


# =============================================================================
# Color Scheme and Styling
# =============================================================================

class Theme:
    """Application color theme."""
    # Primary colors
    PRIMARY = "#2563eb"
    PRIMARY_HOVER = "#1d4ed8"
    PRIMARY_LIGHT = "#dbeafe"

    # Status colors
    SUCCESS = "#059669"
    SUCCESS_LIGHT = "#d1fae5"
    WARNING = "#d97706"
    WARNING_LIGHT = "#fef3c7"
    ERROR = "#dc2626"
    ERROR_LIGHT = "#fee2e2"

    # Neutral colors
    BG_PRIMARY = "#f8fafc"
    BG_SECONDARY = "#ffffff"
    BG_TERTIARY = "#f1f5f9"
    TEXT_PRIMARY = "#1e293b"
    TEXT_SECONDARY = "#64748b"
    TEXT_MUTED = "#94a3b8"
    BORDER = "#e2e8f0"

    # Log colors
    LOG_INFO = "#0369a1"
    LOG_WARNING = "#b45309"
    LOG_ERROR = "#b91c1c"
    LOG_SUCCESS = "#047857"


class StyleManager:
    """Manages application styling."""

    @staticmethod
    def configure_styles():
        """Configure ttk styles for the application."""
        style = ttk.Style()

        # Try to use a modern theme
        available_themes = style.theme_names()
        if 'clam' in available_themes:
            style.theme_use('clam')
        elif 'alt' in available_themes:
            style.theme_use('alt')

        # Configure frame styles
        style.configure(
            "Card.TFrame",
            background=Theme.BG_SECONDARY,
            relief="flat"
        )

        style.configure(
            "TFrame",
            background=Theme.BG_PRIMARY
        )

        # Configure label styles
        style.configure(
            "TLabel",
            background=Theme.BG_PRIMARY,
            foreground=Theme.TEXT_PRIMARY,
            font=('Segoe UI', 10)
        )

        style.configure(
            "Header.TLabel",
            background=Theme.BG_PRIMARY,
            foreground=Theme.TEXT_PRIMARY,
            font=('Segoe UI', 12, 'bold')
        )

        style.configure(
            "Subheader.TLabel",
            background=Theme.BG_PRIMARY,
            foreground=Theme.TEXT_SECONDARY,
            font=('Segoe UI', 9)
        )

        # Configure entry styles
        style.configure(
            "TEntry",
            fieldbackground=Theme.BG_SECONDARY,
            foreground=Theme.TEXT_PRIMARY,
            borderwidth=1,
            relief="solid"
        )

        # Configure button styles
        style.configure(
            "TButton",
            background=Theme.BG_TERTIARY,
            foreground=Theme.TEXT_PRIMARY,
            font=('Segoe UI', 10),
            padding=(12, 6)
        )

        style.configure(
            "Primary.TButton",
            background=Theme.PRIMARY,
            foreground="white",
            font=('Segoe UI', 10, 'bold'),
            padding=(16, 8)
        )

        style.map(
            "Primary.TButton",
            background=[('active', Theme.PRIMARY_HOVER)]
        )

        style.configure(
            "Success.TButton",
            background=Theme.SUCCESS,
            foreground="white",
            font=('Segoe UI', 10, 'bold'),
            padding=(16, 8)
        )

        style.configure(
            "Danger.TButton",
            background=Theme.ERROR,
            foreground="white",
            font=('Segoe UI', 10),
            padding=(16, 8)
        )

        # Configure notebook styles
        style.configure(
            "TNotebook",
            background=Theme.BG_PRIMARY,
            borderwidth=0
        )

        style.configure(
            "TNotebook.Tab",
            background=Theme.BG_TERTIARY,
            foreground=Theme.TEXT_PRIMARY,
            padding=(16, 8),
            font=('Segoe UI', 10)
        )

        style.map(
            "TNotebook.Tab",
            background=[('selected', Theme.BG_SECONDARY)],
            foreground=[('selected', Theme.PRIMARY)]
        )

        # Configure checkbutton styles
        style.configure(
            "TCheckbutton",
            background=Theme.BG_PRIMARY,
            foreground=Theme.TEXT_PRIMARY,
            font=('Segoe UI', 10)
        )

        # Configure labelframe styles
        style.configure(
            "TLabelframe",
            background=Theme.BG_PRIMARY,
            foreground=Theme.TEXT_PRIMARY
        )

        style.configure(
            "TLabelframe.Label",
            background=Theme.BG_PRIMARY,
            foreground=Theme.TEXT_PRIMARY,
            font=('Segoe UI', 10, 'bold')
        )

        # Status indicator styles
        style.configure(
            "StatusActive.TLabel",
            background=Theme.SUCCESS_LIGHT,
            foreground=Theme.SUCCESS,
            font=('Segoe UI', 10, 'bold'),
            padding=(8, 4)
        )

        style.configure(
            "StatusInactive.TLabel",
            background=Theme.BG_TERTIARY,
            foreground=Theme.TEXT_MUTED,
            font=('Segoe UI', 10),
            padding=(8, 4)
        )


# =============================================================================
# Custom Widgets
# =============================================================================

class StatusIndicator(ttk.Frame):
    """A visual status indicator widget."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.configure(style="Card.TFrame")

        self.canvas = tk.Canvas(
            self,
            width=12,
            height=12,
            bg=Theme.BG_SECONDARY,
            highlightthickness=0
        )
        self.canvas.pack(side="left", padx=(0, 8))

        self.label = ttk.Label(self, text="Inactive", style="Subheader.TLabel")
        self.label.pack(side="left")

        self._indicator = self.canvas.create_oval(2, 2, 10, 10, fill=Theme.TEXT_MUTED, outline="")
        self._active = False

    def set_active(self, active: bool, text: str = None):
        """Set the indicator state."""
        self._active = active
        color = Theme.SUCCESS if active else Theme.TEXT_MUTED
        self.canvas.itemconfig(self._indicator, fill=color)

        if text:
            self.label.configure(text=text)
        else:
            self.label.configure(text="Active" if active else "Inactive")


class FormField(ttk.Frame):
    """A labeled form field with optional help text."""

    def __init__(
        self,
        parent,
        label: str,
        help_text: str = "",
        show: str = "",
        width: int = 40,
        **kwargs
    ):
        super().__init__(parent, **kwargs)

        # Label
        self.label = ttk.Label(self, text=label, style="TLabel")
        self.label.pack(anchor="w")

        # Entry
        self.entry = ttk.Entry(self, width=width, show=show)
        self.entry.pack(fill="x", pady=(4, 0))

        # Help text
        if help_text:
            self.help_label = ttk.Label(self, text=help_text, style="Subheader.TLabel")
            self.help_label.pack(anchor="w", pady=(2, 0))

    def get(self) -> str:
        """Get the entry value."""
        return self.entry.get()

    def set(self, value: str):
        """Set the entry value."""
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)


class ToggleCard(ttk.Frame):
    """A card-style toggle for notification methods."""

    def __init__(
        self,
        parent,
        title: str,
        description: str,
        variable: tk.BooleanVar,
        **kwargs
    ):
        super().__init__(parent, **kwargs)
        self.configure(style="Card.TFrame", padding=12)

        # Title and checkbox
        header = ttk.Frame(self)
        header.pack(fill="x")

        self.checkbox = ttk.Checkbutton(
            header,
            text=title,
            variable=variable,
            style="TCheckbutton"
        )
        self.checkbox.pack(side="left")

        # Description
        desc_label = ttk.Label(
            self,
            text=description,
            style="Subheader.TLabel",
            wraplength=200
        )
        desc_label.pack(anchor="w", pady=(4, 0))


# =============================================================================
# Main Application
# =============================================================================

class EmailMonitorApp:
    """Main application class for E2NB GUI."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"E2NB - Email to Notification Blaster v{__version__}")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Set window background
        self.root.configure(bg=Theme.BG_PRIMARY)

        # Load configuration
        self.config = load_config()

        # State variables
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.log_queue: queue.Queue = queue.Queue()

        # Initialize notification variables
        self._init_notification_vars()

        # Apply styling
        StyleManager.configure_styles()

        # Create UI
        self._create_menu()
        self._create_header()
        self._create_notebook()
        self._create_status_bar()

        # Start log processing
        self._process_log_queue()

        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _init_notification_vars(self):
        """Initialize boolean variables for notification toggles."""
        self.twilio_sms_var = tk.BooleanVar(
            value=self.config.getboolean('Twilio', 'enabled', fallback=False)
        )
        self.voice_var = tk.BooleanVar(
            value=self.config.getboolean('Voice', 'enabled', fallback=False)
        )
        self.whatsapp_var = tk.BooleanVar(
            value=self.config.getboolean('WhatsApp', 'enabled', fallback=False)
        )
        self.slack_var = tk.BooleanVar(
            value=self.config.getboolean('Slack', 'enabled', fallback=False)
        )
        self.telegram_var = tk.BooleanVar(
            value=self.config.getboolean('Telegram', 'enabled', fallback=False)
        )
        self.discord_var = tk.BooleanVar(
            value=self.config.getboolean('Discord', 'enabled', fallback=False)
        )
        self.custom_webhook_var = tk.BooleanVar(
            value=self.config.getboolean('CustomWebhook', 'enabled', fallback=False)
        )

    def _create_menu(self):
        """Create the application menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Settings", command=self._save_settings)
        file_menu.add_command(label="Reload Settings", command=self._reload_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Test Email Connection", command=self._test_email_connection)
        tools_menu.add_command(label="Clear Logs", command=self._clear_logs)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=False)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._show_docs)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self._show_about)

    def _create_header(self):
        """Create the application header with status and controls."""
        header_frame = ttk.Frame(self.root, padding="16 16 16 8")
        header_frame.pack(fill="x")

        # Left side - Title and status
        left_frame = ttk.Frame(header_frame)
        left_frame.pack(side="left", fill="y")

        title_label = ttk.Label(
            left_frame,
            text="Email Monitor",
            style="Header.TLabel"
        )
        title_label.pack(anchor="w")

        self.status_indicator = StatusIndicator(left_frame)
        self.status_indicator.pack(anchor="w", pady=(4, 0))

        # Right side - Control buttons
        right_frame = ttk.Frame(header_frame)
        right_frame.pack(side="right")

        self.start_button = ttk.Button(
            right_frame,
            text="Start Monitoring",
            command=self._start_monitoring,
            style="Success.TButton"
        )
        self.start_button.pack(side="left", padx=(0, 8))

        self.stop_button = ttk.Button(
            right_frame,
            text="Stop Monitoring",
            command=self._stop_monitoring,
            style="Danger.TButton",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=(0, 8))

        self.save_button = ttk.Button(
            right_frame,
            text="Save Settings",
            command=self._save_settings,
            style="Primary.TButton"
        )
        self.save_button.pack(side="left")

    def _create_notebook(self):
        """Create the main tabbed interface."""
        self.notebook = ttk.Notebook(self.root, padding=8)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=8)

        # Create tabs
        self._create_email_tab()
        self._create_settings_tab()
        self._create_notifications_tab()
        self._create_twilio_sms_tab()
        self._create_twilio_voice_tab()
        self._create_twilio_whatsapp_tab()
        self._create_slack_tab()
        self._create_telegram_tab()
        self._create_discord_tab()
        self._create_webhook_tab()
        self._create_logs_tab()

    def _create_email_tab(self):
        """Create the Email Settings tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Email Settings")

        # IMAP Server settings
        server_frame = ttk.LabelFrame(frame, text="IMAP Server Configuration", padding=12)
        server_frame.pack(fill="x", pady=(0, 16))

        grid_frame = ttk.Frame(server_frame)
        grid_frame.pack(fill="x")

        # Server
        ttk.Label(grid_frame, text="IMAP Server:").grid(row=0, column=0, sticky="w", pady=4)
        self.imap_server_entry = ttk.Entry(grid_frame, width=40)
        self.imap_server_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.imap_server_entry.insert(0, self.config.get('Email', 'imap_server', fallback='imap.gmail.com'))

        # Port
        ttk.Label(grid_frame, text="Port:").grid(row=1, column=0, sticky="w", pady=4)
        self.imap_port_entry = ttk.Entry(grid_frame, width=10)
        self.imap_port_entry.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=4)
        self.imap_port_entry.insert(0, self.config.get('Email', 'imap_port', fallback=str(DEFAULT_IMAP_PORT)))

        # Test connection button
        test_btn = ttk.Button(grid_frame, text="Test Connection", command=self._test_email_connection)
        test_btn.grid(row=1, column=2, padx=(16, 0), pady=4)

        grid_frame.columnconfigure(1, weight=1)

        # Credentials
        creds_frame = ttk.LabelFrame(frame, text="Email Credentials", padding=12)
        creds_frame.pack(fill="x", pady=(0, 16))

        creds_grid = ttk.Frame(creds_frame)
        creds_grid.pack(fill="x")

        ttk.Label(creds_grid, text="Username (Email):").grid(row=0, column=0, sticky="w", pady=4)
        self.username_entry = ttk.Entry(creds_grid, width=40)
        self.username_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.username_entry.insert(0, self.config.get('Email', 'username', fallback=''))

        ttk.Label(creds_grid, text="Password:").grid(row=1, column=0, sticky="w", pady=4)
        self.password_entry = ttk.Entry(creds_grid, width=40, show="*")
        self.password_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.password_entry.insert(0, self.config.get('Email', 'password', fallback=''))

        # Show/hide password toggle
        self.show_password_var = tk.BooleanVar(value=False)
        show_pass_cb = ttk.Checkbutton(
            creds_grid,
            text="Show",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        )
        show_pass_cb.grid(row=1, column=2, padx=(8, 0), pady=4)

        creds_grid.columnconfigure(1, weight=1)

        # Note about app passwords
        note_label = ttk.Label(
            creds_frame,
            text="Note: For Gmail, use an App Password if 2FA is enabled.",
            style="Subheader.TLabel"
        )
        note_label.pack(anchor="w", pady=(8, 0))

        # Email Filtering
        filter_frame = ttk.LabelFrame(frame, text="Email Filtering (Optional)", padding=12)
        filter_frame.pack(fill="x")

        ttk.Label(
            filter_frame,
            text="Filter emails from specific senders or domains:"
        ).pack(anchor="w")

        self.filter_emails_entry = ttk.Entry(filter_frame, width=60)
        self.filter_emails_entry.pack(fill="x", pady=(4, 0))
        self.filter_emails_entry.insert(0, self.config.get('Email', 'filter_emails', fallback=''))

        ttk.Label(
            filter_frame,
            text="Examples: user@example.com, @company.com (comma-separated)",
            style="Subheader.TLabel"
        ).pack(anchor="w", pady=(4, 0))

    def _create_settings_tab(self):
        """Create the General Settings tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Settings")

        settings_frame = ttk.LabelFrame(frame, text="General Settings", padding=12)
        settings_frame.pack(fill="x")

        grid_frame = ttk.Frame(settings_frame)
        grid_frame.pack(fill="x")

        # Check interval
        ttk.Label(grid_frame, text="Check Interval (seconds):").grid(row=0, column=0, sticky="w", pady=4)
        self.check_interval_entry = ttk.Entry(grid_frame, width=10)
        self.check_interval_entry.grid(row=0, column=1, sticky="w", padx=(8, 0), pady=4)
        self.check_interval_entry.insert(0, self.config.get('Settings', 'check_interval', fallback=str(DEFAULT_CHECK_INTERVAL)))

        ttk.Label(
            grid_frame,
            text="How often to check for new emails",
            style="Subheader.TLabel"
        ).grid(row=0, column=2, sticky="w", padx=(16, 0), pady=4)

        # Max SMS length
        ttk.Label(grid_frame, text="Max SMS Length:").grid(row=1, column=0, sticky="w", pady=4)
        self.max_sms_length_entry = ttk.Entry(grid_frame, width=10)
        self.max_sms_length_entry.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=4)
        self.max_sms_length_entry.insert(0, self.config.get('Settings', 'max_sms_length', fallback=str(DEFAULT_MAX_SMS_LENGTH)))

        ttk.Label(
            grid_frame,
            text="Maximum characters for SMS messages",
            style="Subheader.TLabel"
        ).grid(row=1, column=2, sticky="w", padx=(16, 0), pady=4)

    def _create_notifications_tab(self):
        """Create the Notification Methods overview tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Notifications")

        ttk.Label(
            frame,
            text="Enable/disable notification channels:",
            style="Header.TLabel"
        ).pack(anchor="w", pady=(0, 16))

        # Grid of toggle cards
        grid_frame = ttk.Frame(frame)
        grid_frame.pack(fill="both", expand=True)

        notifications = [
            ("SMS (Twilio)", "Send text messages to phone numbers", self.twilio_sms_var),
            ("Voice Call (Twilio)", "Make voice calls with text-to-speech", self.voice_var),
            ("WhatsApp (Twilio)", "Send WhatsApp messages", self.whatsapp_var),
            ("Slack", "Post to Slack channels", self.slack_var),
            ("Telegram", "Send Telegram bot messages", self.telegram_var),
            ("Discord", "Post to Discord via webhooks", self.discord_var),
            ("Custom Webhook", "Send to any HTTP endpoint", self.custom_webhook_var),
        ]

        for i, (title, desc, var) in enumerate(notifications):
            row = i // 2
            col = i % 2

            card = ToggleCard(grid_frame, title, desc, var)
            card.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)

        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)

    def _create_twilio_sms_tab(self):
        """Create the Twilio SMS configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Twilio SMS")

        config_frame = ttk.LabelFrame(frame, text="Twilio SMS Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Account SID
        ttk.Label(grid_frame, text="Account SID:").grid(row=0, column=0, sticky="w", pady=4)
        self.twilio_sms_sid_entry = ttk.Entry(grid_frame, width=50)
        self.twilio_sms_sid_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_sms_sid_entry.insert(0, self.config.get('Twilio', 'account_sid', fallback=''))

        # Auth Token
        ttk.Label(grid_frame, text="Auth Token:").grid(row=1, column=0, sticky="w", pady=4)
        self.twilio_sms_token_entry = ttk.Entry(grid_frame, width=50, show="*")
        self.twilio_sms_token_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_sms_token_entry.insert(0, self.config.get('Twilio', 'auth_token', fallback=''))

        # From Number
        ttk.Label(grid_frame, text="From Number:").grid(row=2, column=0, sticky="w", pady=4)
        self.twilio_sms_from_entry = ttk.Entry(grid_frame, width=30)
        self.twilio_sms_from_entry.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=4)
        self.twilio_sms_from_entry.insert(0, self.config.get('Twilio', 'from_number', fallback=''))

        # Destination Numbers
        ttk.Label(grid_frame, text="Destination Number(s):").grid(row=3, column=0, sticky="w", pady=4)
        self.twilio_sms_to_entry = ttk.Entry(grid_frame, width=50)
        self.twilio_sms_to_entry.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_sms_to_entry.insert(0, self.config.get('Twilio', 'destination_number', fallback=''))

        ttk.Label(
            grid_frame,
            text="Separate multiple numbers with commas (e.g., +1234567890, +0987654321)",
            style="Subheader.TLabel"
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        grid_frame.columnconfigure(1, weight=1)

    def _create_twilio_voice_tab(self):
        """Create the Twilio Voice configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Twilio Voice")

        config_frame = ttk.LabelFrame(frame, text="Twilio Voice Call Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Account SID
        ttk.Label(grid_frame, text="Account SID:").grid(row=0, column=0, sticky="w", pady=4)
        self.twilio_voice_sid_entry = ttk.Entry(grid_frame, width=50)
        self.twilio_voice_sid_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_voice_sid_entry.insert(0, self.config.get('Voice', 'account_sid', fallback=''))

        # Auth Token
        ttk.Label(grid_frame, text="Auth Token:").grid(row=1, column=0, sticky="w", pady=4)
        self.twilio_voice_token_entry = ttk.Entry(grid_frame, width=50, show="*")
        self.twilio_voice_token_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_voice_token_entry.insert(0, self.config.get('Voice', 'auth_token', fallback=''))

        # From Number
        ttk.Label(grid_frame, text="From Number:").grid(row=2, column=0, sticky="w", pady=4)
        self.twilio_voice_from_entry = ttk.Entry(grid_frame, width=30)
        self.twilio_voice_from_entry.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=4)
        self.twilio_voice_from_entry.insert(0, self.config.get('Voice', 'from_number', fallback=''))

        # Destination Numbers
        ttk.Label(grid_frame, text="Destination Number(s):").grid(row=3, column=0, sticky="w", pady=4)
        self.twilio_voice_to_entry = ttk.Entry(grid_frame, width=50)
        self.twilio_voice_to_entry.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_voice_to_entry.insert(0, self.config.get('Voice', 'destination_number', fallback=''))

        ttk.Label(
            grid_frame,
            text="Separate multiple numbers with commas",
            style="Subheader.TLabel"
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        grid_frame.columnconfigure(1, weight=1)

    def _create_twilio_whatsapp_tab(self):
        """Create the Twilio WhatsApp configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="WhatsApp")

        config_frame = ttk.LabelFrame(frame, text="Twilio WhatsApp Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Account SID
        ttk.Label(grid_frame, text="Account SID:").grid(row=0, column=0, sticky="w", pady=4)
        self.twilio_whatsapp_sid_entry = ttk.Entry(grid_frame, width=50)
        self.twilio_whatsapp_sid_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_whatsapp_sid_entry.insert(0, self.config.get('WhatsApp', 'account_sid', fallback=''))

        # Auth Token
        ttk.Label(grid_frame, text="Auth Token:").grid(row=1, column=0, sticky="w", pady=4)
        self.twilio_whatsapp_token_entry = ttk.Entry(grid_frame, width=50, show="*")
        self.twilio_whatsapp_token_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_whatsapp_token_entry.insert(0, self.config.get('WhatsApp', 'auth_token', fallback=''))

        # From Number
        ttk.Label(grid_frame, text="From Number:").grid(row=2, column=0, sticky="w", pady=4)
        self.twilio_whatsapp_from_entry = ttk.Entry(grid_frame, width=40)
        self.twilio_whatsapp_from_entry.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=4)
        self.twilio_whatsapp_from_entry.insert(0, self.config.get('WhatsApp', 'from_number', fallback=''))

        ttk.Label(
            grid_frame,
            text="Format: whatsapp:+1234567890",
            style="Subheader.TLabel"
        ).grid(row=2, column=2, sticky="w", padx=(8, 0), pady=4)

        # To Numbers
        ttk.Label(grid_frame, text="To Number(s):").grid(row=3, column=0, sticky="w", pady=4)
        self.twilio_whatsapp_to_entry = ttk.Entry(grid_frame, width=50)
        self.twilio_whatsapp_to_entry.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.twilio_whatsapp_to_entry.insert(0, self.config.get('WhatsApp', 'to_number', fallback=''))

        ttk.Label(
            grid_frame,
            text="Separate multiple with commas (e.g., whatsapp:+1234567890, whatsapp:+0987654321)",
            style="Subheader.TLabel"
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        grid_frame.columnconfigure(1, weight=1)

    def _create_slack_tab(self):
        """Create the Slack configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Slack")

        config_frame = ttk.LabelFrame(frame, text="Slack Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Token
        ttk.Label(grid_frame, text="Bot Token:").grid(row=0, column=0, sticky="w", pady=4)
        self.slack_token_entry = ttk.Entry(grid_frame, width=60, show="*")
        self.slack_token_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.slack_token_entry.insert(0, self.config.get('Slack', 'token', fallback=''))

        ttk.Label(
            grid_frame,
            text="Starts with xoxb-",
            style="Subheader.TLabel"
        ).grid(row=0, column=2, sticky="w", padx=(8, 0), pady=4)

        # Channel
        ttk.Label(grid_frame, text="Channel:").grid(row=1, column=0, sticky="w", pady=4)
        self.slack_channel_entry = ttk.Entry(grid_frame, width=30)
        self.slack_channel_entry.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=4)
        self.slack_channel_entry.insert(0, self.config.get('Slack', 'channel', fallback=''))

        ttk.Label(
            grid_frame,
            text="e.g., #notifications or notifications",
            style="Subheader.TLabel"
        ).grid(row=1, column=2, sticky="w", padx=(8, 0), pady=4)

        grid_frame.columnconfigure(1, weight=1)

    def _create_telegram_tab(self):
        """Create the Telegram configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Telegram")

        config_frame = ttk.LabelFrame(frame, text="Telegram Bot Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Bot Token
        ttk.Label(grid_frame, text="Bot Token:").grid(row=0, column=0, sticky="w", pady=4)
        self.telegram_bot_token_entry = ttk.Entry(grid_frame, width=60, show="*")
        self.telegram_bot_token_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.telegram_bot_token_entry.insert(0, self.config.get('Telegram', 'bot_token', fallback=''))

        # Chat ID
        ttk.Label(grid_frame, text="Chat ID:").grid(row=1, column=0, sticky="w", pady=4)
        self.telegram_chat_id_entry = ttk.Entry(grid_frame, width=30)
        self.telegram_chat_id_entry.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=4)
        self.telegram_chat_id_entry.insert(0, self.config.get('Telegram', 'chat_id', fallback=''))

        ttk.Label(
            grid_frame,
            text="Use @userinfobot to get your Chat ID",
            style="Subheader.TLabel"
        ).grid(row=1, column=2, sticky="w", padx=(8, 0), pady=4)

        grid_frame.columnconfigure(1, weight=1)

    def _create_discord_tab(self):
        """Create the Discord configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Discord")

        config_frame = ttk.LabelFrame(frame, text="Discord Webhook Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Webhook URL
        ttk.Label(grid_frame, text="Webhook URL:").grid(row=0, column=0, sticky="w", pady=4)
        self.discord_webhook_entry = ttk.Entry(grid_frame, width=80)
        self.discord_webhook_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.discord_webhook_entry.insert(0, self.config.get('Discord', 'webhook_url', fallback=''))

        ttk.Label(
            grid_frame,
            text="Get this from Channel Settings > Integrations > Webhooks",
            style="Subheader.TLabel"
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

        grid_frame.columnconfigure(1, weight=1)

    def _create_webhook_tab(self):
        """Create the Custom Webhook configuration tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Webhook")

        config_frame = ttk.LabelFrame(frame, text="Custom Webhook Configuration", padding=12)
        config_frame.pack(fill="x")

        grid_frame = ttk.Frame(config_frame)
        grid_frame.pack(fill="x")

        # Webhook URL
        ttk.Label(grid_frame, text="Webhook URL:").grid(row=0, column=0, sticky="w", pady=4)
        self.custom_webhook_entry = ttk.Entry(grid_frame, width=80)
        self.custom_webhook_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)
        self.custom_webhook_entry.insert(0, self.config.get('CustomWebhook', 'webhook_url', fallback=''))

        ttk.Label(
            grid_frame,
            text="Sends JSON payload: {subject, body, sender, timestamp}",
            style="Subheader.TLabel"
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))

        grid_frame.columnconfigure(1, weight=1)

    def _create_logs_tab(self):
        """Create the Logs tab."""
        frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(frame, text="Logs")

        # Toolbar
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", pady=(0, 8))

        ttk.Button(toolbar, text="Clear Logs", command=self._clear_logs).pack(side="left")

        # Auto-scroll checkbox
        self.auto_scroll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            toolbar,
            text="Auto-scroll",
            variable=self.auto_scroll_var
        ).pack(side="left", padx=(16, 0))

        # Log text area
        self.log_text = scrolledtext.ScrolledText(
            frame,
            height=20,
            font=('Consolas', 10),
            bg=Theme.BG_SECONDARY,
            fg=Theme.TEXT_PRIMARY,
            state='disabled',
            wrap='word'
        )
        self.log_text.pack(fill="both", expand=True)

        # Configure log tags for colors
        self.log_text.tag_configure('INFO', foreground=Theme.LOG_INFO)
        self.log_text.tag_configure('WARNING', foreground=Theme.LOG_WARNING)
        self.log_text.tag_configure('ERROR', foreground=Theme.LOG_ERROR)
        self.log_text.tag_configure('SUCCESS', foreground=Theme.LOG_SUCCESS)
        self.log_text.tag_configure('TIMESTAMP', foreground=Theme.TEXT_MUTED)

    def _create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        status_frame = ttk.Frame(self.root, padding="8 4")
        status_frame.pack(fill="x", side="bottom")

        self.status_label = ttk.Label(
            status_frame,
            text="Ready",
            style="Subheader.TLabel"
        )
        self.status_label.pack(side="left")

        version_label = ttk.Label(
            status_frame,
            text=f"v{__version__}",
            style="Subheader.TLabel"
        )
        version_label.pack(side="right")

    def _toggle_password_visibility(self):
        """Toggle password field visibility."""
        show = "" if self.show_password_var.get() else "*"
        self.password_entry.configure(show=show)

    def _log(self, message: str, level: str = "INFO"):
        """Add a message to the log queue for thread-safe logging."""
        self.log_queue.put((message, level))

    def _process_log_queue(self):
        """Process messages from the log queue."""
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self._append_log(message, level)
        except queue.Empty:
            pass
        finally:
            # Schedule next check
            self.root.after(100, self._process_log_queue)

    def _append_log(self, message: str, level: str = "INFO"):
        """Append a message to the log text area."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted_message = f"[{timestamp}] {level}: {message}\n"

        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] ", 'TIMESTAMP')
        self.log_text.insert(tk.END, f"{level}: ", level)
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.configure(state='disabled')

        if self.auto_scroll_var.get():
            self.log_text.see(tk.END)

    def _clear_logs(self):
        """Clear the log text area."""
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')

    def _update_config_from_gui(self):
        """Update the config object from GUI values."""
        # Email settings
        self.config['Email']['imap_server'] = self.imap_server_entry.get()
        self.config['Email']['imap_port'] = self.imap_port_entry.get()
        self.config['Email']['username'] = self.username_entry.get()
        self.config['Email']['password'] = self.password_entry.get()
        self.config['Email']['filter_emails'] = self.filter_emails_entry.get()

        # General settings
        self.config['Settings']['max_sms_length'] = self.max_sms_length_entry.get()
        self.config['Settings']['check_interval'] = self.check_interval_entry.get()

        # Notification enabled states
        self.config['Twilio']['enabled'] = str(self.twilio_sms_var.get())
        self.config['Voice']['enabled'] = str(self.voice_var.get())
        self.config['WhatsApp']['enabled'] = str(self.whatsapp_var.get())
        self.config['Slack']['enabled'] = str(self.slack_var.get())
        self.config['Telegram']['enabled'] = str(self.telegram_var.get())
        self.config['Discord']['enabled'] = str(self.discord_var.get())
        self.config['CustomWebhook']['enabled'] = str(self.custom_webhook_var.get())

        # Twilio SMS
        self.config['Twilio']['account_sid'] = self.twilio_sms_sid_entry.get()
        self.config['Twilio']['auth_token'] = self.twilio_sms_token_entry.get()
        self.config['Twilio']['from_number'] = self.twilio_sms_from_entry.get()
        self.config['Twilio']['destination_number'] = self.twilio_sms_to_entry.get()

        # Twilio Voice
        self.config['Voice']['account_sid'] = self.twilio_voice_sid_entry.get()
        self.config['Voice']['auth_token'] = self.twilio_voice_token_entry.get()
        self.config['Voice']['from_number'] = self.twilio_voice_from_entry.get()
        self.config['Voice']['destination_number'] = self.twilio_voice_to_entry.get()

        # Twilio WhatsApp
        self.config['WhatsApp']['account_sid'] = self.twilio_whatsapp_sid_entry.get()
        self.config['WhatsApp']['auth_token'] = self.twilio_whatsapp_token_entry.get()
        self.config['WhatsApp']['from_number'] = self.twilio_whatsapp_from_entry.get()
        self.config['WhatsApp']['to_number'] = self.twilio_whatsapp_to_entry.get()

        # Slack
        self.config['Slack']['token'] = self.slack_token_entry.get()
        self.config['Slack']['channel'] = self.slack_channel_entry.get()

        # Telegram
        self.config['Telegram']['bot_token'] = self.telegram_bot_token_entry.get()
        self.config['Telegram']['chat_id'] = self.telegram_chat_id_entry.get()

        # Discord
        self.config['Discord']['webhook_url'] = self.discord_webhook_entry.get()

        # Custom Webhook
        self.config['CustomWebhook']['webhook_url'] = self.custom_webhook_entry.get()

    def _save_settings(self):
        """Save settings to config file."""
        try:
            self._update_config_from_gui()
            save_config(self.config)
            self._log("Settings saved successfully", "SUCCESS")
            self.status_label.configure(text="Settings saved")
            messagebox.showinfo("Success", "Settings have been saved to config.ini")
        except Exception as e:
            self._log(f"Failed to save settings: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def _reload_settings(self):
        """Reload settings from config file."""
        try:
            self.config = load_config()
            self._log("Settings reloaded from config.ini", "INFO")
            messagebox.showinfo("Success", "Settings reloaded. Please restart to apply changes.")
        except Exception as e:
            self._log(f"Failed to reload settings: {e}", "ERROR")
            messagebox.showerror("Error", f"Failed to reload settings: {e}")

    def _test_email_connection(self):
        """Test the email connection."""
        self._log("Testing email connection...", "INFO")
        self.status_label.configure(text="Testing connection...")

        def test():
            config = EmailConfig(
                imap_server=self.imap_server_entry.get(),
                imap_port=int(self.imap_port_entry.get() or DEFAULT_IMAP_PORT),
                username=self.username_entry.get(),
                password=self.password_entry.get()
            )
            success, message = test_imap_connection(config)
            self.root.after(0, lambda: self._handle_connection_test_result(success, message))

        threading.Thread(target=test, daemon=True).start()

    def _handle_connection_test_result(self, success: bool, message: str):
        """Handle the result of a connection test."""
        if success:
            self._log(message, "SUCCESS")
            self.status_label.configure(text="Connection successful")
            messagebox.showinfo("Connection Test", message)
        else:
            self._log(f"Connection test failed: {message}", "ERROR")
            self.status_label.configure(text="Connection failed")
            messagebox.showerror("Connection Test", f"Failed: {message}")

    def _validate_settings(self) -> bool:
        """Validate settings before starting monitoring."""
        # Check notification methods
        if not any([
            self.twilio_sms_var.get(),
            self.voice_var.get(),
            self.whatsapp_var.get(),
            self.slack_var.get(),
            self.telegram_var.get(),
            self.discord_var.get(),
            self.custom_webhook_var.get()
        ]):
            messagebox.showwarning(
                "Configuration Required",
                "Please enable at least one notification method."
            )
            return False

        # Check email settings
        if not all([
            self.imap_server_entry.get(),
            self.imap_port_entry.get(),
            self.username_entry.get(),
            self.password_entry.get()
        ]):
            messagebox.showwarning(
                "Configuration Required",
                "Please fill in all email server settings."
            )
            return False

        # Validate check interval
        try:
            interval = int(self.check_interval_entry.get())
            if interval <= 0:
                raise ValueError()
        except ValueError:
            messagebox.showwarning(
                "Invalid Settings",
                "Check interval must be a positive number."
            )
            return False

        return True

    def _start_monitoring(self):
        """Start the email monitoring process."""
        if not self._validate_settings():
            return

        # Update config from GUI
        self._update_config_from_gui()

        self.monitoring = True
        self.stop_event.clear()

        # Update UI
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_indicator.set_active(True, "Monitoring")
        self.status_label.configure(text="Monitoring active")

        self._log("Starting email monitoring", "INFO")

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _stop_monitoring(self):
        """Stop the email monitoring process."""
        self.monitoring = False
        self.stop_event.set()

        # Update UI
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.status_indicator.set_active(False, "Stopped")
        self.status_label.configure(text="Monitoring stopped")

        self._log("Monitoring stopped", "INFO")

    def _monitor_loop(self):
        """Main monitoring loop running in background thread."""
        # Create dispatcher
        dispatcher = NotificationDispatcher(self.config)

        while not self.stop_event.is_set():
            imap = None
            try:
                # Get settings
                check_interval = int(self.config.get('Settings', 'check_interval', fallback=str(DEFAULT_CHECK_INTERVAL)))
                filter_emails = [
                    f.strip().lower()
                    for f in self.config.get('Email', 'filter_emails', fallback='').split(',')
                    if f.strip()
                ]

                # Connect to IMAP
                imap = connect_to_imap(
                    self.config.get('Email', 'imap_server'),
                    int(self.config.get('Email', 'imap_port', fallback=str(DEFAULT_IMAP_PORT))),
                    self.config.get('Email', 'username'),
                    self.config.get('Email', 'password')
                )

                if not imap:
                    self._log(f"Failed to connect to IMAP. Retrying in {check_interval}s...", "WARNING")
                    self.stop_event.wait(check_interval)
                    continue

                # Fetch unread emails
                unread_emails = fetch_unread_emails(imap)
                self._log(f"Found {len(unread_emails)} unread email(s)", "INFO")

                # Process each email
                for email_id, msg in unread_emails:
                    if self.stop_event.is_set():
                        break

                    sender_email = get_sender_email(msg)

                    # Apply filters
                    if filter_emails and not check_email_filter(sender_email, filter_emails):
                        self._log(f"Email from {sender_email} filtered out", "INFO")
                        continue

                    # Extract email content
                    subject = decode_email_subject(msg)
                    body = extract_email_body(msg)

                    self._log(f"Processing: {subject[:50]}...", "INFO")

                    # Create notification
                    notification = EmailNotification(
                        email_id=email_id,
                        sender=sender_email,
                        subject=subject,
                        body=body
                    )

                    # Send notifications
                    results = dispatcher.dispatch(
                        notification,
                        callback=lambda r: self._log(
                            f"{r.service}: {'Success' if r.success else 'Failed'} - {r.message}",
                            "SUCCESS" if r.success else "ERROR"
                        )
                    )

                    # Mark as read if any notification succeeded
                    if any(r.success for r in results):
                        if mark_as_read(imap, email_id):
                            self._log(f"Marked email {email_id.decode()} as read", "INFO")
                    else:
                        self._log(f"No notifications sent for {email_id.decode()}", "WARNING")

            except Exception as e:
                self._log(f"Error in monitoring loop: {e}", "ERROR")
            finally:
                if imap:
                    try:
                        imap.logout()
                    except Exception:
                        pass

                # Wait for next check
                if not self.stop_event.is_set():
                    check_interval = int(self.config.get('Settings', 'check_interval', fallback=str(DEFAULT_CHECK_INTERVAL)))
                    self._log(f"Next check in {check_interval} seconds", "INFO")
                    self.stop_event.wait(check_interval)

    def _show_docs(self):
        """Show documentation."""
        import webbrowser
        webbrowser.open("https://github.com/morroware/e2nb")

    def _show_about(self):
        """Show the About dialog."""
        messagebox.showinfo(
            "About E2NB",
            f"E2NB - Email to Notification Blaster\n\n"
            f"Version: {__version__}\n"
            f"Author: Seth Morrow\n\n"
            f"A professional email monitoring application that forwards\n"
            f"notifications through multiple channels.\n\n"
            f"License: MIT"
        )

    def _on_close(self):
        """Handle window close event."""
        if self.monitoring:
            if messagebox.askyesno("Confirm Exit", "Monitoring is active. Stop and exit?"):
                self._stop_monitoring()
            else:
                return
        self.root.destroy()


# =============================================================================
# Entry Point
# =============================================================================

def main():
    """Application entry point."""
    root = tk.Tk()
    app = EmailMonitorApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
