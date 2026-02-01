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
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from typing import Optional, Dict, Callable

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
    EmailConfig,
    test_imap_connection,
    DEFAULT_CHECK_INTERVAL,
    DEFAULT_MAX_SMS_LENGTH,
    DEFAULT_IMAP_PORT,
)


# =============================================================================
# Color Scheme
# =============================================================================

class Theme:
    """Application color theme."""
    # Sidebar
    SIDEBAR_BG = "#1e293b"
    SIDEBAR_TEXT = "#cbd5e1"
    SIDEBAR_TEXT_ACTIVE = "#ffffff"
    SIDEBAR_HOVER = "#334155"
    SIDEBAR_ACTIVE = "#3b82f6"
    SIDEBAR_SECTION = "#94a3b8"

    # Main content
    BG_PRIMARY = "#ffffff"
    BG_SECONDARY = "#f8fafc"
    BG_INPUT = "#ffffff"
    TEXT_PRIMARY = "#1e293b"
    TEXT_SECONDARY = "#64748b"
    TEXT_MUTED = "#94a3b8"
    BORDER = "#e2e8f0"

    # Accent colors
    PRIMARY = "#3b82f6"
    PRIMARY_HOVER = "#2563eb"
    SUCCESS = "#10b981"
    SUCCESS_BG = "#d1fae5"
    WARNING = "#f59e0b"
    ERROR = "#ef4444"
    ERROR_BG = "#fee2e2"

    # Log colors
    LOG_INFO = "#0ea5e9"
    LOG_WARNING = "#f59e0b"
    LOG_ERROR = "#ef4444"
    LOG_SUCCESS = "#10b981"


# =============================================================================
# Sidebar Navigation
# =============================================================================

class SidebarItem(tk.Frame):
    """A clickable sidebar navigation item."""

    def __init__(self, parent, text: str, command: Callable, indent: int = 0, **kwargs):
        super().__init__(parent, bg=Theme.SIDEBAR_BG, **kwargs)

        self.command = command
        self.active = False

        padding_left = 16 + (indent * 16)

        self.label = tk.Label(
            self,
            text=text,
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_TEXT,
            font=("Segoe UI", 10),
            anchor="w",
            padx=padding_left,
            pady=8
        )
        self.label.pack(fill="x")

        # Bind click events
        self.bind("<Button-1>", self._on_click)
        self.label.bind("<Button-1>", self._on_click)

        # Bind hover events
        self.bind("<Enter>", self._on_enter)
        self.label.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.label.bind("<Leave>", self._on_leave)

    def _on_click(self, event):
        self.command()

    def _on_enter(self, event):
        if not self.active:
            self.configure(bg=Theme.SIDEBAR_HOVER)
            self.label.configure(bg=Theme.SIDEBAR_HOVER)

    def _on_leave(self, event):
        if not self.active:
            self.configure(bg=Theme.SIDEBAR_BG)
            self.label.configure(bg=Theme.SIDEBAR_BG)

    def set_active(self, active: bool):
        self.active = active
        if active:
            self.configure(bg=Theme.SIDEBAR_ACTIVE)
            self.label.configure(bg=Theme.SIDEBAR_ACTIVE, fg=Theme.SIDEBAR_TEXT_ACTIVE)
        else:
            self.configure(bg=Theme.SIDEBAR_BG)
            self.label.configure(bg=Theme.SIDEBAR_BG, fg=Theme.SIDEBAR_TEXT)


class SidebarSection(tk.Frame):
    """A section header in the sidebar."""

    def __init__(self, parent, text: str, **kwargs):
        super().__init__(parent, bg=Theme.SIDEBAR_BG, **kwargs)

        self.label = tk.Label(
            self,
            text=text.upper(),
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_SECTION,
            font=("Segoe UI", 8, "bold"),
            anchor="w"
        )
        self.label.pack(fill="x", padx=16, pady=(16, 4))


# =============================================================================
# Custom Widgets
# =============================================================================

class FormSection(tk.Frame):
    """A form section with title and content area."""

    def __init__(self, parent, title: str, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        # Title
        title_label = tk.Label(
            self,
            text=title,
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"),
            anchor="w"
        )
        title_label.pack(fill="x", pady=(0, 12))

        # Content frame with border
        self.content = tk.Frame(
            self,
            bg=Theme.BG_SECONDARY,
            highlightbackground=Theme.BORDER,
            highlightthickness=1
        )
        self.content.pack(fill="x")


class FormRow(tk.Frame):
    """A single row in a form with label and input."""

    def __init__(
        self,
        parent,
        label: str,
        help_text: str = "",
        show: str = "",
        **kwargs
    ):
        super().__init__(parent, bg=Theme.BG_SECONDARY, **kwargs)

        # Left side - label
        label_frame = tk.Frame(self, bg=Theme.BG_SECONDARY, width=180)
        label_frame.pack(side="left", fill="y", padx=(16, 0), pady=12)
        label_frame.pack_propagate(False)

        tk.Label(
            label_frame,
            text=label,
            bg=Theme.BG_SECONDARY,
            fg=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 10),
            anchor="w"
        ).pack(anchor="w")

        if help_text:
            tk.Label(
                label_frame,
                text=help_text,
                bg=Theme.BG_SECONDARY,
                fg=Theme.TEXT_MUTED,
                font=("Segoe UI", 9),
                anchor="w"
            ).pack(anchor="w")

        # Right side - entry
        entry_frame = tk.Frame(self, bg=Theme.BG_SECONDARY)
        entry_frame.pack(side="left", fill="both", expand=True, padx=16, pady=12)

        self.entry = tk.Entry(
            entry_frame,
            font=("Segoe UI", 10),
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightcolor=Theme.PRIMARY,
            highlightbackground=Theme.BORDER,
            show=show
        )
        self.entry.pack(fill="x", ipady=6)

    def get(self) -> str:
        return self.entry.get()

    def set(self, value: str):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)


class ToggleSwitch(tk.Frame):
    """A toggle switch widget."""

    def __init__(self, parent, text: str, variable: tk.BooleanVar, **kwargs):
        super().__init__(parent, bg=Theme.BG_SECONDARY, **kwargs)

        self.variable = variable

        # Label
        tk.Label(
            self,
            text=text,
            bg=Theme.BG_SECONDARY,
            fg=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 10),
            anchor="w"
        ).pack(side="left", padx=(16, 0), pady=12)

        # Toggle
        self.canvas = tk.Canvas(
            self,
            width=44,
            height=24,
            bg=Theme.BG_SECONDARY,
            highlightthickness=0
        )
        self.canvas.pack(side="right", padx=16, pady=12)

        self._draw()
        self.canvas.bind("<Button-1>", self._toggle)
        self.variable.trace_add("write", lambda *args: self._draw())

    def _draw(self):
        self.canvas.delete("all")
        if self.variable.get():
            # On state
            self.canvas.create_rounded_rect(0, 0, 44, 24, 12, fill=Theme.PRIMARY, outline="")
            self.canvas.create_oval(22, 2, 42, 22, fill="white", outline="")
        else:
            # Off state
            self.canvas.create_rounded_rect(0, 0, 44, 24, 12, fill=Theme.BORDER, outline="")
            self.canvas.create_oval(2, 2, 22, 22, fill="white", outline="")

    def _toggle(self, event):
        self.variable.set(not self.variable.get())


# Add rounded rectangle method to Canvas
def _create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
    points = [
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1,
    ]
    return self.create_polygon(points, smooth=True, **kwargs)

tk.Canvas.create_rounded_rect = _create_rounded_rect


class StatusBadge(tk.Frame):
    """A status badge showing active/inactive state."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        self.canvas = tk.Canvas(
            self,
            width=10,
            height=10,
            bg=Theme.BG_PRIMARY,
            highlightthickness=0
        )
        self.canvas.pack(side="left", padx=(0, 8))

        self.label = tk.Label(
            self,
            text="Inactive",
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_MUTED,
            font=("Segoe UI", 10)
        )
        self.label.pack(side="left")

        self._indicator = self.canvas.create_oval(1, 1, 9, 9, fill=Theme.TEXT_MUTED, outline="")

    def set_active(self, active: bool, text: str = None):
        color = Theme.SUCCESS if active else Theme.TEXT_MUTED
        self.canvas.itemconfig(self._indicator, fill=color)
        self.label.configure(
            text=text or ("Active" if active else "Inactive"),
            fg=Theme.SUCCESS if active else Theme.TEXT_MUTED
        )


# =============================================================================
# Main Application
# =============================================================================

class EmailMonitorApp:
    """Main application class for E2NB GUI."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"E2NB - Email to Notification Blaster")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)
        self.root.configure(bg=Theme.BG_PRIMARY)

        # Load configuration
        self.config = load_config()

        # State
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.log_queue: queue.Queue = queue.Queue()
        self.current_page = "email"
        self.nav_items: Dict[str, SidebarItem] = {}
        self.pages: Dict[str, tk.Frame] = {}

        # Initialize variables
        self._init_variables()

        # Build UI
        self._create_layout()
        self._create_sidebar()
        self._create_pages()
        self._create_header()

        # Show initial page
        self._show_page("email")

        # Start log processing
        self._process_log_queue()

        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _init_variables(self):
        """Initialize tkinter variables."""
        self.twilio_sms_var = tk.BooleanVar(value=self.config.getboolean('Twilio', 'enabled', fallback=False))
        self.voice_var = tk.BooleanVar(value=self.config.getboolean('Voice', 'enabled', fallback=False))
        self.whatsapp_var = tk.BooleanVar(value=self.config.getboolean('WhatsApp', 'enabled', fallback=False))
        self.slack_var = tk.BooleanVar(value=self.config.getboolean('Slack', 'enabled', fallback=False))
        self.telegram_var = tk.BooleanVar(value=self.config.getboolean('Telegram', 'enabled', fallback=False))
        self.discord_var = tk.BooleanVar(value=self.config.getboolean('Discord', 'enabled', fallback=False))
        self.webhook_var = tk.BooleanVar(value=self.config.getboolean('CustomWebhook', 'enabled', fallback=False))
        self.auto_scroll_var = tk.BooleanVar(value=True)
        self.show_password_var = tk.BooleanVar(value=False)

    def _create_layout(self):
        """Create the main layout structure."""
        # Sidebar
        self.sidebar = tk.Frame(self.root, bg=Theme.SIDEBAR_BG, width=220)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Main content area
        self.main_area = tk.Frame(self.root, bg=Theme.BG_PRIMARY)
        self.main_area.pack(side="left", fill="both", expand=True)

        # Header in main area
        self.header = tk.Frame(self.main_area, bg=Theme.BG_PRIMARY, height=70)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)

        # Content container
        self.content = tk.Frame(self.main_area, bg=Theme.BG_PRIMARY)
        self.content.pack(fill="both", expand=True, padx=32, pady=(0, 32))

    def _create_sidebar(self):
        """Create the sidebar navigation."""
        # Logo/Title
        title_frame = tk.Frame(self.sidebar, bg=Theme.SIDEBAR_BG)
        title_frame.pack(fill="x", pady=20)

        tk.Label(
            title_frame,
            text="E2NB",
            bg=Theme.SIDEBAR_BG,
            fg="#ffffff",
            font=("Segoe UI", 16, "bold"),
            padx=16
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text=f"v{__version__}",
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_SECTION,
            font=("Segoe UI", 9),
            padx=16
        ).pack(anchor="w")

        # Navigation sections
        SidebarSection(self.sidebar, "Configuration").pack(fill="x")

        nav_items = [
            ("email", "Email Settings", 0),
            ("settings", "General", 0),
        ]

        for key, text, indent in nav_items:
            item = SidebarItem(self.sidebar, text, lambda k=key: self._show_page(k), indent)
            item.pack(fill="x")
            self.nav_items[key] = item

        SidebarSection(self.sidebar, "Notifications").pack(fill="x")

        notification_items = [
            ("sms", "Twilio SMS", 0),
            ("voice", "Twilio Voice", 0),
            ("whatsapp", "WhatsApp", 0),
            ("slack", "Slack", 0),
            ("telegram", "Telegram", 0),
            ("discord", "Discord", 0),
            ("webhook", "Webhook", 0),
        ]

        for key, text, indent in notification_items:
            item = SidebarItem(self.sidebar, text, lambda k=key: self._show_page(k), indent)
            item.pack(fill="x")
            self.nav_items[key] = item

        SidebarSection(self.sidebar, "Monitor").pack(fill="x")

        item = SidebarItem(self.sidebar, "Logs", lambda: self._show_page("logs"), 0)
        item.pack(fill="x")
        self.nav_items["logs"] = item

    def _create_header(self):
        """Create the header with status and controls."""
        # Left side - status
        left = tk.Frame(self.header, bg=Theme.BG_PRIMARY)
        left.pack(side="left", padx=32, pady=16)

        self.page_title = tk.Label(
            left,
            text="Email Settings",
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 14, "bold")
        )
        self.page_title.pack(anchor="w")

        self.status_badge = StatusBadge(left)
        self.status_badge.pack(anchor="w", pady=(4, 0))

        # Right side - buttons
        right = tk.Frame(self.header, bg=Theme.BG_PRIMARY)
        right.pack(side="right", padx=32, pady=16)

        self.stop_btn = tk.Button(
            right,
            text="Stop",
            command=self._stop_monitoring,
            bg=Theme.ERROR,
            fg="white",
            font=("Segoe UI", 10),
            relief="flat",
            padx=16,
            pady=6,
            cursor="hand2",
            state="disabled"
        )
        self.stop_btn.pack(side="right", padx=(8, 0))

        self.start_btn = tk.Button(
            right,
            text="Start Monitoring",
            command=self._start_monitoring,
            bg=Theme.SUCCESS,
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=16,
            pady=6,
            cursor="hand2"
        )
        self.start_btn.pack(side="right", padx=(8, 0))

        self.save_btn = tk.Button(
            right,
            text="Save",
            command=self._save_settings,
            bg=Theme.PRIMARY,
            fg="white",
            font=("Segoe UI", 10),
            relief="flat",
            padx=16,
            pady=6,
            cursor="hand2"
        )
        self.save_btn.pack(side="right")

    def _create_pages(self):
        """Create all content pages."""
        self._create_email_page()
        self._create_settings_page()
        self._create_sms_page()
        self._create_voice_page()
        self._create_whatsapp_page()
        self._create_slack_page()
        self._create_telegram_page()
        self._create_discord_page()
        self._create_webhook_page()
        self._create_logs_page()

    def _create_scrollable_page(self, name: str) -> tk.Frame:
        """Create a scrollable page container."""
        container = tk.Frame(self.content, bg=Theme.BG_PRIMARY)

        canvas = tk.Canvas(container, bg=Theme.BG_PRIMARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable = tk.Frame(canvas, bg=Theme.BG_PRIMARY)

        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        self.pages[name] = container
        return scrollable

    def _create_email_page(self):
        """Create the email settings page."""
        page = self._create_scrollable_page("email")

        # IMAP Settings
        section = FormSection(page, "IMAP Server")
        section.pack(fill="x", pady=(0, 24))

        self.imap_server = FormRow(section.content, "Server", "e.g., imap.gmail.com")
        self.imap_server.pack(fill="x")
        self.imap_server.set(self.config.get('Email', 'imap_server', fallback='imap.gmail.com'))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.imap_port = FormRow(section.content, "Port", "Usually 993 for SSL")
        self.imap_port.pack(fill="x")
        self.imap_port.set(self.config.get('Email', 'imap_port', fallback='993'))

        # Credentials
        section2 = FormSection(page, "Credentials")
        section2.pack(fill="x", pady=(0, 24))

        self.username = FormRow(section2.content, "Email", "Your email address")
        self.username.pack(fill="x")
        self.username.set(self.config.get('Email', 'username', fallback=''))

        sep = tk.Frame(section2.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.password = FormRow(section2.content, "Password", "App password if 2FA enabled", show="*")
        self.password.pack(fill="x")
        self.password.set(self.config.get('Email', 'password', fallback=''))

        # Test button
        btn_frame = tk.Frame(page, bg=Theme.BG_PRIMARY)
        btn_frame.pack(fill="x", pady=(0, 24))

        tk.Button(
            btn_frame,
            text="Test Connection",
            command=self._test_connection,
            bg=Theme.BG_SECONDARY,
            fg=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 10),
            relief="solid",
            bd=1,
            padx=16,
            pady=6,
            cursor="hand2"
        ).pack(side="left")

        # Filters
        section3 = FormSection(page, "Email Filters (Optional)")
        section3.pack(fill="x")

        self.filters = FormRow(section3.content, "Filter", "Comma-separated addresses or @domains")
        self.filters.pack(fill="x")
        self.filters.set(self.config.get('Email', 'filter_emails', fallback=''))

    def _create_settings_page(self):
        """Create the general settings page."""
        page = self._create_scrollable_page("settings")

        section = FormSection(page, "Monitoring Settings")
        section.pack(fill="x", pady=(0, 24))

        self.check_interval = FormRow(section.content, "Check Interval", "Seconds between checks")
        self.check_interval.pack(fill="x")
        self.check_interval.set(self.config.get('Settings', 'check_interval', fallback='60'))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.max_sms = FormRow(section.content, "Max SMS Length", "Character limit for SMS")
        self.max_sms.pack(fill="x")
        self.max_sms.set(self.config.get('Settings', 'max_sms_length', fallback='1600'))

    def _create_sms_page(self):
        """Create the Twilio SMS page."""
        page = self._create_scrollable_page("sms")

        # Enable toggle
        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable SMS Notifications", self.twilio_sms_var).pack(fill="x")

        section = FormSection(page, "Twilio Credentials")
        section.pack(fill="x", pady=(0, 24))

        self.sms_sid = FormRow(section.content, "Account SID", "From Twilio Console")
        self.sms_sid.pack(fill="x")
        self.sms_sid.set(self.config.get('Twilio', 'account_sid', fallback=''))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.sms_token = FormRow(section.content, "Auth Token", "From Twilio Console", show="*")
        self.sms_token.pack(fill="x")
        self.sms_token.set(self.config.get('Twilio', 'auth_token', fallback=''))

        section2 = FormSection(page, "Phone Numbers")
        section2.pack(fill="x")

        self.sms_from = FormRow(section2.content, "From Number", "Your Twilio number")
        self.sms_from.pack(fill="x")
        self.sms_from.set(self.config.get('Twilio', 'from_number', fallback=''))

        sep = tk.Frame(section2.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.sms_to = FormRow(section2.content, "To Number(s)", "Comma-separated")
        self.sms_to.pack(fill="x")
        self.sms_to.set(self.config.get('Twilio', 'destination_number', fallback=''))

    def _create_voice_page(self):
        """Create the Twilio Voice page."""
        page = self._create_scrollable_page("voice")

        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable Voice Calls", self.voice_var).pack(fill="x")

        section = FormSection(page, "Twilio Credentials")
        section.pack(fill="x", pady=(0, 24))

        self.voice_sid = FormRow(section.content, "Account SID", "From Twilio Console")
        self.voice_sid.pack(fill="x")
        self.voice_sid.set(self.config.get('Voice', 'account_sid', fallback=''))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.voice_token = FormRow(section.content, "Auth Token", "From Twilio Console", show="*")
        self.voice_token.pack(fill="x")
        self.voice_token.set(self.config.get('Voice', 'auth_token', fallback=''))

        section2 = FormSection(page, "Phone Numbers")
        section2.pack(fill="x")

        self.voice_from = FormRow(section2.content, "From Number", "Your Twilio number")
        self.voice_from.pack(fill="x")
        self.voice_from.set(self.config.get('Voice', 'from_number', fallback=''))

        sep = tk.Frame(section2.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.voice_to = FormRow(section2.content, "To Number(s)", "Comma-separated")
        self.voice_to.pack(fill="x")
        self.voice_to.set(self.config.get('Voice', 'destination_number', fallback=''))

    def _create_whatsapp_page(self):
        """Create the WhatsApp page."""
        page = self._create_scrollable_page("whatsapp")

        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable WhatsApp", self.whatsapp_var).pack(fill="x")

        section = FormSection(page, "Twilio Credentials")
        section.pack(fill="x", pady=(0, 24))

        self.wa_sid = FormRow(section.content, "Account SID", "From Twilio Console")
        self.wa_sid.pack(fill="x")
        self.wa_sid.set(self.config.get('WhatsApp', 'account_sid', fallback=''))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.wa_token = FormRow(section.content, "Auth Token", "From Twilio Console", show="*")
        self.wa_token.pack(fill="x")
        self.wa_token.set(self.config.get('WhatsApp', 'auth_token', fallback=''))

        section2 = FormSection(page, "WhatsApp Numbers")
        section2.pack(fill="x")

        self.wa_from = FormRow(section2.content, "From", "e.g., whatsapp:+14155238886")
        self.wa_from.pack(fill="x")
        self.wa_from.set(self.config.get('WhatsApp', 'from_number', fallback=''))

        sep = tk.Frame(section2.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.wa_to = FormRow(section2.content, "To", "e.g., whatsapp:+1234567890")
        self.wa_to.pack(fill="x")
        self.wa_to.set(self.config.get('WhatsApp', 'to_number', fallback=''))

    def _create_slack_page(self):
        """Create the Slack page."""
        page = self._create_scrollable_page("slack")

        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable Slack", self.slack_var).pack(fill="x")

        section = FormSection(page, "Slack Configuration")
        section.pack(fill="x")

        self.slack_token = FormRow(section.content, "Bot Token", "Starts with xoxb-", show="*")
        self.slack_token.pack(fill="x")
        self.slack_token.set(self.config.get('Slack', 'token', fallback=''))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.slack_channel = FormRow(section.content, "Channel", "e.g., #notifications")
        self.slack_channel.pack(fill="x")
        self.slack_channel.set(self.config.get('Slack', 'channel', fallback=''))

    def _create_telegram_page(self):
        """Create the Telegram page."""
        page = self._create_scrollable_page("telegram")

        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable Telegram", self.telegram_var).pack(fill="x")

        section = FormSection(page, "Telegram Bot Configuration")
        section.pack(fill="x")

        self.tg_token = FormRow(section.content, "Bot Token", "From @BotFather", show="*")
        self.tg_token.pack(fill="x")
        self.tg_token.set(self.config.get('Telegram', 'bot_token', fallback=''))

        sep = tk.Frame(section.content, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

        self.tg_chat = FormRow(section.content, "Chat ID", "From @userinfobot")
        self.tg_chat.pack(fill="x")
        self.tg_chat.set(self.config.get('Telegram', 'chat_id', fallback=''))

    def _create_discord_page(self):
        """Create the Discord page."""
        page = self._create_scrollable_page("discord")

        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable Discord", self.discord_var).pack(fill="x")

        section = FormSection(page, "Discord Webhook")
        section.pack(fill="x")

        self.discord_url = FormRow(section.content, "Webhook URL", "From channel integrations")
        self.discord_url.pack(fill="x")
        self.discord_url.set(self.config.get('Discord', 'webhook_url', fallback=''))

    def _create_webhook_page(self):
        """Create the custom webhook page."""
        page = self._create_scrollable_page("webhook")

        toggle_frame = tk.Frame(page, bg=Theme.BG_SECONDARY, highlightbackground=Theme.BORDER, highlightthickness=1)
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, "Enable Custom Webhook", self.webhook_var).pack(fill="x")

        section = FormSection(page, "Webhook Configuration")
        section.pack(fill="x")

        self.webhook_url = FormRow(section.content, "URL", "POST endpoint")
        self.webhook_url.pack(fill="x")
        self.webhook_url.set(self.config.get('CustomWebhook', 'webhook_url', fallback=''))

        # Info
        info = tk.Label(
            page,
            text="Sends JSON: {subject, body, sender, timestamp}",
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_MUTED,
            font=("Segoe UI", 9)
        )
        info.pack(anchor="w", pady=(16, 0))

    def _create_logs_page(self):
        """Create the logs page."""
        page = tk.Frame(self.content, bg=Theme.BG_PRIMARY)
        self.pages["logs"] = page

        # Toolbar
        toolbar = tk.Frame(page, bg=Theme.BG_PRIMARY)
        toolbar.pack(fill="x", pady=(0, 12))

        tk.Button(
            toolbar,
            text="Clear",
            command=self._clear_logs,
            bg=Theme.BG_SECONDARY,
            fg=Theme.TEXT_PRIMARY,
            font=("Segoe UI", 9),
            relief="solid",
            bd=1,
            padx=12,
            pady=4,
            cursor="hand2"
        ).pack(side="left")

        ttk.Checkbutton(
            toolbar,
            text="Auto-scroll",
            variable=self.auto_scroll_var
        ).pack(side="left", padx=(16, 0))

        # Log text
        self.log_text = scrolledtext.ScrolledText(
            page,
            font=("Consolas", 10),
            bg="#1e293b",
            fg="#e2e8f0",
            insertbackground="#e2e8f0",
            relief="flat",
            wrap="word",
            state="disabled"
        )
        self.log_text.pack(fill="both", expand=True)

        # Configure tags
        self.log_text.tag_configure('INFO', foreground=Theme.LOG_INFO)
        self.log_text.tag_configure('WARNING', foreground=Theme.LOG_WARNING)
        self.log_text.tag_configure('ERROR', foreground=Theme.LOG_ERROR)
        self.log_text.tag_configure('SUCCESS', foreground=Theme.LOG_SUCCESS)
        self.log_text.tag_configure('TIMESTAMP', foreground="#64748b")

    def _show_page(self, name: str):
        """Show a specific page."""
        # Update navigation
        for key, item in self.nav_items.items():
            item.set_active(key == name)

        # Hide all pages
        for page in self.pages.values():
            page.pack_forget()

        # Show selected page
        if name in self.pages:
            self.pages[name].pack(fill="both", expand=True)

        # Update title
        titles = {
            "email": "Email Settings",
            "settings": "General Settings",
            "sms": "Twilio SMS",
            "voice": "Twilio Voice",
            "whatsapp": "WhatsApp",
            "slack": "Slack",
            "telegram": "Telegram",
            "discord": "Discord",
            "webhook": "Custom Webhook",
            "logs": "Activity Logs"
        }
        self.page_title.configure(text=titles.get(name, name.title()))
        self.current_page = name

    def _log(self, message: str, level: str = "INFO"):
        """Add a message to the log queue."""
        self.log_queue.put((message, level))

    def _process_log_queue(self):
        """Process the log queue."""
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self._append_log(message, level)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_log_queue)

    def _append_log(self, message: str, level: str = "INFO"):
        """Append to log display."""
        timestamp = datetime.now().strftime('%H:%M:%S')

        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] ", 'TIMESTAMP')
        self.log_text.insert(tk.END, f"{level}: ", level)
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.configure(state='disabled')

        if self.auto_scroll_var.get():
            self.log_text.see(tk.END)

    def _clear_logs(self):
        """Clear the log display."""
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')

    def _update_config(self):
        """Update config from GUI values."""
        # Email
        self.config['Email']['imap_server'] = self.imap_server.get()
        self.config['Email']['imap_port'] = self.imap_port.get()
        self.config['Email']['username'] = self.username.get()
        self.config['Email']['password'] = self.password.get()
        self.config['Email']['filter_emails'] = self.filters.get()

        # Settings
        self.config['Settings']['check_interval'] = self.check_interval.get()
        self.config['Settings']['max_sms_length'] = self.max_sms.get()

        # Toggles
        self.config['Twilio']['enabled'] = str(self.twilio_sms_var.get())
        self.config['Voice']['enabled'] = str(self.voice_var.get())
        self.config['WhatsApp']['enabled'] = str(self.whatsapp_var.get())
        self.config['Slack']['enabled'] = str(self.slack_var.get())
        self.config['Telegram']['enabled'] = str(self.telegram_var.get())
        self.config['Discord']['enabled'] = str(self.discord_var.get())
        self.config['CustomWebhook']['enabled'] = str(self.webhook_var.get())

        # Twilio SMS
        self.config['Twilio']['account_sid'] = self.sms_sid.get()
        self.config['Twilio']['auth_token'] = self.sms_token.get()
        self.config['Twilio']['from_number'] = self.sms_from.get()
        self.config['Twilio']['destination_number'] = self.sms_to.get()

        # Voice
        self.config['Voice']['account_sid'] = self.voice_sid.get()
        self.config['Voice']['auth_token'] = self.voice_token.get()
        self.config['Voice']['from_number'] = self.voice_from.get()
        self.config['Voice']['destination_number'] = self.voice_to.get()

        # WhatsApp
        self.config['WhatsApp']['account_sid'] = self.wa_sid.get()
        self.config['WhatsApp']['auth_token'] = self.wa_token.get()
        self.config['WhatsApp']['from_number'] = self.wa_from.get()
        self.config['WhatsApp']['to_number'] = self.wa_to.get()

        # Slack
        self.config['Slack']['token'] = self.slack_token.get()
        self.config['Slack']['channel'] = self.slack_channel.get()

        # Telegram
        self.config['Telegram']['bot_token'] = self.tg_token.get()
        self.config['Telegram']['chat_id'] = self.tg_chat.get()

        # Discord
        self.config['Discord']['webhook_url'] = self.discord_url.get()

        # Webhook
        self.config['CustomWebhook']['webhook_url'] = self.webhook_url.get()

    def _save_settings(self):
        """Save settings to file."""
        try:
            self._update_config()
            save_config(self.config)
            self._log("Settings saved", "SUCCESS")
            messagebox.showinfo("Saved", "Settings saved to config.ini")
        except Exception as e:
            self._log(f"Save failed: {e}", "ERROR")
            messagebox.showerror("Error", str(e))

    def _test_connection(self):
        """Test email connection."""
        self._log("Testing connection...", "INFO")

        def test():
            cfg = EmailConfig(
                imap_server=self.imap_server.get(),
                imap_port=int(self.imap_port.get() or 993),
                username=self.username.get(),
                password=self.password.get()
            )
            success, msg = test_imap_connection(cfg)
            self.root.after(0, lambda: self._on_test_result(success, msg))

        threading.Thread(target=test, daemon=True).start()

    def _on_test_result(self, success: bool, message: str):
        """Handle test result."""
        if success:
            self._log(message, "SUCCESS")
            messagebox.showinfo("Success", message)
        else:
            self._log(f"Failed: {message}", "ERROR")
            messagebox.showerror("Failed", message)

    def _validate(self) -> bool:
        """Validate settings."""
        if not any([
            self.twilio_sms_var.get(), self.voice_var.get(), self.whatsapp_var.get(),
            self.slack_var.get(), self.telegram_var.get(), self.discord_var.get(),
            self.webhook_var.get()
        ]):
            messagebox.showwarning("Warning", "Enable at least one notification method.")
            return False

        if not all([self.imap_server.get(), self.username.get(), self.password.get()]):
            messagebox.showwarning("Warning", "Fill in email settings.")
            return False

        return True

    def _start_monitoring(self):
        """Start monitoring."""
        if not self._validate():
            return

        self._update_config()
        self.monitoring = True
        self.stop_event.clear()

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_badge.set_active(True, "Monitoring")

        self._log("Monitoring started", "INFO")
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _stop_monitoring(self):
        """Stop monitoring."""
        self.monitoring = False
        self.stop_event.set()

        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_badge.set_active(False, "Stopped")

        self._log("Monitoring stopped", "INFO")

    def _monitor_loop(self):
        """Main monitoring loop."""
        dispatcher = NotificationDispatcher(self.config)

        while not self.stop_event.is_set():
            imap = None
            try:
                interval = int(self.config.get('Settings', 'check_interval', fallback='60'))
                filters = [f.strip().lower() for f in self.config.get('Email', 'filter_emails', fallback='').split(',') if f.strip()]

                imap = connect_to_imap(
                    self.config.get('Email', 'imap_server'),
                    int(self.config.get('Email', 'imap_port', fallback='993')),
                    self.config.get('Email', 'username'),
                    self.config.get('Email', 'password')
                )

                if not imap:
                    self._log(f"Connection failed. Retry in {interval}s", "WARNING")
                    self.stop_event.wait(interval)
                    continue

                emails = fetch_unread_emails(imap)
                self._log(f"Found {len(emails)} unread email(s)", "INFO")

                for email_id, msg in emails:
                    if self.stop_event.is_set():
                        break

                    sender = get_sender_email(msg)
                    if filters and not check_email_filter(sender, filters):
                        continue

                    subject = decode_email_subject(msg)
                    body = extract_email_body(msg)

                    self._log(f"Processing: {subject[:40]}...", "INFO")

                    notification = EmailNotification(
                        email_id=email_id,
                        sender=sender,
                        subject=subject,
                        body=body
                    )

                    results = dispatcher.dispatch(
                        notification,
                        callback=lambda r: self._log(
                            f"{r.service}: {r.message}",
                            "SUCCESS" if r.success else "ERROR"
                        )
                    )

                    if any(r.success for r in results):
                        mark_as_read(imap, email_id)

            except Exception as e:
                self._log(f"Error: {e}", "ERROR")
            finally:
                if imap:
                    try:
                        imap.logout()
                    except:
                        pass

                if not self.stop_event.is_set():
                    interval = int(self.config.get('Settings', 'check_interval', fallback='60'))
                    self.stop_event.wait(interval)

    def _on_close(self):
        """Handle window close."""
        if self.monitoring:
            if messagebox.askyesno("Confirm", "Stop monitoring and exit?"):
                self._stop_monitoring()
            else:
                return
        self.root.destroy()


def main():
    root = tk.Tk()
    app = EmailMonitorApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
