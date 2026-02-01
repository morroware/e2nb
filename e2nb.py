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

import os
import sys

# ---------------------------------------------------------------------------
# DPI Configuration — must run BEFORE importing tkinter
# ---------------------------------------------------------------------------
# Python 3.8+ on Windows declares per-monitor DPI awareness in its manifest.
# Tkinter does not auto-scale pixel-based widget dimensions for high DPI, so
# we override to DPI-unaware mode and let Windows handle the scaling.
if sys.platform == "win32":
    try:
        import ctypes
        try:
            # UNAWARE_GDISCALED: best render quality (Windows 10 1809+)
            ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-5))
        except (AttributeError, OSError):
            try:
                # Basic DPI-unaware fallback
                ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-1))
            except (AttributeError, OSError):
                try:
                    ctypes.windll.shcore.SetProcessDpiAwareness(0)
                except (AttributeError, OSError):
                    pass
    except Exception:
        pass

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
from typing import Optional, Dict, Callable, List

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
# Cross-Platform Font Detection
# =============================================================================

def _detect_fonts() -> tuple:
    """Detect best available fonts for the current platform."""
    if sys.platform == "win32":
        return ("Segoe UI", "Cascadia Code")
    elif sys.platform == "darwin":
        return ("SF Pro Text", "SF Mono")
    else:
        # Linux - try common modern fonts
        return ("Noto Sans", "Noto Sans Mono")

_FONT_UI, _FONT_MONO = _detect_fonts()


# =============================================================================
# Color Scheme
# =============================================================================

class Theme:
    """Application color theme with modern palette."""
    # Sidebar
    SIDEBAR_BG = "#0f172a"
    SIDEBAR_BG_SUBTLE = "#1e293b"
    SIDEBAR_TEXT = "#94a3b8"
    SIDEBAR_TEXT_ACTIVE = "#ffffff"
    SIDEBAR_HOVER = "#1e293b"
    SIDEBAR_ACTIVE = "#3b82f6"
    SIDEBAR_SECTION = "#64748b"
    SIDEBAR_DIVIDER = "#1e293b"
    SIDEBAR_BADGE_BG = "#334155"
    SIDEBAR_BADGE_FG = "#94a3b8"

    # Main content
    BG_PRIMARY = "#ffffff"
    BG_SECONDARY = "#f8fafc"
    BG_TERTIARY = "#f1f5f9"
    BG_INPUT = "#ffffff"
    BG_INPUT_FOCUS = "#f8fafc"
    TEXT_PRIMARY = "#0f172a"
    TEXT_SECONDARY = "#475569"
    TEXT_MUTED = "#94a3b8"
    TEXT_LABEL = "#334155"
    BORDER = "#e2e8f0"
    BORDER_FOCUS = "#3b82f6"
    BORDER_HOVER = "#cbd5e1"

    # Accent colors
    PRIMARY = "#3b82f6"
    PRIMARY_HOVER = "#2563eb"
    PRIMARY_LIGHT = "#dbeafe"
    PRIMARY_SUBTLE = "#eff6ff"
    SUCCESS = "#10b981"
    SUCCESS_HOVER = "#059669"
    SUCCESS_LIGHT = "#d1fae5"
    SUCCESS_BG = "#ecfdf5"
    WARNING = "#f59e0b"
    WARNING_LIGHT = "#fef3c7"
    ERROR = "#ef4444"
    ERROR_HOVER = "#dc2626"
    ERROR_LIGHT = "#fee2e2"
    ERROR_BG = "#fef2f2"

    # Toggle
    TOGGLE_OFF = "#cbd5e1"
    TOGGLE_OFF_HOVER = "#94a3b8"
    TOGGLE_ON = "#3b82f6"
    TOGGLE_ON_HOVER = "#2563eb"
    TOGGLE_KNOB = "#ffffff"

    # Log colors
    LOG_BG = "#0f172a"
    LOG_FG = "#e2e8f0"
    LOG_INFO = "#38bdf8"
    LOG_WARNING = "#fbbf24"
    LOG_ERROR = "#f87171"
    LOG_SUCCESS = "#34d399"
    LOG_TIMESTAMP = "#475569"

    # Cards
    CARD_BORDER = "#e2e8f0"
    CARD_SHADOW = "#f1f5f9"

    # Status indicator colors
    STATUS_ACTIVE = "#10b981"
    STATUS_INACTIVE = "#cbd5e1"

    # Toast
    TOAST_SUCCESS_BG = "#ecfdf5"
    TOAST_SUCCESS_BORDER = "#6ee7b7"
    TOAST_SUCCESS_FG = "#065f46"
    TOAST_ERROR_BG = "#fef2f2"
    TOAST_ERROR_BORDER = "#fca5a5"
    TOAST_ERROR_FG = "#991b1b"
    TOAST_INFO_BG = "#eff6ff"
    TOAST_INFO_BORDER = "#93c5fd"
    TOAST_INFO_FG = "#1e40af"

    # Font family (cross-platform)
    FONT = _FONT_UI
    FONT_MONO = _FONT_MONO


# =============================================================================
# ttk Theme Configuration
# =============================================================================

def configure_ttk_style():
    """Configure ttk widgets to match application theme."""
    style = ttk.Style()
    style.theme_use("clam")

    # Scrollbar
    style.configure(
        "TScrollbar",
        background=Theme.BG_TERTIARY,
        troughcolor=Theme.BG_SECONDARY,
        borderwidth=0,
        arrowsize=0,
        relief="flat",
    )
    style.map(
        "TScrollbar",
        background=[("active", Theme.BORDER_HOVER), ("!active", Theme.BORDER)],
    )

    # Checkbutton
    style.configure(
        "TCheckbutton",
        background=Theme.BG_SECONDARY,
        foreground=Theme.TEXT_SECONDARY,
        font=(Theme.FONT, 9),
        focuscolor="",
    )
    style.map(
        "TCheckbutton",
        background=[("active", Theme.BG_SECONDARY)],
    )


# =============================================================================
# Tooltip Widget
# =============================================================================

class Tooltip:
    """A tooltip widget that appears on hover over a target widget."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._tip_window: Optional[tk.Toplevel] = None
        self._after_id: Optional[str] = None

        self.widget.bind("<Enter>", self._schedule, add="+")
        self.widget.bind("<Leave>", self._cancel, add="+")
        self.widget.bind("<ButtonPress>", self._cancel, add="+")

    def _schedule(self, event=None):
        self._cancel()
        self._after_id = self.widget.after(self.delay, self._show)

    def _cancel(self, event=None):
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        self._hide()

    def _show(self):
        if self._tip_window:
            return
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6

        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        try:
            tw.attributes("-alpha", 0.95)
        except tk.TclError:
            pass

        frame = tk.Frame(
            tw,
            bg="#1e293b",
            highlightbackground="#334155",
            highlightthickness=1,
        )
        frame.pack()

        tk.Label(
            frame,
            text=self.text,
            bg="#1e293b",
            fg="#e2e8f0",
            font=(Theme.FONT, 9),
            padx=10,
            pady=5,
            wraplength=280,
            justify="left",
        ).pack()

    def _hide(self):
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None

    def update_text(self, text: str):
        self.text = text


# =============================================================================
# Toast Notification
# =============================================================================

class Toast:
    """An in-app toast notification that slides in and fades out."""

    _DURATION = 3000
    _FADE_STEPS = 10
    _FADE_DELAY = 30

    def __init__(self, parent: tk.Widget):
        self._parent = parent
        self._current: Optional[tk.Frame] = None
        self._after_ids: List[str] = []

    def _cancel_pending(self):
        for aid in self._after_ids:
            try:
                self._parent.after_cancel(aid)
            except (ValueError, tk.TclError):
                pass
        self._after_ids.clear()
        if self._current:
            try:
                self._current.destroy()
            except tk.TclError:
                pass
            self._current = None

    def show(self, message: str, level: str = "success"):
        self._cancel_pending()

        if level == "success":
            bg, border, fg, icon = (
                Theme.TOAST_SUCCESS_BG, Theme.TOAST_SUCCESS_BORDER,
                Theme.TOAST_SUCCESS_FG, "\u2713",
            )
        elif level == "error":
            bg, border, fg, icon = (
                Theme.TOAST_ERROR_BG, Theme.TOAST_ERROR_BORDER,
                Theme.TOAST_ERROR_FG, "\u2717",
            )
        else:
            bg, border, fg, icon = (
                Theme.TOAST_INFO_BG, Theme.TOAST_INFO_BORDER,
                Theme.TOAST_INFO_FG, "\u2139",
            )

        toast = tk.Frame(
            self._parent,
            bg=bg,
            highlightbackground=border,
            highlightthickness=1,
        )

        inner = tk.Frame(toast, bg=bg)
        inner.pack(fill="x", padx=14, pady=10)

        tk.Label(
            inner, text=icon, bg=bg, fg=fg,
            font=(Theme.FONT, 12, "bold"),
        ).pack(side="left", padx=(0, 10))

        tk.Label(
            inner, text=message, bg=bg, fg=fg,
            font=(Theme.FONT, 10), anchor="w",
        ).pack(side="left", fill="x", expand=True)

        # Close button
        close_label = tk.Label(
            inner, text="\u00d7", bg=bg, fg=fg,
            font=(Theme.FONT, 12), cursor="hand2",
        )
        close_label.pack(side="right", padx=(10, 0))
        close_label.bind("<Button-1>", lambda e: self._cancel_pending())

        toast.place(relx=1.0, y=12, anchor="ne", x=-12)
        self._current = toast

        aid = self._parent.after(self._DURATION, self._fade_out)
        self._after_ids.append(aid)

    def _fade_out(self):
        if not self._current:
            return
        self._fade_step(self._FADE_STEPS)

    def _fade_step(self, remaining: int):
        if remaining <= 0 or not self._current:
            self._cancel_pending()
            return
        try:
            alpha = remaining / self._FADE_STEPS
            self._current.attributes = None  # placeholder
            # tkinter frames don't support alpha; just destroy at end
            if remaining == 1:
                self._cancel_pending()
                return
        except tk.TclError:
            return
        aid = self._parent.after(self._FADE_DELAY, lambda: self._fade_step(remaining - 1))
        self._after_ids.append(aid)


# =============================================================================
# Modern Button
# =============================================================================

class ModernButton(tk.Canvas):
    """A button with hover effects and rounded appearance."""

    def __init__(
        self,
        parent,
        text: str,
        command: Callable = None,
        bg: str = Theme.PRIMARY,
        fg: str = "white",
        hover_bg: str = None,
        font_size: int = 10,
        bold: bool = False,
        padx: int = 20,
        pady: int = 8,
        tooltip: str = "",
        **kwargs
    ):
        self._text = text
        self._command = command
        self._bg = bg
        self._fg = fg
        self._hover_bg = hover_bg or self._darken_color(bg, 20)
        self._disabled_bg = Theme.BORDER
        self._disabled_fg = Theme.TEXT_MUTED
        self._font_size = font_size
        self._bold = bold
        self._padx = padx
        self._pady = pady
        self._enabled = True

        weight = "bold" if bold else "normal"
        font = (Theme.FONT, font_size, weight)

        # Measure text to size the canvas
        temp = tk.Label(parent, text=text, font=font)
        text_width = temp.winfo_reqwidth()
        text_height = temp.winfo_reqheight()
        temp.destroy()

        self._width = text_width + padx * 2
        self._height = text_height + pady * 2
        self._radius = min(6, self._height // 2)

        parent_bg = Theme.BG_PRIMARY
        try:
            parent_bg = parent.cget("bg")
        except (tk.TclError, AttributeError):
            pass

        super().__init__(
            parent,
            width=self._width,
            height=self._height,
            bg=parent_bg,
            highlightthickness=0,
            **kwargs
        )

        self._font = font
        self._draw(self._bg)

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.bind("<ButtonRelease-1>", self._on_release)

        if tooltip:
            Tooltip(self, tooltip)

    def _draw(self, bg_color: str):
        self.delete("all")
        fg = self._fg if self._enabled else self._disabled_fg
        self._draw_rounded_rect(
            1, 1, self._width - 1, self._height - 1,
            self._radius, fill=bg_color, outline=""
        )
        self.create_text(
            self._width // 2, self._height // 2,
            text=self._text, fill=fg, font=self._font
        )

    def _draw_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def _on_enter(self, event):
        if self._enabled:
            self._draw(self._hover_bg)
            self.configure(cursor="hand2")

    def _on_leave(self, event):
        if self._enabled:
            self._draw(self._bg)
        else:
            self.configure(cursor="")

    def _on_click(self, event):
        if self._enabled:
            pressed = self._darken_color(self._hover_bg, 10)
            self._draw(pressed)

    def _on_release(self, event):
        if self._enabled and self._command:
            self._draw(self._hover_bg)
            self._command()

    def configure_state(self, state: str):
        self._enabled = state != "disabled"
        if self._enabled:
            self._draw(self._bg)
        else:
            self._draw(self._disabled_bg)
            self.configure(cursor="")

    @staticmethod
    def _darken_color(hex_color: str, amount: int = 20) -> str:
        hex_color = hex_color.lstrip('#')
        r = max(0, int(hex_color[0:2], 16) - amount)
        g = max(0, int(hex_color[2:4], 16) - amount)
        b = max(0, int(hex_color[4:6], 16) - amount)
        return f"#{r:02x}{g:02x}{b:02x}"


# =============================================================================
# Sidebar Navigation
# =============================================================================

class SidebarItem(tk.Frame):
    """A clickable sidebar navigation item with optional status indicator."""

    def __init__(
        self,
        parent,
        text: str,
        command: Callable,
        indent: int = 0,
        status_var: tk.BooleanVar = None,
        tooltip: str = "",
        **kwargs
    ):
        super().__init__(parent, bg=Theme.SIDEBAR_BG, **kwargs)

        self.command = command
        self.active = False
        self._status_var = status_var

        padding_left = 16 + (indent * 16)

        # Inner container for hover background
        self._inner = tk.Frame(self, bg=Theme.SIDEBAR_BG)
        self._inner.pack(fill="x", padx=6, pady=1)

        # Active indicator bar (left edge)
        self._indicator_bar = tk.Frame(self._inner, bg=Theme.SIDEBAR_BG, width=3)
        self._indicator_bar.pack(side="left", fill="y")

        # Text label
        self.label = tk.Label(
            self._inner,
            text=text,
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_TEXT,
            font=(Theme.FONT, 10),
            anchor="w",
            padx=padding_left - 4,
            pady=7,
        )
        self.label.pack(side="left", fill="x", expand=True)

        # Status dot (for notification services)
        if status_var is not None:
            self._status_canvas = tk.Canvas(
                self._inner, width=8, height=8,
                bg=Theme.SIDEBAR_BG, highlightthickness=0,
            )
            self._status_canvas.pack(side="right", padx=(0, 14), pady=0)
            self._status_canvas.place(relx=1.0, rely=0.5, anchor="e", x=-14)
            self._status_dot = self._status_canvas.create_oval(
                0, 0, 8, 8,
                fill=Theme.STATUS_ACTIVE if status_var.get() else Theme.STATUS_INACTIVE,
                outline="",
            )
            status_var.trace_add("write", self._update_status_dot)

        # Bind click events to all child widgets
        for w in [self, self._inner, self.label, self._indicator_bar]:
            w.bind("<Button-1>", self._on_click)
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)

        if tooltip:
            Tooltip(self, tooltip)

    def _update_status_dot(self, *args):
        if hasattr(self, '_status_canvas'):
            is_on = self._status_var.get()
            self._status_canvas.itemconfig(
                self._status_dot,
                fill=Theme.STATUS_ACTIVE if is_on else Theme.STATUS_INACTIVE,
            )

    def _on_click(self, event):
        self.command()

    def _on_enter(self, event):
        if not self.active:
            self._set_bg(Theme.SIDEBAR_HOVER)
            self.configure(cursor="hand2")

    def _on_leave(self, event):
        if not self.active:
            self._set_bg(Theme.SIDEBAR_BG)

    def _set_bg(self, color: str):
        for w in [self._inner, self.label, self._indicator_bar]:
            w.configure(bg=color)
        if hasattr(self, '_status_canvas'):
            self._status_canvas.configure(bg=color)

    def set_active(self, active: bool):
        self.active = active
        if active:
            self._set_bg(Theme.SIDEBAR_HOVER)
            self._indicator_bar.configure(bg=Theme.SIDEBAR_ACTIVE)
            self.label.configure(fg=Theme.SIDEBAR_TEXT_ACTIVE)
        else:
            self._set_bg(Theme.SIDEBAR_BG)
            self._indicator_bar.configure(bg=Theme.SIDEBAR_BG)
            self.label.configure(fg=Theme.SIDEBAR_TEXT)


class SidebarSection(tk.Frame):
    """A section header in the sidebar."""

    def __init__(self, parent, text: str, **kwargs):
        super().__init__(parent, bg=Theme.SIDEBAR_BG, **kwargs)

        divider = tk.Frame(self, bg=Theme.SIDEBAR_DIVIDER, height=1)
        divider.pack(fill="x", padx=20, pady=(10, 0))

        self.label = tk.Label(
            self,
            text=text.upper(),
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_SECTION,
            font=(Theme.FONT, 8, "bold"),
            anchor="w",
        )
        self.label.pack(fill="x", padx=20, pady=(6, 2))


class SidebarBadge(tk.Frame):
    """A small badge showing enabled service count in sidebar."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.SIDEBAR_BG, **kwargs)

        self._label = tk.Label(
            self,
            text="0 / 7 active",
            bg=Theme.SIDEBAR_BADGE_BG,
            fg=Theme.SIDEBAR_BADGE_FG,
            font=(Theme.FONT, 8),
            padx=10,
            pady=3,
        )
        self._label.pack(fill="x", padx=20, pady=(4, 0))

    def update_count(self, active: int, total: int = 7):
        self._label.configure(text=f"{active} / {total} active")


# =============================================================================
# Custom Widgets
# =============================================================================

class FormSection(tk.Frame):
    """A form section with title, description, and card-like content area with shadow."""

    def __init__(self, parent, title: str, description: str = "", **kwargs):
        super().__init__(parent, bg=Theme.BG_SECONDARY, **kwargs)

        # Title
        tk.Label(
            self, text=title,
            bg=Theme.BG_SECONDARY, fg=Theme.TEXT_PRIMARY,
            font=(Theme.FONT, 12, "bold"), anchor="w",
        ).pack(fill="x", pady=(0, 2))

        if description:
            tk.Label(
                self, text=description,
                bg=Theme.BG_SECONDARY, fg=Theme.TEXT_MUTED,
                font=(Theme.FONT, 9), anchor="w",
            ).pack(fill="x", pady=(0, 10))
        else:
            tk.Frame(self, bg=Theme.BG_SECONDARY, height=10).pack(fill="x")

        # Shadow layer (bottom + right)
        shadow = tk.Frame(self, bg=Theme.CARD_SHADOW)
        shadow.pack(fill="x")

        # Card content
        self.content = tk.Frame(
            shadow, bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.CARD_BORDER,
            highlightthickness=1,
        )
        self.content.pack(fill="x", padx=(0, 1), pady=(0, 1))


class PlaceholderEntry(tk.Entry):
    """An Entry widget with placeholder text that disappears on focus."""

    def __init__(self, parent, placeholder: str = "", **kwargs):
        super().__init__(parent, **kwargs)
        self._placeholder = placeholder
        self._placeholder_active = False
        self._real_fg = kwargs.get("fg", Theme.TEXT_PRIMARY)
        self._show_char = kwargs.get("show", "")

        if placeholder:
            self.bind("<FocusIn>", self._on_focus_in, add="+")
            self.bind("<FocusOut>", self._on_focus_out, add="+")
            # Show placeholder initially if empty
            if not self.get():
                self._show_placeholder()

    def _show_placeholder(self):
        if not self.get():
            self._placeholder_active = True
            self.configure(fg=Theme.TEXT_MUTED, show="")
            self.insert(0, self._placeholder)

    def _on_focus_in(self, event=None):
        if self._placeholder_active:
            self._placeholder_active = False
            self.delete(0, tk.END)
            self.configure(fg=self._real_fg, show=self._show_char)

    def _on_focus_out(self, event=None):
        if not self.get():
            self._show_placeholder()

    def get(self) -> str:
        if self._placeholder_active:
            return ""
        return super().get()

    def set_value(self, value: str):
        """Set the entry value, clearing placeholder if needed."""
        was_placeholder = self._placeholder_active
        if self._placeholder_active:
            self._placeholder_active = False
            self.configure(fg=self._real_fg, show=self._show_char)
        self.delete(0, tk.END)
        if value:
            self.insert(0, value)
        elif self._placeholder and self != self.focus_get():
            self._show_placeholder()


class FormRow(tk.Frame):
    """A single row in a form with label and input with focus states."""

    def __init__(
        self,
        parent,
        label: str,
        help_text: str = "",
        show: str = "",
        tooltip: str = "",
        placeholder: str = "",
        **kwargs
    ):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        # Left side - label
        label_frame = tk.Frame(self, bg=Theme.BG_PRIMARY, width=180)
        label_frame.pack(side="left", fill="y", padx=(16, 0), pady=14)
        label_frame.pack_propagate(False)

        self._label_widget = tk.Label(
            label_frame, text=label,
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_LABEL,
            font=(Theme.FONT, 10), anchor="w",
        )
        self._label_widget.pack(anchor="w")

        if help_text:
            tk.Label(
                label_frame, text=help_text,
                bg=Theme.BG_PRIMARY, fg=Theme.TEXT_MUTED,
                font=(Theme.FONT, 9), anchor="w",
            ).pack(anchor="w", pady=(2, 0))

        # Right side - entry with custom focus frame
        entry_container = tk.Frame(self, bg=Theme.BG_PRIMARY)
        entry_container.pack(side="left", fill="both", expand=True, padx=16, pady=14)

        # Wrapper frame that acts as the visible border
        self._entry_wrapper = tk.Frame(
            entry_container, bg=Theme.BORDER, highlightthickness=0,
        )
        self._entry_wrapper.pack(fill="x")

        # Use placeholder if provided, otherwise use help_text as placeholder
        ph = placeholder or help_text

        self.entry = PlaceholderEntry(
            self._entry_wrapper,
            placeholder=ph,
            font=(Theme.FONT, 10),
            bg=Theme.BG_INPUT,
            fg=Theme.TEXT_PRIMARY,
            relief="flat",
            bd=0,
            highlightthickness=0,
            insertbackground=Theme.PRIMARY,
            show=show,
        )
        self.entry.pack(fill="x", ipady=8, padx=1, pady=1)

        # Focus events
        self.entry.bind("<FocusIn>", self._on_focus_in, add="+")
        self.entry.bind("<FocusOut>", self._on_focus_out, add="+")
        self.entry.bind("<Enter>", self._on_hover_in)
        self.entry.bind("<Leave>", self._on_hover_out)

        if tooltip:
            Tooltip(self.entry, tooltip)

    def _on_focus_in(self, event):
        self._entry_wrapper.configure(bg=Theme.BORDER_FOCUS)
        self.entry.configure(bg=Theme.BG_INPUT_FOCUS)

    def _on_focus_out(self, event):
        self._entry_wrapper.configure(bg=Theme.BORDER)
        self.entry.configure(bg=Theme.BG_INPUT)

    def _on_hover_in(self, event):
        if self.entry != self.entry.focus_get():
            self._entry_wrapper.configure(bg=Theme.BORDER_HOVER)

    def _on_hover_out(self, event):
        if self.entry != self.entry.focus_get():
            self._entry_wrapper.configure(bg=Theme.BORDER)

    def get(self) -> str:
        return self.entry.get()

    def set(self, value: str):
        self.entry.set_value(value)


class ToggleSwitch(tk.Frame):
    """An animated toggle switch widget with smooth transitions."""

    _ANIM_STEPS = 6
    _ANIM_DELAY = 16

    def __init__(self, parent, text: str, variable: tk.BooleanVar, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        self.variable = variable
        self._hovering = False
        self._animating = False

        tk.Label(
            self, text=text,
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_PRIMARY,
            font=(Theme.FONT, 10), anchor="w",
        ).pack(side="left", padx=(16, 0), pady=12)

        # Status text
        self._status_label = tk.Label(
            self, text="On" if variable.get() else "Off",
            bg=Theme.BG_PRIMARY,
            fg=Theme.SUCCESS if variable.get() else Theme.TEXT_MUTED,
            font=(Theme.FONT, 9), anchor="e",
        )
        self._status_label.pack(side="right", padx=(0, 4), pady=12)

        self._track_w = 48
        self._track_h = 26
        self._knob_r = 9
        self._knob_pad = 3

        self.canvas = tk.Canvas(
            self, width=self._track_w, height=self._track_h,
            bg=Theme.BG_PRIMARY, highlightthickness=0,
        )
        self.canvas.pack(side="right", padx=(8, 16), pady=12)

        self._off_x = self._knob_pad + self._knob_r + 1
        self._on_x = self._track_w - self._knob_pad - self._knob_r - 1
        self._current_x = float(self._on_x if variable.get() else self._off_x)

        self._draw()

        self.canvas.bind("<Button-1>", self._toggle)
        self.canvas.bind("<Enter>", self._on_enter)
        self.canvas.bind("<Leave>", self._on_leave)
        self.variable.trace_add("write", lambda *args: self._on_var_change())

    def _on_var_change(self):
        on = self.variable.get()
        self._status_label.configure(
            text="On" if on else "Off",
            fg=Theme.SUCCESS if on else Theme.TEXT_MUTED,
        )
        self._animate_to_state()

    def _draw(self):
        self.canvas.delete("all")
        w, h = self._track_w, self._track_h
        r = h // 2

        on = self.variable.get()
        if on:
            track_color = Theme.TOGGLE_ON_HOVER if self._hovering else Theme.TOGGLE_ON
        else:
            track_color = Theme.TOGGLE_OFF_HOVER if self._hovering else Theme.TOGGLE_OFF

        self._draw_rounded_rect(0, 0, w, h, r, fill=track_color, outline="")

        cx = self._current_x
        cy = h / 2
        kr = self._knob_r

        self.canvas.create_oval(
            cx - kr, cy - kr, cx + kr, cy + kr,
            fill=Theme.TOGGLE_KNOB, outline="",
        )

    def _draw_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.canvas.create_polygon(points, smooth=True, **kwargs)

    def _toggle(self, event):
        if not self._animating:
            self.variable.set(not self.variable.get())

    def _on_enter(self, event):
        self._hovering = True
        self.canvas.configure(cursor="hand2")
        self._draw()

    def _on_leave(self, event):
        self._hovering = False
        self._draw()

    def _animate_to_state(self):
        target = self._on_x if self.variable.get() else self._off_x
        if abs(self._current_x - target) < 1:
            self._current_x = target
            self._draw()
            return
        self._animating = True
        step = (target - self._current_x) / self._ANIM_STEPS
        self._animate_step(target, step, 0)

    def _animate_step(self, target: float, step: float, count: int):
        if count >= self._ANIM_STEPS:
            self._current_x = target
            self._animating = False
            self._draw()
            return
        self._current_x += step
        self._draw()
        self.after(self._ANIM_DELAY, lambda: self._animate_step(target, step, count + 1))


# Add rounded rectangle method to Canvas
def _create_rounded_rect(self, x1, y1, x2, y2, radius, **kwargs):
    points = [
        x1 + radius, y1, x2 - radius, y1, x2, y1, x2, y1 + radius,
        x2, y2 - radius, x2, y2, x2 - radius, y2, x1 + radius, y2,
        x1, y2, x1, y2 - radius, x1, y1 + radius, x1, y1,
    ]
    return self.create_polygon(points, smooth=True, **kwargs)

tk.Canvas.create_rounded_rect = _create_rounded_rect


class StatusBadge(tk.Frame):
    """A status badge showing active/inactive state with pulsing dot."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        self._pulse_active = False

        self.canvas = tk.Canvas(
            self, width=12, height=12,
            bg=Theme.BG_PRIMARY, highlightthickness=0,
        )
        self.canvas.pack(side="left", padx=(0, 8))

        self.label = tk.Label(
            self, text="Inactive",
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_MUTED,
            font=(Theme.FONT, 10),
        )
        self.label.pack(side="left")

        self._glow = self.canvas.create_oval(0, 0, 12, 12, fill="", outline="")
        self._indicator = self.canvas.create_oval(2, 2, 10, 10, fill=Theme.TEXT_MUTED, outline="")

    def set_active(self, active: bool, text: str = None):
        color = Theme.STATUS_ACTIVE if active else Theme.TEXT_MUTED
        glow = Theme.SUCCESS_LIGHT if active else ""
        self.canvas.itemconfig(self._indicator, fill=color)
        self.canvas.itemconfig(self._glow, fill=glow)
        self.label.configure(
            text=text or ("Active" if active else "Inactive"),
            fg=Theme.SUCCESS if active else Theme.TEXT_MUTED,
        )
        if active and not self._pulse_active:
            self._pulse_active = True
            self._pulse(0)
        elif not active:
            self._pulse_active = False
            self.canvas.itemconfig(self._glow, fill="")

    def _pulse(self, step: int):
        if not self._pulse_active:
            return
        if step % 40 < 20:
            self.canvas.itemconfig(self._glow, fill=Theme.SUCCESS_LIGHT)
        else:
            self.canvas.itemconfig(self._glow, fill="")
        self.after(100, lambda: self._pulse(step + 1))


# =============================================================================
# Main Application
# =============================================================================

class EmailMonitorApp:
    """Main application class for E2NB GUI."""

    # Page metadata: key -> (title, section)
    PAGE_META = {
        "email":    ("Email Settings",   "Configuration"),
        "settings": ("General Settings", "Configuration"),
        "sms":      ("Twilio SMS",       "Notifications"),
        "voice":    ("Twilio Voice",     "Notifications"),
        "whatsapp": ("WhatsApp",         "Notifications"),
        "slack":    ("Slack",            "Notifications"),
        "telegram": ("Telegram",         "Notifications"),
        "discord":  ("Discord",          "Notifications"),
        "webhook":  ("Custom Webhook",   "Notifications"),
        "logs":     ("Activity Logs",    "Monitor"),
    }

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("E2NB - Email to Notification Blaster")
        self.root.minsize(940, 640)
        # Launch at maximum windowed size (not fullscreen)
        self.root.state("zoomed")
        self.root.configure(bg=Theme.BG_PRIMARY)

        try:
            self.root.iconbitmap(default="")
        except tk.TclError:
            pass

        # Configure ttk widgets
        configure_ttk_style()

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
        self._create_status_bar()

        # Toast system
        self.toast = Toast(self.content)

        # Show initial page
        self._show_page("email")

        # Start log processing
        self._process_log_queue()

        # Keyboard shortcuts
        self.root.bind("<Control-s>", lambda e: self._save_settings())
        self.root.bind("<Control-l>", lambda e: self._show_page("logs"))

        # Handle close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Initial badge count
        self._update_services_badge()

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

        # Track changes to service toggles
        for var in self._service_vars():
            var.trace_add("write", lambda *a: self._update_services_badge())

    def _service_vars(self) -> list:
        return [
            self.twilio_sms_var, self.voice_var, self.whatsapp_var,
            self.slack_var, self.telegram_var, self.discord_var,
            self.webhook_var,
        ]

    def _update_services_badge(self):
        if hasattr(self, '_services_badge'):
            count = sum(1 for v in self._service_vars() if v.get())
            self._services_badge.update_count(count)

    def _create_layout(self):
        """Create the main layout structure."""
        # Sidebar
        self.sidebar = tk.Frame(self.root, bg=Theme.SIDEBAR_BG, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Main content area
        self.main_area = tk.Frame(self.root, bg=Theme.BG_PRIMARY)
        self.main_area.pack(side="left", fill="both", expand=True)

        # Header
        self.header = tk.Frame(self.main_area, bg=Theme.BG_PRIMARY, height=80)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)

        # Header bottom border
        tk.Frame(self.main_area, bg=Theme.BORDER, height=1).pack(fill="x")

        # Content container
        self.content = tk.Frame(self.main_area, bg=Theme.BG_SECONDARY)
        self.content.pack(fill="both", expand=True, padx=0, pady=0)

        # Global mousewheel handler — routes scroll events to whichever
        # scrollable area (sidebar or content page) the cursor is over.
        self._active_scroll_canvas = None

        def _on_global_mousewheel(event):
            if self._active_scroll_canvas:
                self._active_scroll_canvas.yview_scroll(
                    int(-1 * (event.delta / 120)), "units"
                )

        self.root.bind_all("<MouseWheel>", _on_global_mousewheel)

    def _create_sidebar(self):
        """Create the sidebar navigation with scrollable nav area."""
        # Logo area (fixed at top)
        title_frame = tk.Frame(self.sidebar, bg=Theme.SIDEBAR_BG)
        title_frame.pack(fill="x", pady=(20, 4))

        tk.Label(
            title_frame, text="E2NB",
            bg=Theme.SIDEBAR_BG, fg="#ffffff",
            font=(Theme.FONT, 18, "bold"), padx=20,
        ).pack(anchor="w")

        tk.Label(
            title_frame, text=f"v{__version__}",
            bg=Theme.SIDEBAR_BG, fg=Theme.SIDEBAR_SECTION,
            font=(Theme.FONT, 9), padx=20,
        ).pack(anchor="w")

        # Scrollable navigation area (fills remaining space)
        self._sb_canvas = tk.Canvas(
            self.sidebar, bg=Theme.SIDEBAR_BG, highlightthickness=0,
        )
        self._sb_canvas.pack(fill="both", expand=True)

        nav = tk.Frame(self._sb_canvas, bg=Theme.SIDEBAR_BG)
        sb_canvas_win = self._sb_canvas.create_window(
            (0, 0), window=nav, anchor="nw",
        )

        def _on_sb_canvas_config(event):
            self._sb_canvas.itemconfigure(sb_canvas_win, width=event.width)
        self._sb_canvas.bind("<Configure>", _on_sb_canvas_config)

        nav.bind("<Configure>", lambda e: self._sb_canvas.configure(
            scrollregion=self._sb_canvas.bbox("all"),
        ))

        # Route mousewheel to sidebar when cursor is over it
        def _enter_sb(event):
            self._active_scroll_canvas = self._sb_canvas
        def _leave_sb(event):
            if self._active_scroll_canvas is self._sb_canvas:
                self._active_scroll_canvas = None
        self._sb_canvas.bind("<Enter>", _enter_sb)
        self._sb_canvas.bind("<Leave>", _leave_sb)

        # Configuration section
        SidebarSection(nav, "Configuration").pack(fill="x")

        nav_items = [
            ("email", "Email Settings", 0, None, "Configure IMAP server and credentials"),
            ("settings", "General", 0, None, "Monitoring interval and SMS settings"),
        ]
        for key, text, indent, var, tip in nav_items:
            item = SidebarItem(
                nav, text, lambda k=key: self._show_page(k),
                indent, status_var=var, tooltip=tip,
            )
            item.pack(fill="x")
            self.nav_items[key] = item

        # Notifications section
        SidebarSection(nav, "Notifications").pack(fill="x")

        notification_items = [
            ("sms", "Twilio SMS", 0, self.twilio_sms_var, "SMS notifications via Twilio"),
            ("voice", "Twilio Voice", 0, self.voice_var, "Voice call notifications"),
            ("whatsapp", "WhatsApp", 0, self.whatsapp_var, "WhatsApp messages via Twilio"),
            ("slack", "Slack", 0, self.slack_var, "Slack channel notifications"),
            ("telegram", "Telegram", 0, self.telegram_var, "Telegram bot messages"),
            ("discord", "Discord", 0, self.discord_var, "Discord webhook notifications"),
            ("webhook", "Webhook", 0, self.webhook_var, "Custom HTTP webhook"),
        ]
        for key, text, indent, var, tip in notification_items:
            item = SidebarItem(
                nav, text, lambda k=key: self._show_page(k),
                indent, status_var=var, tooltip=tip,
            )
            item.pack(fill="x")
            self.nav_items[key] = item

        # Services badge
        self._services_badge = SidebarBadge(nav)
        self._services_badge.pack(fill="x", pady=(4, 0))

        # Monitor section
        SidebarSection(nav, "Monitor").pack(fill="x")

        item = SidebarItem(
            nav, "Logs",
            lambda: self._show_page("logs"),
            0, tooltip="View monitoring activity logs (Ctrl+L)",
        )
        item.pack(fill="x")
        self.nav_items["logs"] = item

        # Keyboard shortcut hints (at end of scrollable area)
        hints_frame = tk.Frame(nav, bg=Theme.SIDEBAR_BG)
        hints_frame.pack(fill="x", pady=(12, 16))

        for shortcut, desc in [("Ctrl+S", "Save"), ("Ctrl+L", "Logs")]:
            row = tk.Frame(hints_frame, bg=Theme.SIDEBAR_BG)
            row.pack(fill="x", padx=20, pady=1)
            tk.Label(
                row, text=shortcut,
                bg=Theme.SIDEBAR_BADGE_BG, fg=Theme.SIDEBAR_BADGE_FG,
                font=(Theme.FONT_MONO, 8), padx=4, pady=1,
            ).pack(side="left")
            tk.Label(
                row, text=desc,
                bg=Theme.SIDEBAR_BG, fg=Theme.SIDEBAR_SECTION,
                font=(Theme.FONT, 8), padx=6,
            ).pack(side="left")

    def _create_header(self):
        """Create the header with breadcrumb, status, and controls."""
        left = tk.Frame(self.header, bg=Theme.BG_PRIMARY)
        left.pack(side="left", padx=32, pady=12)

        # Breadcrumb (section label)
        self._breadcrumb = tk.Label(
            left, text="Configuration",
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_MUTED,
            font=(Theme.FONT, 9),
        )
        self._breadcrumb.pack(anchor="w")

        # Page title
        self.page_title = tk.Label(
            left, text="Email Settings",
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_PRIMARY,
            font=(Theme.FONT, 16, "bold"),
        )
        self.page_title.pack(anchor="w", pady=(2, 0))

        # Status badge
        self.status_badge = StatusBadge(left)
        self.status_badge.pack(anchor="w", pady=(2, 0))

        # Right side - buttons
        right = tk.Frame(self.header, bg=Theme.BG_PRIMARY)
        right.pack(side="right", padx=32, pady=16)

        self.stop_btn = ModernButton(
            right, text="Stop",
            command=self._stop_monitoring,
            bg=Theme.ERROR, hover_bg=Theme.ERROR_HOVER,
            tooltip="Stop email monitoring",
        )
        self.stop_btn.pack(side="right", padx=(8, 0))
        self.stop_btn.configure_state("disabled")

        self.start_btn = ModernButton(
            right, text="Start Monitoring",
            command=self._start_monitoring,
            bg=Theme.SUCCESS, hover_bg=Theme.SUCCESS_HOVER,
            bold=True, tooltip="Begin monitoring for new emails",
        )
        self.start_btn.pack(side="right", padx=(8, 0))

        self.save_btn = ModernButton(
            right, text="Save",
            command=self._save_settings,
            bg=Theme.PRIMARY, hover_bg=Theme.PRIMARY_HOVER,
            tooltip="Save all settings to config.ini (Ctrl+S)",
        )
        self.save_btn.pack(side="right")

    def _create_status_bar(self):
        """Create a status bar at the bottom."""
        self.status_bar = tk.Frame(self.main_area, bg=Theme.BG_TERTIARY, height=28)
        self.status_bar.pack(side="bottom", fill="x")
        self.status_bar.pack_propagate(False)

        # Top border
        tk.Frame(self.status_bar, bg=Theme.BORDER, height=1).pack(fill="x")

        inner = tk.Frame(self.status_bar, bg=Theme.BG_TERTIARY)
        inner.pack(fill="both", expand=True, padx=16)

        self._status_text = tk.Label(
            inner, text="Ready",
            bg=Theme.BG_TERTIARY, fg=Theme.TEXT_MUTED,
            font=(Theme.FONT, 8), anchor="w",
        )
        self._status_text.pack(side="left", pady=2)

        self._status_right = tk.Label(
            inner, text="",
            bg=Theme.BG_TERTIARY, fg=Theme.TEXT_MUTED,
            font=(Theme.FONT, 8), anchor="e",
        )
        self._status_right.pack(side="right", pady=2)

    def _update_status_bar(self, text: str, right_text: str = ""):
        self._status_text.configure(text=text)
        self._status_right.configure(text=right_text)

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
        """Create a scrollable page container with max-width content."""
        container = tk.Frame(self.content, bg=Theme.BG_SECONDARY)

        canvas = tk.Canvas(container, bg=Theme.BG_SECONDARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)

        # Outer scrollable frame
        scrollable_outer = tk.Frame(canvas, bg=Theme.BG_SECONDARY)
        scrollable_outer.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas_window = canvas.create_window((0, 0), window=scrollable_outer, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Max-width inner container (centered)
        inner = tk.Frame(scrollable_outer, bg=Theme.BG_SECONDARY)
        inner.pack(fill="x", expand=True, padx=36, pady=28)

        # Route mousewheel to this content canvas when cursor is over it
        def _enter_content(event):
            self._active_scroll_canvas = canvas
        def _leave_content(event):
            if self._active_scroll_canvas is canvas:
                self._active_scroll_canvas = None
        canvas.bind("<Enter>", _enter_content)
        canvas.bind("<Leave>", _leave_content)

        # Keep scrollable frame width matched to canvas
        def _on_canvas_configure(event):
            canvas.itemconfigure(canvas_window, width=event.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        self.pages[name] = container
        return inner

    def _create_separator(self, parent):
        sep = tk.Frame(parent, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")

    def _create_email_page(self):
        page = self._create_scrollable_page("email")

        section = FormSection(page, "IMAP Server", "Configure your email server connection")
        section.pack(fill="x", pady=(0, 24))

        self.imap_server = FormRow(
            section.content, "Server", "e.g., imap.gmail.com",
            tooltip="Hostname of your IMAP email server",
        )
        self.imap_server.pack(fill="x")
        self.imap_server.set(self.config.get('Email', 'imap_server', fallback='imap.gmail.com'))

        self._create_separator(section.content)

        self.imap_port = FormRow(
            section.content, "Port", "Usually 993 for SSL",
            tooltip="IMAP port number (993 for SSL/TLS)",
        )
        self.imap_port.pack(fill="x")
        self.imap_port.set(self.config.get('Email', 'imap_port', fallback='993'))

        section2 = FormSection(page, "Credentials", "Your email login details")
        section2.pack(fill="x", pady=(0, 24))

        self.username = FormRow(
            section2.content, "Email", "Your email address",
            tooltip="Full email address for IMAP login",
        )
        self.username.pack(fill="x")
        self.username.set(self.config.get('Email', 'username', fallback=''))

        self._create_separator(section2.content)

        self.password = FormRow(
            section2.content, "Password", "App password if 2FA enabled", show="*",
            tooltip="Use an app-specific password if 2FA is enabled",
        )
        self.password.pack(fill="x")
        self.password.set(self.config.get('Email', 'password', fallback=''))

        btn_frame = tk.Frame(page, bg=Theme.BG_SECONDARY)
        btn_frame.pack(fill="x", pady=(0, 24))

        ModernButton(
            btn_frame, text="Test Connection",
            command=self._test_connection,
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_PRIMARY,
            hover_bg=Theme.BG_TERTIARY,
            tooltip="Verify IMAP server connection",
        ).pack(side="left")

        section3 = FormSection(page, "Email Filters", "Only process emails matching these filters (optional)")
        section3.pack(fill="x")

        self.filters = FormRow(
            section3.content, "Filter", "Comma-separated addresses or @domains",
            tooltip="e.g., alerts@example.com, @company.com",
        )
        self.filters.pack(fill="x")
        self.filters.set(self.config.get('Email', 'filter_emails', fallback=''))

    def _create_settings_page(self):
        page = self._create_scrollable_page("settings")

        section = FormSection(page, "Monitoring Settings", "Control how often emails are checked")
        section.pack(fill="x", pady=(0, 24))

        self.check_interval = FormRow(
            section.content, "Check Interval", "Seconds between checks",
            tooltip="How frequently to check for new emails (in seconds)",
        )
        self.check_interval.pack(fill="x")
        self.check_interval.set(self.config.get('Settings', 'check_interval', fallback='60'))

        self._create_separator(section.content)

        self.max_sms = FormRow(
            section.content, "Max SMS Length", "Character limit for SMS",
            tooltip="Messages longer than this will be truncated",
        )
        self.max_sms.pack(fill="x")
        self.max_sms.set(self.config.get('Settings', 'max_sms_length', fallback='1600'))

    def _create_notification_page(self, name, toggle_text, toggle_var, sections):
        page = self._create_scrollable_page(name)

        toggle_frame = tk.Frame(
            page, bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.CARD_BORDER, highlightthickness=1,
        )
        toggle_frame.pack(fill="x", pady=(0, 24))
        ToggleSwitch(toggle_frame, toggle_text, toggle_var).pack(fill="x")

        created_rows = {}
        for section_title, section_desc, rows in sections:
            section = FormSection(page, section_title, section_desc)
            section.pack(fill="x", pady=(0, 24))
            for i, (key, label, help_text, show, tip) in enumerate(rows):
                if i > 0:
                    self._create_separator(section.content)
                row = FormRow(section.content, label, help_text, show=show, tooltip=tip)
                row.pack(fill="x")
                created_rows[key] = row
        return created_rows

    def _create_sms_page(self):
        rows = self._create_notification_page(
            "sms", "Enable SMS Notifications", self.twilio_sms_var,
            [
                ("Twilio Credentials", "Your Twilio account details", [
                    ("sms_sid", "Account SID", "From Twilio Console", "", "Find this on your Twilio dashboard"),
                    ("sms_token", "Auth Token", "From Twilio Console", "*", "Keep this secret"),
                ]),
                ("Phone Numbers", "SMS sender and recipient numbers", [
                    ("sms_from", "From Number", "Your Twilio number", "", "Must be a valid Twilio phone number"),
                    ("sms_to", "To Number(s)", "Comma-separated", "", "Recipients for SMS notifications"),
                ]),
            ],
        )
        self.sms_sid = rows["sms_sid"]
        self.sms_sid.set(self.config.get('Twilio', 'account_sid', fallback=''))
        self.sms_token = rows["sms_token"]
        self.sms_token.set(self.config.get('Twilio', 'auth_token', fallback=''))
        self.sms_from = rows["sms_from"]
        self.sms_from.set(self.config.get('Twilio', 'from_number', fallback=''))
        self.sms_to = rows["sms_to"]
        self.sms_to.set(self.config.get('Twilio', 'destination_number', fallback=''))

    def _create_voice_page(self):
        rows = self._create_notification_page(
            "voice", "Enable Voice Calls", self.voice_var,
            [
                ("Twilio Credentials", "Your Twilio account details", [
                    ("voice_sid", "Account SID", "From Twilio Console", "", "Find this on your Twilio dashboard"),
                    ("voice_token", "Auth Token", "From Twilio Console", "*", "Keep this secret"),
                ]),
                ("Phone Numbers", "Voice call sender and recipient numbers", [
                    ("voice_from", "From Number", "Your Twilio number", "", "Must be a valid Twilio phone number"),
                    ("voice_to", "To Number(s)", "Comma-separated", "", "Recipients for voice call notifications"),
                ]),
            ],
        )
        self.voice_sid = rows["voice_sid"]
        self.voice_sid.set(self.config.get('Voice', 'account_sid', fallback=''))
        self.voice_token = rows["voice_token"]
        self.voice_token.set(self.config.get('Voice', 'auth_token', fallback=''))
        self.voice_from = rows["voice_from"]
        self.voice_from.set(self.config.get('Voice', 'from_number', fallback=''))
        self.voice_to = rows["voice_to"]
        self.voice_to.set(self.config.get('Voice', 'destination_number', fallback=''))

    def _create_whatsapp_page(self):
        rows = self._create_notification_page(
            "whatsapp", "Enable WhatsApp", self.whatsapp_var,
            [
                ("Twilio Credentials", "Your Twilio account details", [
                    ("wa_sid", "Account SID", "From Twilio Console", "", "Find this on your Twilio dashboard"),
                    ("wa_token", "Auth Token", "From Twilio Console", "*", "Keep this secret"),
                ]),
                ("WhatsApp Numbers", "WhatsApp sender and recipient", [
                    ("wa_from", "From", "e.g., whatsapp:+14155238886", "", "Twilio WhatsApp sandbox or approved number"),
                    ("wa_to", "To", "e.g., whatsapp:+1234567890", "", "Recipient WhatsApp number"),
                ]),
            ],
        )
        self.wa_sid = rows["wa_sid"]
        self.wa_sid.set(self.config.get('WhatsApp', 'account_sid', fallback=''))
        self.wa_token = rows["wa_token"]
        self.wa_token.set(self.config.get('WhatsApp', 'auth_token', fallback=''))
        self.wa_from = rows["wa_from"]
        self.wa_from.set(self.config.get('WhatsApp', 'from_number', fallback=''))
        self.wa_to = rows["wa_to"]
        self.wa_to.set(self.config.get('WhatsApp', 'to_number', fallback=''))

    def _create_slack_page(self):
        rows = self._create_notification_page(
            "slack", "Enable Slack", self.slack_var,
            [
                ("Slack Configuration", "Bot token and channel settings", [
                    ("slack_token", "Bot Token", "Starts with xoxb-", "*", "Create a Slack app and get the bot token"),
                    ("slack_channel", "Channel", "e.g., #notifications", "", "Channel where messages will be posted"),
                ]),
            ],
        )
        self.slack_token = rows["slack_token"]
        self.slack_token.set(self.config.get('Slack', 'token', fallback=''))
        self.slack_channel = rows["slack_channel"]
        self.slack_channel.set(self.config.get('Slack', 'channel', fallback=''))

    def _create_telegram_page(self):
        rows = self._create_notification_page(
            "telegram", "Enable Telegram", self.telegram_var,
            [
                ("Telegram Bot Configuration", "Bot token and chat settings", [
                    ("tg_token", "Bot Token", "From @BotFather", "*", "Create a bot via @BotFather on Telegram"),
                    ("tg_chat", "Chat ID", "From @userinfobot", "", "Get your chat ID from @userinfobot"),
                ]),
            ],
        )
        self.tg_token = rows["tg_token"]
        self.tg_token.set(self.config.get('Telegram', 'bot_token', fallback=''))
        self.tg_chat = rows["tg_chat"]
        self.tg_chat.set(self.config.get('Telegram', 'chat_id', fallback=''))

    def _create_discord_page(self):
        rows = self._create_notification_page(
            "discord", "Enable Discord", self.discord_var,
            [
                ("Discord Webhook", "Webhook URL from channel integrations", [
                    ("discord_url", "Webhook URL", "From channel integrations", "", "Create a webhook in Discord channel settings"),
                ]),
            ],
        )
        self.discord_url = rows["discord_url"]
        self.discord_url.set(self.config.get('Discord', 'webhook_url', fallback=''))

    def _create_webhook_page(self):
        rows = self._create_notification_page(
            "webhook", "Enable Custom Webhook", self.webhook_var,
            [
                ("Webhook Configuration", "Custom HTTP POST endpoint", [
                    ("webhook_url", "URL", "POST endpoint", "", "Receives JSON: {subject, body, sender, timestamp}"),
                ]),
            ],
        )
        self.webhook_url = rows["webhook_url"]
        self.webhook_url.set(self.config.get('CustomWebhook', 'webhook_url', fallback=''))

    def _create_logs_page(self):
        page = tk.Frame(self.content, bg=Theme.BG_SECONDARY)
        self.pages["logs"] = page

        # Toolbar
        toolbar = tk.Frame(page, bg=Theme.BG_SECONDARY)
        toolbar.pack(fill="x", padx=36, pady=(24, 12))

        ModernButton(
            toolbar, text="Clear Logs",
            command=self._clear_logs,
            bg=Theme.BG_PRIMARY, fg=Theme.TEXT_PRIMARY,
            hover_bg=Theme.BG_TERTIARY, font_size=9, padx=14, pady=6,
            tooltip="Clear all log entries",
        ).pack(side="left")

        ttk.Checkbutton(
            toolbar, text="Auto-scroll",
            variable=self.auto_scroll_var,
        ).pack(side="left", padx=(16, 0))

        # Log text
        log_container = tk.Frame(page, bg=Theme.LOG_BG, highlightbackground="#1e293b", highlightthickness=1)
        log_container.pack(fill="both", expand=True, padx=36, pady=(0, 24))

        self.log_text = scrolledtext.ScrolledText(
            log_container,
            font=(Theme.FONT_MONO, 10),
            bg=Theme.LOG_BG, fg=Theme.LOG_FG,
            insertbackground=Theme.LOG_FG,
            relief="flat", wrap="word", state="disabled",
            padx=16, pady=16,
            selectbackground=Theme.PRIMARY,
            selectforeground="#ffffff",
            spacing3=2,
        )
        self.log_text.pack(fill="both", expand=True)

        self.log_text.tag_configure('INFO', foreground=Theme.LOG_INFO)
        self.log_text.tag_configure('WARNING', foreground=Theme.LOG_WARNING)
        self.log_text.tag_configure('ERROR', foreground=Theme.LOG_ERROR)
        self.log_text.tag_configure('SUCCESS', foreground=Theme.LOG_SUCCESS)
        self.log_text.tag_configure('TIMESTAMP', foreground=Theme.LOG_TIMESTAMP)

        # Empty state
        self._log_empty = tk.Label(
            log_container,
            text="No log entries yet.\nStart monitoring to see activity here.",
            bg=Theme.LOG_BG, fg=Theme.LOG_TIMESTAMP,
            font=(Theme.FONT, 11), justify="center",
        )
        self._log_empty.place(relx=0.5, rely=0.4, anchor="center")

    def _show_page(self, name: str):
        for key, item in self.nav_items.items():
            item.set_active(key == name)

        for page in self.pages.values():
            page.pack_forget()

        if name in self.pages:
            self.pages[name].pack(fill="both", expand=True)

        meta = self.PAGE_META.get(name, (name.title(), ""))
        self.page_title.configure(text=meta[0])
        self._breadcrumb.configure(text=meta[1])
        self.current_page = name

    def _log(self, message: str, level: str = "INFO"):
        self.log_queue.put((message, level))

    def _process_log_queue(self):
        try:
            while True:
                message, level = self.log_queue.get_nowait()
                self._append_log(message, level)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._process_log_queue)

    def _append_log(self, message: str, level: str = "INFO"):
        # Hide empty state
        if hasattr(self, '_log_empty') and self._log_empty.winfo_exists():
            self._log_empty.place_forget()

        timestamp = datetime.now().strftime('%H:%M:%S')

        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] ", 'TIMESTAMP')
        self.log_text.insert(tk.END, f"{level}: ", level)
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.configure(state='disabled')

        if self.auto_scroll_var.get():
            self.log_text.see(tk.END)

    def _clear_logs(self):
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')
        # Show empty state again
        if hasattr(self, '_log_empty'):
            self._log_empty.place(relx=0.5, rely=0.4, anchor="center")

    def _update_config(self):
        self.config['Email']['imap_server'] = self.imap_server.get()
        self.config['Email']['imap_port'] = self.imap_port.get()
        self.config['Email']['username'] = self.username.get()
        self.config['Email']['password'] = self.password.get()
        self.config['Email']['filter_emails'] = self.filters.get()

        self.config['Settings']['check_interval'] = self.check_interval.get()
        self.config['Settings']['max_sms_length'] = self.max_sms.get()

        self.config['Twilio']['enabled'] = str(self.twilio_sms_var.get())
        self.config['Voice']['enabled'] = str(self.voice_var.get())
        self.config['WhatsApp']['enabled'] = str(self.whatsapp_var.get())
        self.config['Slack']['enabled'] = str(self.slack_var.get())
        self.config['Telegram']['enabled'] = str(self.telegram_var.get())
        self.config['Discord']['enabled'] = str(self.discord_var.get())
        self.config['CustomWebhook']['enabled'] = str(self.webhook_var.get())

        self.config['Twilio']['account_sid'] = self.sms_sid.get()
        self.config['Twilio']['auth_token'] = self.sms_token.get()
        self.config['Twilio']['from_number'] = self.sms_from.get()
        self.config['Twilio']['destination_number'] = self.sms_to.get()

        self.config['Voice']['account_sid'] = self.voice_sid.get()
        self.config['Voice']['auth_token'] = self.voice_token.get()
        self.config['Voice']['from_number'] = self.voice_from.get()
        self.config['Voice']['destination_number'] = self.voice_to.get()

        self.config['WhatsApp']['account_sid'] = self.wa_sid.get()
        self.config['WhatsApp']['auth_token'] = self.wa_token.get()
        self.config['WhatsApp']['from_number'] = self.wa_from.get()
        self.config['WhatsApp']['to_number'] = self.wa_to.get()

        self.config['Slack']['token'] = self.slack_token.get()
        self.config['Slack']['channel'] = self.slack_channel.get()

        self.config['Telegram']['bot_token'] = self.tg_token.get()
        self.config['Telegram']['chat_id'] = self.tg_chat.get()

        self.config['Discord']['webhook_url'] = self.discord_url.get()

        self.config['CustomWebhook']['webhook_url'] = self.webhook_url.get()

    def _save_settings(self):
        try:
            self._update_config()
            save_config(self.config)
            self._log("Settings saved", "SUCCESS")
            self.toast.show("Settings saved to config.ini", "success")
            self._update_status_bar("Settings saved", datetime.now().strftime('%H:%M:%S'))
        except Exception as e:
            self._log(f"Save failed: {e}", "ERROR")
            self.toast.show(f"Save failed: {e}", "error")

    def _test_connection(self):
        self._log("Testing connection...", "INFO")
        self._update_status_bar("Testing IMAP connection...")

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
        if success:
            self._log(message, "SUCCESS")
            self.toast.show(message, "success")
            self._update_status_bar("Connection test passed")
        else:
            self._log(f"Failed: {message}", "ERROR")
            self.toast.show(f"Connection failed: {message}", "error")
            self._update_status_bar("Connection test failed")

    def _validate(self) -> bool:
        if not any(v.get() for v in self._service_vars()):
            self.toast.show("Enable at least one notification method.", "error")
            return False
        if not all([self.imap_server.get(), self.username.get(), self.password.get()]):
            self.toast.show("Fill in email settings first.", "error")
            return False
        return True

    def _start_monitoring(self):
        if not self._validate():
            return

        self._update_config()
        self.monitoring = True
        self.stop_event.clear()

        self.start_btn.configure_state("disabled")
        self.stop_btn.configure_state("normal")
        self.status_badge.set_active(True, "Monitoring")
        self._update_status_bar("Monitoring active")

        self._log("Monitoring started", "INFO")
        self.toast.show("Email monitoring started", "success")
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _stop_monitoring(self):
        self.monitoring = False
        self.stop_event.set()

        self.start_btn.configure_state("normal")
        self.stop_btn.configure_state("disabled")
        self.status_badge.set_active(False, "Stopped")
        self._update_status_bar("Monitoring stopped")

        self._log("Monitoring stopped", "INFO")

    def _monitor_loop(self):
        dispatcher = NotificationDispatcher(self.config)

        while not self.stop_event.is_set():
            imap = None
            try:
                interval = int(self.config.get('Settings', 'check_interval', fallback='60'))
                filters = [f.strip().lower() for f in self.config.get('Email', 'filter_emails', fallback='').split(',') if f.strip()]

                self.root.after(0, lambda: self._update_status_bar(
                    "Checking for new emails...",
                    datetime.now().strftime('%H:%M:%S'),
                ))

                imap = connect_to_imap(
                    self.config.get('Email', 'imap_server'),
                    int(self.config.get('Email', 'imap_port', fallback='993')),
                    self.config.get('Email', 'username'),
                    self.config.get('Email', 'password')
                )

                if not imap:
                    self._log(f"Connection failed. Retry in {interval}s", "WARNING")
                    self.root.after(0, lambda: self._update_status_bar("Connection failed, retrying..."))
                    self.stop_event.wait(interval)
                    continue

                emails = fetch_unread_emails(imap)
                self._log(f"Found {len(emails)} unread email(s)", "INFO")
                self.root.after(0, lambda n=len(emails): self._update_status_bar(
                    f"Monitoring active - {n} unread",
                    f"Last check: {datetime.now().strftime('%H:%M:%S')}",
                ))

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
