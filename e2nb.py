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
# DPI Awareness (Windows)
# =============================================================================

def enable_dpi_awareness():
    """Enable DPI awareness on Windows for crisp rendering on high-DPI displays."""
    if sys.platform == "win32":
        try:
            import ctypes
            # Try Windows 10+ per-monitor DPI awareness
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            try:
                # Fall back to system-level DPI awareness
                ctypes.windll.user32.SetProcessDPIAware()
            except (AttributeError, OSError):
                pass

enable_dpi_awareness()


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
    SIDEBAR_ACTIVE_BG = "rgba(59,130,246,0.15)"
    SIDEBAR_SECTION = "#64748b"
    SIDEBAR_DIVIDER = "#1e293b"

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

    # Shadows and depth (simulated with borders)
    CARD_BORDER = "#e2e8f0"
    CARD_SHADOW = "#f1f5f9"

    # Status indicator colors
    STATUS_ACTIVE = "#10b981"
    STATUS_INACTIVE = "#cbd5e1"

    # Font family
    FONT = "Segoe UI"
    FONT_MONO = "Consolas"


# =============================================================================
# Tooltip Widget
# =============================================================================

class Tooltip:
    """A tooltip widget that appears on hover over a target widget."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 400):
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
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4

        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")

        # Tooltip styling
        frame = tk.Frame(
            tw,
            bg=Theme.SIDEBAR_BG,
            highlightbackground=Theme.SIDEBAR_BG_SUBTLE,
            highlightthickness=1,
        )
        frame.pack()

        label = tk.Label(
            frame,
            text=self.text,
            bg=Theme.SIDEBAR_BG,
            fg="#e2e8f0",
            font=(Theme.FONT, 9),
            padx=8,
            pady=4,
            wraplength=250,
            justify="left",
        )
        label.pack()

    def _hide(self):
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None

    def update_text(self, text: str):
        self.text = text


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

        super().__init__(
            parent,
            width=self._width,
            height=self._height,
            bg=parent.cget("bg") if hasattr(parent, "cget") else Theme.BG_PRIMARY,
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
            2, 2, self._width - 2, self._height - 2,
            self._radius, fill=bg_color, outline=""
        )
        self.create_text(
            self._width // 2, self._height // 2,
            text=self._text, fill=fg, font=self._font
        )

    def _draw_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def _on_enter(self, event):
        if self._enabled:
            self._draw(self._hover_bg)
            self.configure(cursor="hand2")

    def _on_leave(self, event):
        if self._enabled:
            self._draw(self._bg)

    def _on_click(self, event):
        if self._enabled:
            # Pressed state - slightly darker
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

    @staticmethod
    def _darken_color(hex_color: str, amount: int = 20) -> str:
        """Darken a hex color by the given amount."""
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
        self._inner.pack(fill="x", padx=4, pady=1)

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
            pady=10,
        )
        self.label.pack(side="left", fill="x", expand=True)

        # Status dot (for notification services)
        if status_var is not None:
            self._status_canvas = tk.Canvas(
                self._inner,
                width=10,
                height=10,
                bg=Theme.SIDEBAR_BG,
                highlightthickness=0,
            )
            self._status_canvas.pack(side="right", padx=(0, 12))
            # Center vertically
            self._status_canvas.place(relx=1.0, rely=0.5, anchor="e", x=-12)
            self._status_dot = self._status_canvas.create_oval(
                1, 1, 9, 9,
                fill=Theme.STATUS_ACTIVE if status_var.get() else Theme.STATUS_INACTIVE,
                outline="",
            )
            # Update dot when variable changes
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
            for w in [self._inner, self.label, self._indicator_bar]:
                w.configure(bg=Theme.SIDEBAR_HOVER)
            if hasattr(self, '_status_canvas'):
                self._status_canvas.configure(bg=Theme.SIDEBAR_HOVER)

    def _on_leave(self, event):
        if not self.active:
            for w in [self._inner, self.label, self._indicator_bar]:
                w.configure(bg=Theme.SIDEBAR_BG)
            if hasattr(self, '_status_canvas'):
                self._status_canvas.configure(bg=Theme.SIDEBAR_BG)

    def set_active(self, active: bool):
        self.active = active
        if active:
            bg = Theme.SIDEBAR_HOVER
            self._indicator_bar.configure(bg=Theme.SIDEBAR_ACTIVE)
            self.label.configure(fg=Theme.SIDEBAR_TEXT_ACTIVE)
        else:
            bg = Theme.SIDEBAR_BG
            self._indicator_bar.configure(bg=Theme.SIDEBAR_BG)
            self.label.configure(fg=Theme.SIDEBAR_TEXT)

        for w in [self._inner, self.label]:
            w.configure(bg=bg)
        if hasattr(self, '_status_canvas'):
            self._status_canvas.configure(bg=bg)


class SidebarSection(tk.Frame):
    """A section header in the sidebar."""

    def __init__(self, parent, text: str, **kwargs):
        super().__init__(parent, bg=Theme.SIDEBAR_BG, **kwargs)

        # Divider line
        divider = tk.Frame(self, bg=Theme.SIDEBAR_DIVIDER, height=1)
        divider.pack(fill="x", padx=16, pady=(12, 0))

        self.label = tk.Label(
            self,
            text=text.upper(),
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_SECTION,
            font=(Theme.FONT, 8, "bold"),
            anchor="w",
        )
        self.label.pack(fill="x", padx=16, pady=(8, 4))


# =============================================================================
# Custom Widgets
# =============================================================================

class FormSection(tk.Frame):
    """A form section with title and card-like content area."""

    def __init__(self, parent, title: str, description: str = "", **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        # Title
        title_label = tk.Label(
            self,
            text=title,
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_PRIMARY,
            font=(Theme.FONT, 12, "bold"),
            anchor="w",
        )
        title_label.pack(fill="x", pady=(0, 2))

        # Optional description
        if description:
            desc_label = tk.Label(
                self,
                text=description,
                bg=Theme.BG_PRIMARY,
                fg=Theme.TEXT_MUTED,
                font=(Theme.FONT, 9),
                anchor="w",
            )
            desc_label.pack(fill="x", pady=(0, 8))
        else:
            spacer = tk.Frame(self, bg=Theme.BG_PRIMARY, height=8)
            spacer.pack(fill="x")

        # Content frame styled as card
        self.content = tk.Frame(
            self,
            bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.CARD_BORDER,
            highlightthickness=1,
        )
        self.content.pack(fill="x")


class FormRow(tk.Frame):
    """A single row in a form with label and input with focus states."""

    def __init__(
        self,
        parent,
        label: str,
        help_text: str = "",
        show: str = "",
        tooltip: str = "",
        **kwargs
    ):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        # Left side - label
        label_frame = tk.Frame(self, bg=Theme.BG_PRIMARY, width=180)
        label_frame.pack(side="left", fill="y", padx=(16, 0), pady=14)
        label_frame.pack_propagate(False)

        self._label_widget = tk.Label(
            label_frame,
            text=label,
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_LABEL,
            font=(Theme.FONT, 10),
            anchor="w",
        )
        self._label_widget.pack(anchor="w")

        if help_text:
            help_label = tk.Label(
                label_frame,
                text=help_text,
                bg=Theme.BG_PRIMARY,
                fg=Theme.TEXT_MUTED,
                font=(Theme.FONT, 9),
                anchor="w",
            )
            help_label.pack(anchor="w", pady=(2, 0))

        # Right side - entry with custom focus frame
        entry_container = tk.Frame(self, bg=Theme.BG_PRIMARY)
        entry_container.pack(side="left", fill="both", expand=True, padx=16, pady=14)

        # Wrapper frame that acts as the visible border
        self._entry_wrapper = tk.Frame(
            entry_container,
            bg=Theme.BORDER,
            highlightthickness=0,
        )
        self._entry_wrapper.pack(fill="x")

        self.entry = tk.Entry(
            self._entry_wrapper,
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
        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", self._on_focus_out)
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
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)


class ToggleSwitch(tk.Frame):
    """An animated toggle switch widget with smooth transitions."""

    _ANIM_STEPS = 6
    _ANIM_DELAY = 16  # ~60fps

    def __init__(self, parent, text: str, variable: tk.BooleanVar, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        self.variable = variable
        self._hovering = False
        self._animating = False

        # Label
        tk.Label(
            self,
            text=text,
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_PRIMARY,
            font=(Theme.FONT, 10),
            anchor="w",
        ).pack(side="left", padx=(16, 0), pady=12)

        # Toggle canvas
        self._track_w = 48
        self._track_h = 26
        self._knob_r = 9  # knob radius
        self._knob_pad = 3

        self.canvas = tk.Canvas(
            self,
            width=self._track_w,
            height=self._track_h,
            bg=Theme.BG_PRIMARY,
            highlightthickness=0,
        )
        self.canvas.pack(side="right", padx=16, pady=12)

        # Compute knob x positions
        self._off_x = self._knob_pad + self._knob_r + 1
        self._on_x = self._track_w - self._knob_pad - self._knob_r - 1
        self._current_x = float(self._on_x if variable.get() else self._off_x)

        self._draw()

        self.canvas.bind("<Button-1>", self._toggle)
        self.canvas.bind("<Enter>", self._on_enter)
        self.canvas.bind("<Leave>", self._on_leave)
        self.variable.trace_add("write", lambda *args: self._animate_to_state())

    def _draw(self):
        self.canvas.delete("all")
        w, h = self._track_w, self._track_h
        r = h // 2

        # Interpolate track color
        on = self.variable.get()
        if on:
            track_color = Theme.TOGGLE_ON_HOVER if self._hovering else Theme.TOGGLE_ON
        else:
            track_color = Theme.TOGGLE_OFF_HOVER if self._hovering else Theme.TOGGLE_OFF

        # Track (rounded rect)
        self._draw_rounded_rect(0, 0, w, h, r, fill=track_color, outline="")

        # Knob with subtle shadow
        cx = self._current_x
        cy = h / 2
        kr = self._knob_r

        # Shadow
        self.canvas.create_oval(
            cx - kr, cy - kr + 1, cx + kr, cy + kr + 1,
            fill="#00000010", outline="",
        )
        # Knob
        self.canvas.create_oval(
            cx - kr, cy - kr, cx + kr, cy + kr,
            fill=Theme.TOGGLE_KNOB, outline="",
        )

    def _draw_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1,
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


# Add rounded rectangle method to Canvas (used by StatusBadge)
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
    """A status badge showing active/inactive state with pulsing dot."""

    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=Theme.BG_PRIMARY, **kwargs)

        self._pulse_active = False

        self.canvas = tk.Canvas(
            self,
            width=12,
            height=12,
            bg=Theme.BG_PRIMARY,
            highlightthickness=0,
        )
        self.canvas.pack(side="left", padx=(0, 8))

        self.label = tk.Label(
            self,
            text="Inactive",
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_MUTED,
            font=(Theme.FONT, 10),
        )
        self.label.pack(side="left")

        # Draw indicator dot
        self._glow = self.canvas.create_oval(0, 0, 12, 12, fill="", outline="")
        self._indicator = self.canvas.create_oval(2, 2, 10, 10, fill=Theme.TEXT_MUTED, outline="")

    def set_active(self, active: bool, text: str = None):
        color = Theme.STATUS_ACTIVE if active else Theme.TEXT_MUTED
        glow_color = Theme.SUCCESS_LIGHT if active else ""
        self.canvas.itemconfig(self._indicator, fill=color)
        self.canvas.itemconfig(self._glow, fill=glow_color)
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
        # Subtle pulse by toggling glow visibility
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

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"E2NB - Email to Notification Blaster")
        self.root.geometry("1050x720")
        self.root.minsize(920, 620)
        self.root.configure(bg=Theme.BG_PRIMARY)

        # Try to set a better icon on Windows
        try:
            self.root.iconbitmap(default="")
        except tk.TclError:
            pass

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
        self.sidebar = tk.Frame(self.root, bg=Theme.SIDEBAR_BG, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Main content area
        self.main_area = tk.Frame(self.root, bg=Theme.BG_PRIMARY)
        self.main_area.pack(side="left", fill="both", expand=True)

        # Header in main area
        self.header = tk.Frame(self.main_area, bg=Theme.BG_PRIMARY, height=76)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)

        # Subtle header bottom border
        header_border = tk.Frame(self.main_area, bg=Theme.BORDER, height=1)
        header_border.pack(fill="x")

        # Content container
        self.content = tk.Frame(self.main_area, bg=Theme.BG_SECONDARY)
        self.content.pack(fill="both", expand=True, padx=0, pady=0)

    def _create_sidebar(self):
        """Create the sidebar navigation."""
        # Logo/Title area
        title_frame = tk.Frame(self.sidebar, bg=Theme.SIDEBAR_BG)
        title_frame.pack(fill="x", pady=(24, 8))

        tk.Label(
            title_frame,
            text="E2NB",
            bg=Theme.SIDEBAR_BG,
            fg="#ffffff",
            font=(Theme.FONT, 18, "bold"),
            padx=20,
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text=f"v{__version__}",
            bg=Theme.SIDEBAR_BG,
            fg=Theme.SIDEBAR_SECTION,
            font=(Theme.FONT, 9),
            padx=20,
        ).pack(anchor="w")

        # Navigation sections
        SidebarSection(self.sidebar, "Configuration").pack(fill="x")

        nav_items = [
            ("email", "Email Settings", 0, None, "Configure IMAP server and credentials"),
            ("settings", "General", 0, None, "Monitoring interval and SMS settings"),
        ]

        for key, text, indent, var, tip in nav_items:
            item = SidebarItem(
                self.sidebar, text,
                lambda k=key: self._show_page(k),
                indent, status_var=var, tooltip=tip,
            )
            item.pack(fill="x")
            self.nav_items[key] = item

        SidebarSection(self.sidebar, "Notifications").pack(fill="x")

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
                self.sidebar, text,
                lambda k=key: self._show_page(k),
                indent, status_var=var, tooltip=tip,
            )
            item.pack(fill="x")
            self.nav_items[key] = item

        SidebarSection(self.sidebar, "Monitor").pack(fill="x")

        item = SidebarItem(
            self.sidebar, "Logs",
            lambda: self._show_page("logs"),
            0, tooltip="View monitoring activity logs",
        )
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
            font=(Theme.FONT, 15, "bold"),
        )
        self.page_title.pack(anchor="w")

        self.status_badge = StatusBadge(left)
        self.status_badge.pack(anchor="w", pady=(4, 0))

        # Right side - buttons
        right = tk.Frame(self.header, bg=Theme.BG_PRIMARY)
        right.pack(side="right", padx=32, pady=16)

        self.stop_btn = ModernButton(
            right,
            text="Stop",
            command=self._stop_monitoring,
            bg=Theme.ERROR,
            hover_bg=Theme.ERROR_HOVER,
            tooltip="Stop email monitoring",
        )
        self.stop_btn.pack(side="right", padx=(8, 0))
        self.stop_btn.configure_state("disabled")

        self.start_btn = ModernButton(
            right,
            text="Start Monitoring",
            command=self._start_monitoring,
            bg=Theme.SUCCESS,
            hover_bg=Theme.SUCCESS_HOVER,
            bold=True,
            tooltip="Begin monitoring for new emails",
        )
        self.start_btn.pack(side="right", padx=(8, 0))

        self.save_btn = ModernButton(
            right,
            text="Save",
            command=self._save_settings,
            bg=Theme.PRIMARY,
            hover_bg=Theme.PRIMARY_HOVER,
            tooltip="Save all settings to config.ini",
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
        container = tk.Frame(self.content, bg=Theme.BG_SECONDARY)

        canvas = tk.Canvas(container, bg=Theme.BG_SECONDARY, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable = tk.Frame(canvas, bg=Theme.BG_SECONDARY)

        scrollable.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=32, pady=24)
        scrollbar.pack(side="right", fill="y")

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Horizontal resize: keep the scrollable frame width matched to canvas
        def _on_canvas_configure(event):
            canvas.itemconfigure(canvas.find_withtag("all")[0], width=event.width)

        canvas.bind("<Configure>", _on_canvas_configure)

        self.pages[name] = container
        return scrollable

    def _create_separator(self, parent):
        """Create a styled separator line."""
        sep = tk.Frame(parent, bg=Theme.BORDER, height=1)
        sep.pack(fill="x")
        return sep

    def _create_email_page(self):
        """Create the email settings page."""
        page = self._create_scrollable_page("email")

        # IMAP Settings
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

        # Credentials
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

        # Test button
        btn_frame = tk.Frame(page, bg=Theme.BG_SECONDARY)
        btn_frame.pack(fill="x", pady=(0, 24))

        test_btn = ModernButton(
            btn_frame,
            text="Test Connection",
            command=self._test_connection,
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_PRIMARY,
            hover_bg=Theme.BG_TERTIARY,
            tooltip="Verify IMAP server connection",
        )
        test_btn.pack(side="left")

        # Filters
        section3 = FormSection(page, "Email Filters", "Only process emails matching these filters (optional)")
        section3.pack(fill="x")

        self.filters = FormRow(
            section3.content, "Filter", "Comma-separated addresses or @domains",
            tooltip="e.g., alerts@example.com, @company.com",
        )
        self.filters.pack(fill="x")
        self.filters.set(self.config.get('Email', 'filter_emails', fallback=''))

    def _create_settings_page(self):
        """Create the general settings page."""
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

    def _create_notification_page(
        self,
        name: str,
        toggle_text: str,
        toggle_var: tk.BooleanVar,
        sections: list,
    ) -> tk.Frame:
        """Helper to create a notification service page with toggle and form sections."""
        page = self._create_scrollable_page(name)

        # Enable toggle card
        toggle_frame = tk.Frame(
            page, bg=Theme.BG_PRIMARY,
            highlightbackground=Theme.CARD_BORDER,
            highlightthickness=1,
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
        """Create the Twilio SMS page."""
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
        """Create the Twilio Voice page."""
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
        """Create the WhatsApp page."""
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
        """Create the Slack page."""
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
        """Create the Telegram page."""
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
        """Create the Discord page."""
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
        """Create the custom webhook page."""
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
        """Create the logs page."""
        page = tk.Frame(self.content, bg=Theme.BG_SECONDARY)
        self.pages["logs"] = page

        # Toolbar
        toolbar = tk.Frame(page, bg=Theme.BG_SECONDARY)
        toolbar.pack(fill="x", padx=32, pady=(24, 12))

        clear_btn = ModernButton(
            toolbar,
            text="Clear Logs",
            command=self._clear_logs,
            bg=Theme.BG_PRIMARY,
            fg=Theme.TEXT_PRIMARY,
            hover_bg=Theme.BG_TERTIARY,
            font_size=9,
            padx=14,
            pady=6,
            tooltip="Clear all log entries",
        )
        clear_btn.pack(side="left")

        ttk.Checkbutton(
            toolbar,
            text="Auto-scroll",
            variable=self.auto_scroll_var,
        ).pack(side="left", padx=(16, 0))

        # Log text with modern styling
        log_frame = tk.Frame(page, bg=Theme.LOG_BG)
        log_frame.pack(fill="both", expand=True, padx=32, pady=(0, 24))

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=(Theme.FONT_MONO, 10),
            bg=Theme.LOG_BG,
            fg=Theme.LOG_FG,
            insertbackground=Theme.LOG_FG,
            relief="flat",
            wrap="word",
            state="disabled",
            padx=16,
            pady=12,
            selectbackground=Theme.PRIMARY,
            selectforeground="#ffffff",
        )
        self.log_text.pack(fill="both", expand=True)

        # Configure tags
        self.log_text.tag_configure('INFO', foreground=Theme.LOG_INFO)
        self.log_text.tag_configure('WARNING', foreground=Theme.LOG_WARNING)
        self.log_text.tag_configure('ERROR', foreground=Theme.LOG_ERROR)
        self.log_text.tag_configure('SUCCESS', foreground=Theme.LOG_SUCCESS)
        self.log_text.tag_configure('TIMESTAMP', foreground=Theme.LOG_TIMESTAMP)

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
            "logs": "Activity Logs",
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

        self.start_btn.configure_state("disabled")
        self.stop_btn.configure_state("normal")
        self.status_badge.set_active(True, "Monitoring")

        self._log("Monitoring started", "INFO")
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _stop_monitoring(self):
        """Stop monitoring."""
        self.monitoring = False
        self.stop_event.set()

        self.start_btn.configure_state("normal")
        self.stop_btn.configure_state("disabled")
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
