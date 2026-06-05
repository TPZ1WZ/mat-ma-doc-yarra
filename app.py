import tkinter as tk
from tkinter import ttk

from core.theme import *
from screens.home_screen import HomeScreen
from screens.setup_screen import SetupScreen
from screens.analyze_screen import AnalyzeScreen
from screens.family_screen import FamilyScreen
from screens.generate_screen import GenerateScreen
from screens.monitor_screen import MonitorScreen
from screens.validate_screen import ValidateScreen
from screens.reports_screen import ReportsScreen
from screens.analysis_suite_screen import AnalysisSuiteScreen
from screens.web_mode_screen import WebModeScreen

# Nav grouped by section: (section_label, [(key, icon, label), ...])
NAV_SECTIONS = [
    ("WORKFLOW", [
        ("Home",    "⌂",  "Home"),
        ("Setup",   "⚙",  "Setup"),
        ("Analyze", "◉",  "Samples"),
        ("Family",  "❖",  "Family"),
    ]),
    ("GENERATE & TEST", [
        ("Generate",  "⚡", "Generate"),
        ("Monitor",   "◈",  "Monitor"),
        ("Validate",  "✔",  "Validate / Test"),
    ]),
    ("ANALYSIS", [
        ("Reports",       "≡",  "Reports"),
        ("AnalysisSuite", "◎",  "Analysis Suite"),
        ("WebMode",       "⊞",  "Web Mode"),
    ]),
]


class MainApplication:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.configure(bg=SB_BG)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # ── Sidebar ──────────────────────────────────────────────────
        self.sidebar = tk.Frame(root, bg=SB_BG, width=220)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # ── Content area ─────────────────────────────────────────────
        self.content_frame = tk.Frame(root, bg=CONT_BG)
        self.content_frame.grid(row=0, column=1, sticky="nsew")

        # ── Status bar (spans full width, row=1) ─────────────────────
        root.grid_rowconfigure(1, weight=0)
        self.status_bar = tk.Frame(root, bg=STAT_BG, height=26, bd=0,
                                   highlightbackground=CARD_BDR, highlightthickness=1)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_bar.grid_propagate(False)
        self._build_status_bar()

        self.screens: dict = {}
        self.current_screen = None
        self._nav_btns: dict = {}

        from core.state import AppState
        AppState().navigate_callback = self.show_screen

        self._build_sidebar()
        self._init_all_screens()
        self.show_screen("Home")

        self._update_status()

    # ── Sidebar ──────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = self.sidebar

        # ── Logo block ───────────────────────────────────────────────
        logo_frame = tk.Frame(sb, bg=SB_BG)
        logo_frame.pack(fill="x", pady=(20, 0), padx=16)

        # App icon badge
        badge_row = tk.Frame(logo_frame, bg=SB_BG)
        badge_row.pack(anchor="w")

        badge = tk.Label(badge_row, text="⬡", font=("Segoe UI", 22),
                         bg=SB_BG, fg=ACE_BLUE)
        badge.pack(side="left")

        title_col = tk.Frame(badge_row, bg=SB_BG)
        title_col.pack(side="left", padx=(6, 0))
        tk.Label(title_col, text="YARA Studio",
                 font=("Segoe UI", 13, "bold"), bg=SB_BG, fg=SB_LOGO,
                 anchor="w").pack(anchor="w")
        tk.Label(title_col, text="Wuxia YARA Forge",
                 font=("Segoe UI", 8), bg=SB_BG, fg=SB_MUTED,
                 anchor="w").pack(anchor="w")

        # Version tag
        ver_frame = tk.Frame(logo_frame, bg="#1A3A6A")
        ver_frame.pack(anchor="w", pady=(8, 0))
        tk.Label(ver_frame, text=" v1.0  •  yarGen GUI ",
                 font=("Segoe UI", 8), bg="#1A3A6A", fg=SB_MUTED).pack()

        tk.Frame(sb, bg="#1A3A6A", height=1).pack(fill="x", padx=0, pady=(14, 0))

        # ── Nav sections ─────────────────────────────────────────────
        for section_label, items in NAV_SECTIONS:
            tk.Label(sb, text=section_label,
                     font=("Segoe UI", 7, "bold"),
                     bg=SB_BG, fg=SB_MUTED, anchor="w"
                     ).pack(anchor="w", padx=20, pady=(12, 3))

            for key, icon, label in items:
                self._make_nav_btn(sb, key, icon, label)

        # ── Bottom status strip ───────────────────────────────────────
        tk.Frame(sb, bg="#1A3A6A", height=1).pack(side="bottom", fill="x", pady=(0, 0))
        bottom = tk.Frame(sb, bg="#0A1830")
        bottom.pack(side="bottom", fill="x")
        tk.Label(bottom, text="● Static analysis  •  Offline",
                 font=("Segoe UI", 8), bg="#0A1830", fg="#3A6090"
                 ).pack(pady=8)

    def _make_nav_btn(self, parent, key, icon, label):
        row = tk.Frame(parent, bg=SB_BG, cursor="hand2")
        row.pack(fill="x")

        # Left accent indicator
        accent = tk.Frame(row, bg=SB_BG, width=4)
        accent.pack(side="left", fill="y")

        # Icon label
        icon_lbl = tk.Label(row, text=icon, font=("Segoe UI", 11),
                             bg=SB_BG, fg=SB_MUTED, width=2, anchor="center",
                             padx=6, pady=9)
        icon_lbl.pack(side="left")

        # Text label
        lbl = tk.Label(row, text=label, font=FONT_NAV,
                       bg=SB_BG, fg=SB_TEXT, anchor="w",
                       padx=4, pady=9)
        lbl.pack(side="left", fill="x", expand=True)

        def on_click():
            self.show_screen(key)

        def on_enter(_):
            if key != getattr(self, "_active_key", None):
                for w in (row, icon_lbl, lbl):
                    w.config(bg=SB_HOVER)

        def on_leave(_):
            if key != getattr(self, "_active_key", None):
                for w in (row, icon_lbl, lbl):
                    w.config(bg=SB_BG)

        for widget in (row, icon_lbl, lbl):
            widget.bind("<Button-1>", lambda e, k=key: on_click())
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)

        self._nav_btns[key] = (row, lbl, accent, icon_lbl)

    def _set_active_nav(self, key):
        prev = getattr(self, "_active_key", None)
        if prev and prev in self._nav_btns:
            row, lbl, accent, icon_lbl = self._nav_btns[prev]
            for w in (row, lbl, icon_lbl):
                w.config(bg=SB_BG)
            lbl.config(fg=SB_TEXT, font=FONT_NAV)
            icon_lbl.config(fg=SB_MUTED)
            accent.config(bg=SB_BG)

        self._active_key = key
        if key in self._nav_btns:
            row, lbl, accent, icon_lbl = self._nav_btns[key]
            for w in (row, lbl, icon_lbl):
                w.config(bg=SB_ACTIVE)
            lbl.config(fg=SB_ATXT, font=("Segoe UI", 10, "bold"))
            icon_lbl.config(fg="#7FB8FF")
            accent.config(bg=ACE_BLUE)

    # ── Status bar ───────────────────────────────────────────────────
    def _build_status_bar(self):
        sb = self.status_bar
        self._sv_env     = tk.StringVar(value="Env: Unknown")
        self._sv_project = tk.StringVar(value="Project: —")
        self._sv_preset  = tk.StringVar(value="Preset: Beginner")
        self._sv_output  = tk.StringVar(value="Output: —")
        self._sv_status  = tk.StringVar(value="● Idle")

        common = dict(font=FONT_STAT, bg=STAT_BG, fg=TEXT_M)
        sep_kw = dict(bg=CARD_BDR, width=1)

        def stat_lbl(textvariable, **extra):
            return tk.Label(sb, textvariable=textvariable, **common, **extra)

        stat_lbl(self._sv_env).pack(side="left", padx=(12, 0))
        tk.Frame(sb, **sep_kw).pack(side="left", fill="y", padx=6, pady=5)
        stat_lbl(self._sv_project).pack(side="left")
        tk.Frame(sb, **sep_kw).pack(side="left", fill="y", padx=6, pady=5)
        stat_lbl(self._sv_preset).pack(side="left")
        tk.Frame(sb, **sep_kw).pack(side="left", fill="y", padx=6, pady=5)
        stat_lbl(self._sv_output).pack(side="left")

        # Right side
        tk.Label(sb, text="Static only  •  No exec  •  Offline",
                 font=FONT_STAT, bg=STAT_BG, fg=TEXT_M).pack(side="right", padx=14)
        tk.Frame(sb, **sep_kw).pack(side="right", fill="y", padx=6, pady=5)
        self._status_lbl = tk.Label(sb, textvariable=self._sv_status,
                                    font=("Segoe UI", 9, "bold"), bg=STAT_BG, fg=STAT_OK)
        self._status_lbl.pack(side="right", padx=(0, 4))
        tk.Frame(sb, **sep_kw).pack(side="right", fill="y", padx=6, pady=5)

    def _update_status(self):
        try:
            from core.state import AppState
            from core.runner import BackgroundRunner
            state = AppState()
            runner = BackgroundRunner()

            if state.selected_family_dir:
                import os
                self._sv_project.set(f"Project: {os.path.basename(state.selected_family_dir)}")

            if runner.is_running():
                self._sv_status.set("● Running")
                self._status_lbl.config(fg=ACE_ORANGE)
            else:
                self._sv_status.set("● Idle")
                self._status_lbl.config(fg=STAT_OK)
        except Exception:
            pass
        self.root.after(1000, self._update_status)

    # ── Screens ──────────────────────────────────────────────────────
    def _init_all_screens(self):
        self.screens["Home"]          = HomeScreen(self.content_frame, navigate=self.show_screen)
        self.screens["Setup"]         = SetupScreen(self.content_frame)
        self.screens["Analyze"]       = AnalyzeScreen(self.content_frame)
        self.screens["Family"]        = FamilyScreen(self.content_frame)
        self.screens["Generate"]      = GenerateScreen(self.content_frame)
        self.screens["Monitor"]       = MonitorScreen(self.content_frame)
        self.screens["Validate"]      = ValidateScreen(self.content_frame)
        self.screens["AnalysisSuite"] = AnalysisSuiteScreen(self.content_frame)
        self.screens["Reports"]       = ReportsScreen(self.content_frame)
        self.screens["WebMode"]       = WebModeScreen(self.content_frame)

    def show_screen(self, screen_key: str):
        if screen_key not in self.screens:
            return
        if self.current_screen:
            self.current_screen.pack_forget()
        self.current_screen = self.screens[screen_key]
        self.current_screen.pack(fill="both", expand=True)
        self._set_active_nav(screen_key)


if __name__ == "__main__":
    root = tk.Tk()
    root.title("YARA Malware Analysis Studio")
    root.geometry("1280x780")
    root.minsize(1000, 650)
    configure_ttk_styles()
    app = MainApplication(root)
    root.mainloop()
