import tkinter as tk
from tkinter import ttk
from core.theme import *


WORKFLOW_CARDS = [
    ("1. Setup",           "⚙",  ACE_BLUE,   "Kiểm tra Python, yarGen.py, DB và\ndependencies trước khi luyện công.",             "Setup",         "Check"),
    ("2. Samples",         "◉",  ACE_TEAL,   "Scan hash, file type, archive warning\nvà gom cụm sample cùng family.",              "Analyze",       "Analyze"),
    ("3. Generate",        "⚡", ACE_ORANGE,  "Chọn preset, build command và tạo\nYARA rule bằng engine gốc.",                      "Generate",      "Generate"),
    ("4. Monitor",         "◈",  ACE_PURPLE,  "Theo dõi stage, log và mascot\ntrong lúc yarGen chạy.",                             "Monitor",       "Open"),
    ("5. Validate / Test", "✔",  ACE_GREEN,   "Kiểm thử malware/goodware và\nkiểm soát false positive.",                           "Validate",      "Test"),
    ("6. Analysis Suite",  "◎",  "#C2410C",   "Quality Gate, Rule Doctor, IOC,\nMITRE, Family DNA và Report cuối.",                "AnalysisSuite", "Open Suite"),
]


class HomeScreen(tk.Frame):
    def __init__(self, parent, navigate=None):
        super().__init__(parent, bg=CONT_BG)
        self.navigate = navigate
        self._build_ui()

    def _build_ui(self):
        # ── Top header bar ────────────────────────────────────────────
        hdr_outer = tk.Frame(self, bg=SB_BG)
        hdr_outer.pack(fill="x")

        hdr = tk.Frame(hdr_outer, bg=SB_BG)
        hdr.pack(fill="x", padx=28, pady=(20, 18))

        # Title + subtitle
        title_col = tk.Frame(hdr, bg=SB_BG)
        title_col.pack(side="left", fill="x", expand=True)

        tk.Label(title_col, text="Lò luyện YARA kiếm hiệp",
                 font=("Segoe UI", 22, "bold"),
                 bg=SB_BG, fg="#FFFFFF").pack(anchor="w")
        tk.Label(title_col,
                 text="Generate  •  Validate  •  IOC  •  MITRE  •  Report",
                 font=("Segoe UI", 10), bg=SB_BG, fg=SB_MUTED).pack(anchor="w", pady=(4, 0))

        # Quick-link buttons on right
        btn_col = tk.Frame(hdr, bg=SB_BG)
        btn_col.pack(side="right", anchor="e")
        for text, key in [("⚡  Generate", "Generate"),
                          ("≡  Reports", "Reports"),
                          ("◉  Samples", "Analyze")]:
            b = tk.Button(btn_col, text=text,
                          font=("Segoe UI", 9, "bold"),
                          bg="#1E4D9A", fg="#FFFFFF",
                          relief="flat", bd=0, padx=12, pady=5,
                          cursor="hand2",
                          command=lambda k=key: self.navigate(k) if self.navigate else None)
            b.pack(side="left", padx=(6, 0))

        # ── Dashboard area ────────────────────────────────────────────
        body = tk.Frame(self, bg=CONT_BG)
        body.pack(fill="both", expand=True, padx=22, pady=16)

        # Section heading
        heading_row = tk.Frame(body, bg=CONT_BG)
        heading_row.pack(fill="x", pady=(0, 12))

        tk.Label(heading_row, text="Bảng điều khiển",
                 font=("Segoe UI", 14, "bold"),
                 bg=CONT_BG, fg=TEXT_H).pack(side="left")
        tk.Label(heading_row,
                 text="  —  Workflow rèn chữ ký YARA từ sample family",
                 font=("Segoe UI", 9), bg=CONT_BG, fg=TEXT_M).pack(side="left", pady=(4, 0))

        # ── Cards grid (3 columns × 2 rows) ──────────────────────────
        grid_frame = tk.Frame(body, bg=CONT_BG)
        grid_frame.pack(fill="both", expand=True)
        for c in range(3):
            grid_frame.grid_columnconfigure(c, weight=1, uniform="col")
        for r in range(2):
            grid_frame.grid_rowconfigure(r, weight=1, uniform="row")

        for idx, (title, icon, color, desc, nav_key, btn_text) in enumerate(WORKFLOW_CARDS):
            r, c = divmod(idx, 3)
            self._make_card(grid_frame, title, icon, color, desc, nav_key, btn_text, r, c)

        # ── Quick flow strip ──────────────────────────────────────────
        flow_card = tk.Frame(body, bg=CARD_BG,
                             highlightbackground=CARD_BDR, highlightthickness=1)
        flow_card.pack(fill="x", pady=(10, 0))

        flow_inner = tk.Frame(flow_card, bg=CARD_BG)
        flow_inner.pack(fill="x", padx=18, pady=10)

        tk.Label(flow_inner, text="Quick cultivation flow:",
                 font=("Segoe UI", 9, "bold"),
                 bg=CARD_BG, fg=TEXT_M).pack(side="left", padx=(0, 12))

        steps = [
            ("Setup", "Setup"), ("→", None),
            ("Samples", "Analyze"), ("→", None),
            ("Generate", "Generate"), ("→", None),
            ("Monitor", "Monitor"), ("→", None),
            ("Validate", "Validate"), ("→", None),
            ("Analysis Suite", "AnalysisSuite"),
        ]
        for text, key in steps:
            if key is None:
                tk.Label(flow_inner, text=text, font=("Segoe UI", 9),
                         bg=CARD_BG, fg=TEXT_M).pack(side="left", padx=3)
            else:
                lbl = tk.Label(flow_inner, text=text,
                               font=("Segoe UI", 9, "bold"),
                               bg=CARD_BG, fg=ACE_BLUE, cursor="hand2")
                lbl.pack(side="left", padx=3)
                lbl.bind("<Button-1>", lambda e, k=key: self.navigate(k) if self.navigate else None)

        start_btn = tk.Button(
            flow_inner, text="Start with Setup  →",
            font=("Segoe UI", 9, "bold"),
            bg=ACE_BLUE, fg="#FFFFFF",
            relief="flat", bd=0, padx=16, pady=5, cursor="hand2",
            command=lambda: self.navigate("Setup") if self.navigate else None
        )
        start_btn.pack(side="right")

    def _make_card(self, parent, title, icon, color, desc, nav_key, btn_text, row, col):
        # Shadow frame
        shadow = tk.Frame(parent, bg=CARD_SHD)
        shadow.grid(row=row, column=col, padx=7, pady=7, sticky="nsew")

        card_frame = tk.Frame(shadow, bg=CARD_BG,
                              highlightbackground=CARD_BDR, highlightthickness=1)
        card_frame.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        # Color top stripe (taller)
        tk.Frame(card_frame, bg=color, height=5).pack(fill="x")

        inner = tk.Frame(card_frame, bg=CARD_BG)
        inner.pack(fill="both", expand=True, padx=16, pady=12)

        # Icon + Title row
        top_row = tk.Frame(inner, bg=CARD_BG)
        top_row.pack(fill="x", pady=(0, 6))
        tk.Label(top_row, text=icon, font=("Segoe UI", 20),
                 bg=CARD_BG, fg=color).pack(side="left")
        tk.Label(top_row, text=title, font=("Segoe UI", 11, "bold"),
                 bg=CARD_BG, fg=TEXT_H).pack(side="left", padx=10)

        # Description
        tk.Label(inner, text=desc, font=("Segoe UI", 9),
                 bg=CARD_BG, fg=TEXT_M,
                 justify="left", anchor="w",
                 wraplength=240).pack(anchor="w", pady=(0, 12))

        # Divider
        tk.Frame(inner, bg=CARD_BDR, height=1).pack(fill="x", pady=(0, 10))

        # Action button
        tk.Button(
            inner, text=btn_text,
            font=("Segoe UI", 9, "bold"),
            bg=color, fg="#FFFFFF",
            relief="flat", bd=0, padx=14, pady=5, cursor="hand2",
            command=lambda k=nav_key: self.navigate(k) if self.navigate else None
        ).pack(anchor="w")
