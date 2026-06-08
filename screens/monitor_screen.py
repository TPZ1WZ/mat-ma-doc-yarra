import os
import re
import tkinter as tk
from tkinter import messagebox
from core.state import AppState
from core.runner import BackgroundRunner
from core.theme import *

STAGES = [
    ("Preflight",    ["[+] Scanning", "[+] Starting", "Loading", "Init"]),
    ("Load DB",      ["[+] Loading goodware", "goodware strings", "Loading strings DB", "good-"]),
    ("Extract",      ["[+] Extracting strings", "Processing sample", "[+] Generating", "strings from"]),
    ("Generate",     ["[+] Creating", "[+] Writing", "Generating YARA", "simple rules", "super rules"]),
    ("Validate",     ["[+] Validating", "[+] Testing", "Finished", "Done", "rules written"]),
]

STAGE_COLORS = {
    "Preflight":  "#3498DB",
    "Load DB":    "#9B59B6",
    "Extract":    "#E67E22",
    "Generate":   "#27AE60",
    "Validate":   "#1ABC9C",
}


class MonitorScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.runner = BackgroundRunner()

        self._current_stage = "idle"
        self._simple_rules = 0
        self._super_rules = 0
        self._string_count = 0
        self._last_output_path = ""

        self._build_ui()
        self._poll_logs()

    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="HỆ THỐNG GIÁM SÁT TIẾN TRÌNH NGẦM REAL-TIME",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 12))

        # ── Stage progress card ───────────────────────────────────
        stg_shadow = tk.Frame(self, bg=CARD_SHD)
        stg_shadow.pack(fill="x", padx=20, pady=(0, 10))
        stg_card = tk.Frame(stg_shadow, bg=CARD_BG,
                            highlightbackground=CARD_BDR, highlightthickness=1)
        stg_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        stg_hdr = tk.Frame(stg_card, bg="#EEF3FC")
        stg_hdr.pack(fill="x")
        tk.Frame(stg_card, bg=ACE_BLUE, height=3).place(x=0, y=0, relwidth=1)
        tk.Label(stg_hdr, text="Tiến trình xử lý theo giai đoạn",
                 font=("Segoe UI", 10, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=14, pady=8).pack(anchor="w")
        tk.Frame(stg_card, bg=CARD_BDR, height=1).pack(fill="x")

        self._stage_labels = {}
        stage_bar = tk.Frame(stg_card, bg=CARD_BG)
        stage_bar.pack(fill="x", padx=12, pady=10)
        for idx, (name, _) in enumerate(STAGES):
            lbl = tk.Label(
                stage_bar, text=f"  {name}  ",
                font=("Segoe UI", 9, "bold"),
                bg="#BDC3C7", fg="#FFFFFF",
                padx=6, pady=4, relief="flat"
            )
            lbl.pack(side="left", padx=3)
            self._stage_labels[name] = lbl
            if idx < len(STAGES) - 1:
                tk.Label(stage_bar, text="›", font=("Segoe UI", 12),
                         bg=CARD_BG, fg="#95A5A6").pack(side="left")

        # ── Stats + controls row ──────────────────────────────────
        meta_row = tk.Frame(self, bg=CONT_BG)
        meta_row.pack(fill="x", padx=20, pady=(0, 8))

        stats_grp = tk.Frame(meta_row, bg=CONT_BG)
        stats_grp.pack(side="left")
        self._stat_vars = {
            "SIMPLE Rules": tk.StringVar(value="0"),
            "SUPER Rules":  tk.StringVar(value="0"),
            "Strings":      tk.StringVar(value="0"),
        }
        for label, var in self._stat_vars.items():
            s = tk.Frame(stats_grp, bg=CARD_SHD)
            s.pack(side="left", padx=(0, 8))
            c = tk.Frame(s, bg=CARD_BG,
                         highlightbackground=CARD_BDR, highlightthickness=1)
            c.pack(padx=(0, 2), pady=(0, 2), ipadx=14, ipady=6)
            tk.Label(c, textvariable=var, font=("Segoe UI", 18, "bold"),
                     bg=CARD_BG, fg=TEXT_H).pack()
            tk.Label(c, text=label, font=("Segoe UI", 8),
                     bg=CARD_BG, fg=TEXT_M).pack()

        ctrl_grp = tk.Frame(meta_row, bg=CONT_BG)
        ctrl_grp.pack(side="right", anchor="e")
        tk.Button(ctrl_grp, text="Xóa Log",
                  font=("Segoe UI", 9), bg="#7F8C8D", fg="#FFFFFF",
                  bd=0, padx=12, pady=5, cursor="hand2",
                  command=self._clear_monitor).pack(side="left", padx=(0, 6))
        tk.Button(ctrl_grp, text="Cưỡng Bức Dừng (Abort)",
                  font=("Segoe UI", 9, "bold"), bg="#C0392B", fg="#FFFFFF",
                  relief="flat", bd=0, padx=15, pady=5, cursor="hand2",
                  command=self._abort_task).pack(side="left", padx=(0, 6))
        tk.Button(ctrl_grp, text="Tải lại luật",
                  font=("Segoe UI", 9), bg="#16A085", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                  command=self._reload_rule_preview).pack(side="left")

        # ── Split pane: log (left) + rule preview (right) ─────────
        split = tk.Frame(self, bg=CONT_BG)
        split.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # LEFT — console log (60%)
        console_shadow = tk.Frame(split, bg=CARD_SHD)
        console_shadow.pack(side="left", fill="both", expand=True, padx=(0, 6))
        console_card = tk.Frame(console_shadow, bg=CARD_BG,
                                highlightbackground=CARD_BDR, highlightthickness=1)
        console_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        console_hdr = tk.Frame(console_card, bg="#1A2035")
        console_hdr.pack(fill="x")
        tk.Label(console_hdr, text="  ◉  Standard Output Log — yarGen Real-time",
                 font=("Segoe UI", 10, "bold"),
                 bg="#1A2035", fg="#7FB8FF", anchor="w", pady=8).pack(side="left")

        console_body = tk.Frame(console_card, bg="#1E1E1E")
        console_body.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            console_body, font=("Consolas", 9),
            bg="#1E1E1E", fg="#F8F8F2",
            insertbackground="white", bd=0, wrap="word",
            padx=8, pady=6, state="disabled"
        )
        scrollbar = tk.Scrollbar(console_body, orient="vertical",
                                 command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.log_text.tag_config("info",    foreground="#61AFEF")
        self.log_text.tag_config("warning", foreground="#E5C07B")
        self.log_text.tag_config("error",   foreground="#E06C75")
        self.log_text.tag_config("success", foreground="#98C379")
        self.log_text.tag_config("normal",  foreground="#ABB2BF")

        self.last_log_count = 0

        # RIGHT — rule preview (40%, always visible)
        prev_shadow = tk.Frame(split, bg=CARD_SHD, width=520)
        prev_shadow.pack(side="left", fill="both", padx=(0, 0))
        prev_shadow.pack_propagate(False)
        prev_card = tk.Frame(prev_shadow, bg=CARD_BG,
                             highlightbackground=CARD_BDR, highlightthickness=1)
        prev_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        _prev_hdr = tk.Frame(prev_card, bg="#EEF3FC")
        _prev_hdr.pack(fill="x")
        tk.Frame(prev_card, bg=ACE_TEAL, height=3).place(x=0, y=0, relwidth=1)
        self._preview_title_lbl = tk.Label(
            _prev_hdr, text="  Preview: (chờ yarGen xong...)",
            font=("Segoe UI", 9, "bold"), bg="#EEF3FC", fg="#16A085",
            anchor="w", padx=12, pady=6
        )
        self._preview_title_lbl.pack(side="left")
        tk.Frame(prev_card, bg=CARD_BDR, height=1).pack(fill="x")

        _prev_body = tk.Frame(prev_card, bg="#1E1E1E")
        _prev_body.pack(fill="both", expand=True)
        _prev_body.grid_rowconfigure(0, weight=1)
        _prev_body.grid_columnconfigure(0, weight=1)

        self.preview_text = tk.Text(
            _prev_body, font=("Consolas", 8),
            bg="#1E1E1E", fg="#98C379", wrap="none", bd=0,
            padx=8, pady=4, state="disabled"
        )
        _sb_prev = tk.Scrollbar(_prev_body, orient="vertical",
                                command=self.preview_text.yview)
        _sb_h = tk.Scrollbar(_prev_body, orient="horizontal",
                             command=self.preview_text.xview)
        self.preview_text.configure(yscrollcommand=_sb_prev.set,
                                    xscrollcommand=_sb_h.set)
        self.preview_text.grid(row=0, column=0, sticky="nsew")
        _sb_prev.grid(row=0, column=1, sticky="ns")
        _sb_h.grid(row=1, column=0, sticky="ew")

    # ─────────────────────────────────────────────────────────────
    def _detect_stage(self, line: str):
        line_lower = line.lower()
        for stage_name, keywords in STAGES:
            if any(kw.lower() in line_lower for kw in keywords):
                return stage_name
        return None

    def _extract_stats(self, line: str):
        m_simple  = re.search(r'(\d+)\s+simple\s+rule',  line, re.IGNORECASE)
        m_super   = re.search(r'(\d+)\s+super\s+rule',   line, re.IGNORECASE)
        m_strings = re.search(r'(\d+)\s+strings',        line, re.IGNORECASE)
        if m_simple:
            self._simple_rules = int(m_simple.group(1))
        if m_super:
            self._super_rules = int(m_super.group(1))
        if m_strings:
            self._string_count = int(m_strings.group(1))

    def _detect_output_path(self, line: str):
        m = re.search(r'[\w/\\:.-]+\.yar', line)
        if m:
            candidate = m.group(0)
            if os.path.isfile(candidate):
                self._last_output_path = candidate

    def _update_stage_ui(self, stage_name: str):
        if stage_name == self._current_stage:
            return
        self._current_stage = stage_name
        keys = list(self._stage_labels.keys())
        for name, lbl in self._stage_labels.items():
            if name == stage_name:
                lbl.config(bg=STAGE_COLORS.get(name, "#3498DB"), fg="#FFFFFF")
            elif keys.index(name) < keys.index(stage_name):
                lbl.config(bg="#27AE60", fg="#FFFFFF")
            else:
                lbl.config(bg="#BDC3C7", fg="#FFFFFF")

    def _classify_line(self, line: str) -> str:
        lower = line.lower()
        if any(k in lower for k in ["error", "fatal", "exception", "traceback"]):
            return "error"
        if any(k in lower for k in ["warning", "warn", "[warning"]):
            return "warning"
        if any(k in lower for k in ["done", "finished", "success", "written", "complete"]):
            return "success"
        if any(k in lower for k in ["[+]", "[info]", "[*]"]):
            return "info"
        return "normal"

    def _append_line(self, line: str):
        tag = self._classify_line(line)
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, line + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _clear_monitor(self):
        self.state.clear_log()
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")
        self.last_log_count = 0
        self._simple_rules = 0
        self._super_rules = 0
        self._string_count = 0
        self._current_stage = "idle"
        self._update_stats_ui()
        for lbl in self._stage_labels.values():
            lbl.config(bg="#BDC3C7", fg="#FFFFFF")

    def _update_stats_ui(self):
        self._stat_vars["SIMPLE Rules"].set(str(self._simple_rules))
        self._stat_vars["SUPER Rules"].set(str(self._super_rules))
        self._stat_vars["Strings"].set(str(self._string_count))

    def _abort_task(self):
        if self.runner.is_running():
            if messagebox.askyesno("Xác nhận", "Bạn có chắc muốn hủy tiến trình đang chạy không?"):
                self.runner.terminate_current_task()
        else:
            messagebox.showinfo("Thông báo", "Hiện tại không có tác vụ nào đang chạy.")

    def _load_rule_into_preview(self, path: str):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            return
        self._preview_title_lbl.config(
            text=f"  Preview: {os.path.basename(path)}"
        )
        self.preview_text.configure(state="normal")
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert(tk.END, content)
        self.preview_text.configure(state="disabled")

    def _reload_rule_preview(self):
        if not self._last_output_path or not os.path.isfile(self._last_output_path):
            rules_dir = self.state.rules_dir
            yar_files = [
                os.path.join(rules_dir, f)
                for f in os.listdir(rules_dir)
                if f.endswith(".yar")
            ]
            if yar_files:
                self._last_output_path = max(yar_files, key=os.path.getmtime)
        if not self._last_output_path or not os.path.isfile(self._last_output_path):
            messagebox.showinfo("Thông báo", "Chưa tìm thấy file .yar nào trong thư mục rules/.")
            return
        self._load_rule_into_preview(self._last_output_path)

    # ─────────────────────────────────────────────────────────────
    def _poll_logs(self):
        current_logs = self.state.get_logs()
        current_count = len(current_logs)

        if current_count > self.last_log_count:
            new_lines = current_logs[self.last_log_count:]
            for line in new_lines:
                self._append_line(line)
                stage = self._detect_stage(line)
                if stage:
                    self._update_stage_ui(stage)
                self._extract_stats(line)
                self._detect_output_path(line)
            self.last_log_count = current_count
            self._update_stats_ui()

        if not self.runner.is_running() and self.last_log_count > 0:
            if self._last_output_path and os.path.isfile(self._last_output_path):
                current_preview = self.preview_text.get("1.0", "1.1")
                if not current_preview.strip():
                    self._load_rule_into_preview(self._last_output_path)

        self.after(500, self._poll_logs)
