import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from core.state import AppState
from core.yara_engine import YaraEngine
from core.theme import *


def _input_card(parent, title, color=None):
    """Returns inner body frame of a compact input card."""
    color = color or ACE_BLUE
    shadow = tk.Frame(parent, bg=CARD_SHD)
    shadow.pack(fill="x", padx=20, pady=(0, 10))
    card = tk.Frame(shadow, bg=CARD_BG,
                    highlightbackground=CARD_BDR, highlightthickness=1)
    card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

    hdr = tk.Frame(card, bg="#EEF3FC")
    hdr.pack(fill="x")
    tk.Frame(card, bg=color, height=3).place(x=0, y=0, relwidth=1)
    tk.Label(hdr, text=title, font=("Segoe UI", 10, "bold"),
             bg="#EEF3FC", fg=TEXT_H, anchor="w",
             padx=14, pady=8).pack(anchor="w")
    tk.Frame(card, bg=CARD_BDR, height=1).pack(fill="x")

    body = tk.Frame(card, bg=CARD_BG)
    body.pack(fill="x", padx=12, pady=10)
    return body


class ValidateScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.engine = YaraEngine()
        self._build_ui()

    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="KIỂM THỬ VÀ XÁC MINH CHẤT LƯỢNG LUẬT YARA",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left", anchor="w")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 14))

        # ── Card 1: YARA rule file ────────────────────────────────────
        body1 = _input_card(self, "Cấu hình luật YARA mục tiêu", ACE_BLUE)
        row1 = tk.Frame(body1, bg=CARD_BG)
        row1.pack(fill="x")
        self.rule_path_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.rule_path_var,
                 font=("Segoe UI", 10), bd=1, relief="solid"
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row1, text="Browse Rule…",
                  font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                  command=self._browse_rule).pack(side="left", padx=(0, 8))
        tk.Button(row1, text="✔  Kiểm Tra Biên Dịch",
                  font=("Segoe UI", 10, "bold"),
                  bg=ACE_BLUE, fg="#FFFFFF",
                  relief="flat", bd=0, padx=16, pady=5, cursor="hand2",
                  command=self._check_compile).pack(side="left")

        # ── Card 2: Scan target ───────────────────────────────────────
        body2 = _input_card(self, "Cấu hình đối tượng rà quét thử nghiệm", ACE_GREEN)
        row2 = tk.Frame(body2, bg=CARD_BG)
        row2.pack(fill="x")
        self.target_path_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.target_path_var,
                 font=("Segoe UI", 10), bd=1, relief="solid"
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row2, text="Browse Target…",
                  font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                  command=self._browse_target).pack(side="left", padx=(0, 8))
        tk.Button(row2, text="▶  Khởi Chạy Quét Thử",
                  font=("Segoe UI", 10, "bold"),
                  bg=ACE_GREEN, fg="#FFFFFF",
                  relief="flat", bd=0, padx=16, pady=5, cursor="hand2",
                  command=self._run_scan).pack(side="left")

        # ── Console output ────────────────────────────────────────────
        console_shadow = tk.Frame(self, bg=CARD_SHD)
        console_shadow.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        console_card = tk.Frame(console_shadow, bg=CARD_BG,
                                highlightbackground=CARD_BDR, highlightthickness=1)
        console_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        console_hdr = tk.Frame(console_card, bg="#1A2035")
        console_hdr.pack(fill="x")
        tk.Label(console_hdr, text="  ◉  Scan Output Console",
                 font=("Segoe UI", 10, "bold"),
                 bg="#1A2035", fg="#7FB8FF", anchor="w",
                 pady=8).pack(side="left")

        console_body = tk.Frame(console_card, bg="#0F1929")
        console_body.pack(fill="both", expand=True)

        self.console_text = tk.Text(
            console_body, font=("Consolas", 10),
            bg="#0F1929", fg="#A8D8A8", bd=0, wrap="word",
            padx=12, pady=8,
            insertbackground="#A8D8A8",
            selectbackground="#1E4D9A"
        )
        sb = tk.Scrollbar(console_body, orient="vertical",
                          command=self.console_text.yview)
        self.console_text.configure(yscrollcommand=sb.set)
        self.console_text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Add color tags
        self.console_text.tag_config("success", foreground="#7EC8A4")
        self.console_text.tag_config("error",   foreground="#FF6B6B")
        self.console_text.tag_config("alert",   foreground="#FFD166")
        self.console_text.tag_config("info",    foreground="#74B9FF")
        self.console_text.tag_config("muted",   foreground="#5A7BA6")

        self._log("Sẵn sàng. Chọn file luật .yar và thư mục mục tiêu để bắt đầu.\n", "muted")

    # ── Helpers ──────────────────────────────────────────────────────
    def _log(self, text, tag=None):
        self.console_text.config(state="normal")
        if tag:
            self.console_text.insert(tk.END, text, tag)
        else:
            self.console_text.insert(tk.END, text)
        self.console_text.see(tk.END)

    def _browse_rule(self):
        f = filedialog.askopenfilename(
            title="Chọn file luật YARA (.yar)",
            initialdir=self.state.rules_dir,
            filetypes=[("YARA Rules", "*.yar"), ("All Files", "*.*")]
        )
        if f:
            self.rule_path_var.set(f)

    def _browse_target(self):
        target = filedialog.askdirectory(title="Chọn thư mục mục tiêu")
        if not target:
            target = filedialog.askopenfilename(title="Chọn file mục tiêu")
        if target:
            self.target_path_var.set(target)

    def _check_compile(self):
        rule_path = self.rule_path_var.get().strip()
        if not rule_path or not os.path.exists(rule_path):
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file luật YARA hợp lệ.")
            return
        with open(rule_path, "r", encoding="utf-8", errors="replace") as f:
            rule_text = f.read()

        self.console_text.delete("1.0", tk.END)
        self._log(f"[*] Nạp luật từ: {rule_path}\n", "info")
        self._log(f"[*] Biên dịch với backend: '{self.state.current_yara_backend}'...\n", "info")
        self.update_idletasks()

        res = self.engine.compile_rule_text(rule_text)
        if res["success"]:
            self._log("[SUCCESS] Biên dịch thành công! Không phát hiện lỗi cú pháp.\n", "success")
            self._log(f"Backend: {res['backend_used']}\n", "muted")
            messagebox.showinfo("Thành công", "Luật YARA hợp lệ, sẵn sàng quét!")
        else:
            self._log("[FAILED] Phát hiện lỗi cú pháp:\n", "error")
            self._log("─" * 40 + "\n", "muted")
            self._log(f"{res['error']}\n", "error")
            messagebox.showerror("Lỗi cú pháp", "Biên dịch thất bại. Kiểm tra lại cú pháp luật.")

    def _run_scan(self):
        rule_path   = self.rule_path_var.get().strip()
        target_path = self.target_path_var.get().strip()
        if not rule_path or not os.path.exists(rule_path):
            messagebox.showwarning("Cảnh báo", "Vui lòng cấu hình file luật YARA trước.")
            return
        if not target_path or not os.path.exists(target_path):
            messagebox.showwarning("Cảnh báo", "Vui lòng cấu hình đường dẫn đích cần quét.")
            return

        self.console_text.delete("1.0", tk.END)
        self._log(f"[*] Bắt đầu quét: {target_path}\n", "info")
        self._log("[*] Đang quét, vui lòng đợi...\n", "info")

        def _worker():
            matches = self.engine.scan_target(rule_path, target_path)
            self.after(0, lambda: self._display_scan_result(matches))

        threading.Thread(target=_worker, daemon=True).start()

    def _display_scan_result(self, matches):
        self._log("[*] Quét hoàn tất!\n", "info")
        self._log("═" * 40 + "\n", "muted")
        self._log(f"TỔNG SỐ ĐỐI TƯỢNG PHÁT HIỆN: {len(matches)}\n", "alert")
        self._log("═" * 40 + "\n\n", "muted")
        if not matches:
            self._log("[CLEAN] Không có file nào khớp luật YARA.\n", "success")
        else:
            for m in matches:
                self._log("[ALERT] Phát hiện mục tiêu nghi nhiễm:\n", "alert")
                self._log(f"  File  : {m['file']}\n")
                self._log(f"  Luật  : {', '.join(m['rules'])}\n")
                self._log("─" * 40 + "\n", "muted")
