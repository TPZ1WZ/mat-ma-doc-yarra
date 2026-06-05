import os
import sys
import subprocess
import tkinter as tk
from tkinter import messagebox
from core.state import AppState
from core.theme import *


class WebModeScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self._web_process = None
        self._build_ui()

    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="CẤU HÌNH VÀ KÍCH HOẠT LOCAL WEB MODE",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 14))

        # ── Status card ───────────────────────────────────────────
        st_shadow = tk.Frame(self, bg=CARD_SHD)
        st_shadow.pack(fill="x", padx=20, pady=(0, 12))
        st_card = tk.Frame(st_shadow, bg=CARD_BG,
                           highlightbackground=CARD_BDR, highlightthickness=1)
        st_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        st_hdr = tk.Frame(st_card, bg="#EEF3FC")
        st_hdr.pack(fill="x")
        tk.Frame(st_card, bg=ACE_TEAL, height=3).place(x=0, y=0, relwidth=1)
        tk.Label(st_hdr, text="Trạng thái Local Web Server",
                 font=("Segoe UI", 11, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=14, pady=9).pack(anchor="w")
        tk.Frame(st_card, bg=CARD_BDR, height=1).pack(fill="x")

        st_body = tk.Frame(st_card, bg=CARD_BG)
        st_body.pack(fill="x", padx=14, pady=14)

        # Status row
        row1 = tk.Frame(st_body, bg=CARD_BG)
        row1.pack(fill="x", pady=(0, 10))
        tk.Label(row1, text="Trạng thái hệ thống:",
                 font=("Segoe UI", 10), bg=CARD_BG, fg=TEXT_M,
                 width=30, anchor="w").pack(side="left")
        dot_frame = tk.Frame(row1, bg=CARD_BG)
        dot_frame.pack(side="left")
        self.dot_lbl = tk.Label(dot_frame, text="●", font=("Segoe UI", 12),
                                bg=CARD_BG, fg="#C0392B")
        self.dot_lbl.pack(side="left", padx=(0, 6))
        self.status_var = tk.StringVar(value="ĐANG TẮT (Offline)")
        self.lbl_status_val = tk.Label(dot_frame, textvariable=self.status_var,
                                       font=("Segoe UI", 10, "bold"),
                                       bg=CARD_BG, fg="#C0392B")
        self.lbl_status_val.pack(side="left")

        # URL row
        row2 = tk.Frame(st_body, bg=CARD_BG)
        row2.pack(fill="x")
        tk.Label(row2, text="Địa chỉ truy cập mạng cục bộ:",
                 font=("Segoe UI", 10), bg=CARD_BG, fg=TEXT_M,
                 width=30, anchor="w").pack(side="left")
        self.url_entry_var = tk.StringVar(value="http://127.0.0.1:8088")
        tk.Entry(row2, textvariable=self.url_entry_var,
                 font=("Consolas", 10), bd=1, relief="solid",
                 state="readonly", width=34).pack(side="left")

        # ── Toggle button ─────────────────────────────────────────
        tk.Button(
            self, text="▶  Bật / Tắt Web Server Cục Bộ",
            font=("Segoe UI", 10, "bold"),
            bg=ACE_TEAL, fg="#FFFFFF", relief="flat", bd=0,
            padx=20, pady=8, cursor="hand2",
            command=self._toggle_web_server
        ).pack(anchor="w", padx=20, pady=(4, 16))

        # ── Tips card ─────────────────────────────────────────────
        tip_shadow = tk.Frame(self, bg=CARD_SHD)
        tip_shadow.pack(fill="x", padx=20, pady=(0, 14))
        tip_card = tk.Frame(tip_shadow, bg=CARD_BG,
                            highlightbackground=CARD_BDR, highlightthickness=1)
        tip_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        tip_inner = tk.Frame(tip_card, bg=CARD_BG)
        tip_inner.pack(fill="x", padx=14, pady=10)
        tk.Label(tip_inner, text="Kiến trúc Flask SSE",
                 font=("Segoe UI", 9, "bold"), bg=CARD_BG, fg=TEXT_M
                 ).pack(anchor="w", pady=(0, 4))
        tk.Label(
            tip_inner,
            text="Giao diện Web sử dụng kiến trúc Flask liên kết phi tập trung, "
                 "hỗ trợ Server-Sent Events (SSE)\n"
                 "để đẩy trực tiếp nhật ký log của yarGen từ tiến trình con nền lên trình duyệt thời gian thực.",
            font=FONT_SMALL, bg=CARD_BG, fg=TEXT_M, justify="left"
        ).pack(anchor="w")

    def _toggle_web_server(self):
        if not self.state.is_web_mode_running:
            self._start_web_server()
        else:
            self._stop_web_server()

    def _start_web_server(self):
        web_server_path = os.path.join(self.state.base_dir, "web_server.py")
        python_exe = sys.executable
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        try:
            self._web_process = subprocess.Popen(
                [python_exe, "-X", "utf8", web_server_path],
                cwd=self.state.base_dir,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.state.is_web_mode_running = True
            self.status_var.set("ĐANG CHẠY (Online)")
            self.lbl_status_val.config(fg=ACE_GREEN)
            self.dot_lbl.config(fg=ACE_GREEN)
            messagebox.showinfo("Thành công",
                                "Web Server đã khởi động!\nMở trình duyệt tại: http://127.0.0.1:8088")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể khởi động Web Server:\n{str(e)}")

    def _stop_web_server(self):
        if self._web_process and self._web_process.poll() is None:
            self._web_process.terminate()
            try:
                self._web_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._web_process.kill()
        self._web_process = None
        self.state.is_web_mode_running = False
        self.status_var.set("ĐANG TẮT (Offline)")
        self.lbl_status_val.config(fg="#C0392B")
        self.dot_lbl.config(fg="#C0392B")
        messagebox.showinfo("Thông báo", "Đã dừng Web Server.")
