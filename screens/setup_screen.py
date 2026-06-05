import os
import sys
import importlib
import tkinter as tk
from tkinter import messagebox
from core.state import AppState
from core.theme import *

CHECKS = [
    ("python_exe",     "Python Executable",             "Trình thông dịch Python hiện tại"),
    ("yargen_py",      "yarGen.py",                     "File engine yarGen.py trong thư mục gốc"),
    ("dbs_dir",        "Thư mục dbs/",                  "Cơ sở dữ liệu Goodware (dbs/)"),
    ("rules_dir",      "Thư mục rules/",                "Thư mục lưu luật YARA đầu ra"),
    ("reports_dir",    "Thư mục reports/",              "Thư mục lưu báo cáo phân tích"),
    ("yara64_exe",     "yara64.exe (3rdparty/yara/)",   "YARA CLI backend (tùy chọn)"),
    ("pefile_mod",     "Module pefile",                 "Thư viện phân tích PE structure"),
    ("yara_mod",       "Module yara-python",            "Backend YARA biên dịch và quét rule"),
    ("flask_mod",      "Module Flask",                  "Web server cho Web Mode"),
]

STATUS_OK   = "✓  OK"
STATUS_WARN = "⚠  Không bắt buộc"
STATUS_FAIL = "✗  Thiếu / Lỗi"

COLOR_OK   = "#27AE60"
COLOR_WARN = "#E67E22"
COLOR_FAIL = "#C0392B"


class SetupScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self._rows: dict = {}
        self._build_ui()
        self._run_checks()

    def _build_ui(self):
        title_lbl = tk.Label(
            self,
            text="KIỂM TRA MÔI TRƯỜNG VÀ CẤU HÌNH HỆ THỐNG",
            font=FONT_TITLE,
            bg=CONT_BG, fg=TEXT_H
        )
        title_lbl.pack(anchor="w", padx=20, pady=15)

        desc_lbl = tk.Label(
            self,
            text="Hệ thống sẽ xác minh tất cả thành phần cần thiết trước khi bạn bắt đầu quy trình phân tích.",
            font=("Segoe UI", 9, "italic"),
            bg=CONT_BG, fg=TEXT_M
        )
        desc_lbl.pack(anchor="w", padx=20, pady=(0, 10))

        # Bảng kiểm tra
        tbl_shadow = tk.Frame(self, bg=CARD_SHD)
        tbl_shadow.pack(fill="both", expand=True, padx=20, pady=(0, 8))
        table_frame = tk.Frame(tbl_shadow, bg=CARD_BG,
                               highlightbackground=CARD_BDR, highlightthickness=1)
        table_frame.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        # Card header
        tbl_hdr = tk.Frame(table_frame, bg="#EEF3FC")
        tbl_hdr.pack(fill="x")
        tk.Frame(table_frame, bg=ACE_BLUE, height=3).place(x=0, y=0, relwidth=1)
        tk.Label(tbl_hdr, text="Kết quả kiểm tra thành phần",
                 font=("Segoe UI", 11, "bold"),
                 bg="#EEF3FC", fg=TEXT_H, anchor="w",
                 padx=14, pady=9).pack(anchor="w")
        tk.Frame(table_frame, bg=CARD_BDR, height=1).pack(fill="x")

        # Inner grid container (separate from pack-managed header)
        grid_frame = tk.Frame(table_frame, bg=CARD_BG)
        grid_frame.pack(fill="both", expand=True, padx=4, pady=4)

        # Table header row
        hdr_bg = "#E0E8F8"
        for col, (text, width) in enumerate([
            ("Thành phần", 220), ("Mô tả", 340), ("Trạng thái", 160), ("Chi tiết", 280)
        ]):
            tk.Label(
                grid_frame, text=text, font=("Segoe UI", 9, "bold"),
                bg=hdr_bg, fg=TEXT_H, width=width // 8, anchor="w", padx=8, pady=5
            ).grid(row=0, column=col, sticky="ew", padx=1, pady=1)

        # Hàng dữ liệu
        for row_idx, (key, name, desc) in enumerate(CHECKS, start=1):
            row_bg = CARD_BG if row_idx % 2 == 0 else "#F7F9FD"

            name_lbl = tk.Label(grid_frame, text=name, font=("Segoe UI", 9, "bold"),
                                 bg=row_bg, fg=TEXT_H, anchor="w", padx=8, pady=7)
            name_lbl.grid(row=row_idx, column=0, sticky="ew", padx=1, pady=1)

            desc_lbl2 = tk.Label(grid_frame, text=desc, font=FONT_NORMAL,
                                  bg=row_bg, fg=TEXT_M, anchor="w", padx=8, pady=7)
            desc_lbl2.grid(row=row_idx, column=1, sticky="ew", padx=1, pady=1)

            status_lbl = tk.Label(grid_frame, text="...", font=("Segoe UI", 9, "bold"),
                                   bg=row_bg, fg="#95A5A6", anchor="w", padx=8, pady=7)
            status_lbl.grid(row=row_idx, column=2, sticky="ew", padx=1, pady=1)

            detail_lbl = tk.Label(grid_frame, text="", font=FONT_MONO,
                                   bg=row_bg, fg=TEXT_M, anchor="w", padx=8, pady=7,
                                   wraplength=270, justify="left")
            detail_lbl.grid(row=row_idx, column=3, sticky="ew", padx=1, pady=1)

            self._rows[key] = (status_lbl, detail_lbl, row_bg)

        grid_frame.grid_columnconfigure(1, weight=1)
        grid_frame.grid_columnconfigure(3, weight=1)

        # Tổng kết + nút
        bottom_frame = tk.Frame(self, bg=CONT_BG)
        bottom_frame.pack(fill="x", padx=20, pady=10)

        self.summary_var = tk.StringVar(value="")
        self.summary_lbl = tk.Label(
            bottom_frame, textvariable=self.summary_var,
            font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H
        )
        self.summary_lbl.pack(side="left")

        btn_recheck = tk.Button(
            bottom_frame, text="Kiểm Tra Lại",
            font=("Segoe UI", 9, "bold"),
            bg=ACE_BLUE, fg="#FFFFFF", relief="flat", bd=0, padx=15, pady=6,
            cursor="hand2", command=self._run_checks
        )
        btn_recheck.pack(side="right")

        tip_shadow = tk.Frame(self, bg=CARD_SHD)
        tip_shadow.pack(fill="x", padx=20, pady=(0, 14))
        tip_frame = tk.Frame(tip_shadow, bg=CARD_BG,
                             highlightbackground=CARD_BDR, highlightthickness=1)
        tip_frame.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))
        tip_inner = tk.Frame(tip_frame, bg=CARD_BG)
        tip_inner.pack(fill="x", padx=14, pady=10)
        tk.Label(tip_inner, text="Hướng dẫn", font=("Segoe UI", 9, "bold"),
                 bg=CARD_BG, fg=TEXT_M).pack(anchor="w", pady=(0, 4))
        tk.Label(
            tip_inner,
            text="• ✓ OK: sẵn sàng sử dụng.\n"
                 "• ⚠ Không bắt buộc: tính năng liên quan bị tắt nhưng không ảnh hưởng luồng chính.\n"
                 "• ✗ Thiếu / Lỗi: cần cài đặt hoặc cấu hình lại trước khi dùng.\n"
                 "• yarGen.py: đặt vào thư mục gốc dự án (cùng cấp main.py) để dùng Generate nâng cao.",
            font=FONT_SMALL, bg=CARD_BG, fg=TEXT_M,
            justify="left"
        ).pack(anchor="w")

    def _update_row(self, key: str, status_text: str, status_color: str, detail: str):
        status_lbl, detail_lbl, _ = self._rows[key]
        status_lbl.config(text=status_text, fg=status_color)
        detail_lbl.config(text=detail)

    def _run_checks(self):
        self.summary_var.set("Đang kiểm tra...")
        self.update_idletasks()

        ok_count = 0
        fail_count = 0

        # 1. Python executable
        py_path = sys.executable
        self._update_row("python_exe", STATUS_OK, COLOR_OK, py_path)
        ok_count += 1

        # 2. yarGen.py
        yargen_path = os.path.join(self.state.base_dir, "yarGen.py")
        if os.path.isfile(yargen_path):
            self._update_row("yargen_py", STATUS_OK, COLOR_OK, yargen_path)
            ok_count += 1
        else:
            self._update_row(
                "yargen_py", STATUS_FAIL, COLOR_FAIL,
                f"Không tìm thấy tại: {yargen_path}\n→ Tải từ github.com/Neo23x0/yarGen"
            )
            fail_count += 1

        # 3. dbs/
        dbs_dir = self.state.dbs_dir
        if os.path.isdir(dbs_dir):
            files = [f for f in os.listdir(dbs_dir) if os.path.isfile(os.path.join(dbs_dir, f))]
            self._update_row("dbs_dir", STATUS_OK, COLOR_OK, f"{len(files)} file(s) trong {dbs_dir}")
            ok_count += 1
        else:
            self._update_row("dbs_dir", STATUS_FAIL, COLOR_FAIL, f"Thư mục không tồn tại: {dbs_dir}")
            fail_count += 1

        # 4. rules/
        rules_dir = self.state.rules_dir
        os.makedirs(rules_dir, exist_ok=True)
        self._update_row("rules_dir", STATUS_OK, COLOR_OK, rules_dir)
        ok_count += 1

        # 5. reports/
        reports_dir = self.state.reports_dir
        os.makedirs(reports_dir, exist_ok=True)
        self._update_row("reports_dir", STATUS_OK, COLOR_OK, reports_dir)
        ok_count += 1

        # 6. yara64.exe (optional)
        yara_exe = os.path.join(self.state.yara_3rdparty_dir, "yara64.exe")
        if os.path.isfile(yara_exe):
            self._update_row("yara64_exe", STATUS_OK, COLOR_OK, yara_exe)
            ok_count += 1
        else:
            self._update_row("yara64_exe", STATUS_WARN, COLOR_WARN,
                             f"Không tìm thấy. Đặt yara64.exe vào:\n{self.state.yara_3rdparty_dir}")

        # 7. pefile
        try:
            import pefile as _pefile
            ver = getattr(_pefile, "__version__", "installed")
            self._update_row("pefile_mod", STATUS_OK, COLOR_OK, f"pefile {ver}")
            ok_count += 1
        except ImportError:
            self._update_row("pefile_mod", STATUS_FAIL, COLOR_FAIL, "pip install pefile")
            fail_count += 1

        # 8. yara-python
        try:
            import yara as _yara
            ver = getattr(_yara, "__version__", "installed")
            self._update_row("yara_mod", STATUS_OK, COLOR_OK, f"yara-python {ver}")
            ok_count += 1
        except ImportError:
            self._update_row("yara_mod", STATUS_WARN, COLOR_WARN,
                             "pip install yara-python  (fallback sang YARA CLI nếu có)")

        # 9. Flask
        try:
            import flask as _flask
            ver = getattr(_flask, "__version__", "installed")
            self._update_row("flask_mod", STATUS_OK, COLOR_OK, f"Flask {ver}")
            ok_count += 1
        except ImportError:
            self._update_row("flask_mod", STATUS_WARN, COLOR_WARN,
                             "pip install Flask  (cần cho Web Mode)")

        # Tổng kết
        total = len(CHECKS)
        if fail_count == 0:
            self.summary_var.set(f"✓  Tất cả {ok_count}/{total} thành phần sẵn sàng. Bạn có thể bắt đầu phân tích!")
            self.summary_lbl.config(fg=STAT_OK)
        else:
            self.summary_var.set(f"⚠  {fail_count} thành phần cần chú ý. Một số tính năng có thể bị giới hạn.")
            self.summary_lbl.config(fg=STAT_WARN)
