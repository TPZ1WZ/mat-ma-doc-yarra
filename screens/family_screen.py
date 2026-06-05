import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core.state import AppState
from core.family_signature import FamilySignatureGenerator
from core.theme import *


class FamilyScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.sig_generator = FamilySignatureGenerator()
        self._build_ui()

    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="TRÍCH XUẤT ĐẶC TRƯNG CHUNG HỌ MÃ ĐỘC",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left", anchor="w")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 14))

        # ── Config card ───────────────────────────────────────────────
        cfg_shadow = tk.Frame(self, bg=CARD_SHD)
        cfg_shadow.pack(fill="x", padx=20, pady=(0, 12))
        cfg_card = tk.Frame(cfg_shadow, bg=CARD_BG,
                            highlightbackground=CARD_BDR, highlightthickness=1)
        cfg_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        # Card header strip
        cfg_hdr = tk.Frame(cfg_card, bg="#EEF3FC")
        cfg_hdr.pack(fill="x")
        tk.Frame(cfg_card, bg=ACE_TEAL, height=3).place(x=0, y=0, relwidth=1)
        cfg_hdr_inner = tk.Frame(cfg_hdr, bg="#EEF3FC")
        cfg_hdr_inner.pack(fill="x", padx=14, pady=(10, 8))
        tk.Label(cfg_hdr_inner, text="Cấu hình tập mẫu họ mã độc",
                 font=("Segoe UI", 11, "bold"),
                 bg="#EEF3FC", fg=TEXT_H).pack(anchor="w")
        tk.Frame(cfg_card, bg=CARD_BDR, height=1).pack(fill="x")

        cfg_body = tk.Frame(cfg_card, bg=CARD_BG)
        cfg_body.pack(fill="x", padx=14, pady=12)

        # Row 1: Directory
        row1 = tk.Frame(cfg_body, bg=CARD_BG)
        row1.pack(fill="x", pady=(0, 10))
        tk.Label(row1, text="Thư mục họ mẫu:",
                 font=("Segoe UI", 10), bg=CARD_BG, fg=TEXT_N,
                 width=22, anchor="w").pack(side="left")
        self.dir_path_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.dir_path_var,
                 font=("Segoe UI", 10), bd=1, relief="solid"
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row1, text="Browse…",
                  font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=4, cursor="hand2",
                  command=self._browse_directory).pack(side="left")

        # Row 2: Coverage slider
        row2 = tk.Frame(cfg_body, bg=CARD_BG)
        row2.pack(fill="x")
        tk.Label(row2, text="Tỷ lệ bao phủ (Coverage):",
                 font=("Segoe UI", 10), bg=CARD_BG, fg=TEXT_N,
                 width=22, anchor="w").pack(side="left")

        self.coverage_var = tk.DoubleVar(value=0.6)
        self.coverage_lbl_var = tk.StringVar(value="60%")

        def update_coverage_label(val):
            self.coverage_lbl_var.set(f"{float(val)*100:.0f}%")

        slider = tk.Scale(row2, from_=0.1, to=1.0, resolution=0.05,
                          orient="horizontal", variable=self.coverage_var,
                          bg=CARD_BG, bd=0, highlightthickness=0,
                          fg=TEXT_N, troughcolor=CARD_BDR,
                          command=update_coverage_label)
        slider.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Label(row2, textvariable=self.coverage_lbl_var,
                 font=("Segoe UI", 10, "bold"),
                 bg=CARD_BG, fg=ACE_TEAL, width=5).pack(side="left", padx=(0, 12))

        tk.Button(row2, text="⚙  Tìm Đặc Trưng Chung",
                  font=("Segoe UI", 10, "bold"),
                  bg=ACE_TEAL, fg="#FFFFFF",
                  relief="flat", bd=0, padx=16, pady=6, cursor="hand2",
                  command=self._process_family).pack(side="left")

        # ── Results card ──────────────────────────────────────────────
        res_shadow = tk.Frame(self, bg=CARD_SHD)
        res_shadow.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        res_card = tk.Frame(res_shadow, bg=CARD_BG,
                            highlightbackground=CARD_BDR, highlightthickness=1)
        res_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        res_hdr = tk.Frame(res_card, bg="#EEF3FC")
        res_hdr.pack(fill="x")
        res_hdr_inner = tk.Frame(res_hdr, bg="#EEF3FC")
        res_hdr_inner.pack(fill="x", padx=14, pady=(8, 6))
        tk.Label(res_hdr_inner,
                 text="Các đặc trưng chung thỏa mãn điều kiện bao phủ",
                 font=("Segoe UI", 11, "bold"),
                 bg="#EEF3FC", fg=TEXT_H).pack(side="left")
        self.result_count_var = tk.StringVar(value="")
        tk.Label(res_hdr_inner, textvariable=self.result_count_var,
                 font=("Segoe UI", 9), bg="#EEF3FC", fg=TEXT_M).pack(side="left", padx=(12, 0))
        tk.Frame(res_card, bg=CARD_BDR, height=1).pack(fill="x")

        tree_frame = tk.Frame(res_card, bg=CARD_BG)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=8)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("No", "String", "Count", "Percentage"),
            show="headings"
        )
        self.tree.heading("No",         text="STT")
        self.tree.heading("String",     text="Chuỗi đặc trưng tĩnh trích xuất được")
        self.tree.heading("Count",      text="Số mẫu xuất hiện")
        self.tree.heading("Percentage", text="Tỷ lệ (%)")

        self.tree.column("No",         width=50,  anchor="center")
        self.tree.column("String",     width=600, anchor="w")
        self.tree.column("Count",      width=130, anchor="center")
        self.tree.column("Percentage", width=100, anchor="center")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ── Handlers ─────────────────────────────────────────────────────
    def _browse_directory(self):
        d = filedialog.askdirectory(title="Chọn thư mục chứa tập mẫu của họ mã độc")
        if d:
            self.dir_path_var.set(d)
            self.state.selected_family_dir = d

    def _process_family(self):
        dir_path = self.dir_path_var.get().strip()
        if not dir_path or not os.path.isdir(dir_path):
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một thư mục chứa mẫu hợp lệ trước!")
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.result_count_var.set("Đang xử lý...")

        def _worker():
            res = self.sig_generator.process_family_directory(
                dir_path, coverage=self.coverage_var.get()
            )
            self.after(0, lambda: self._display_features(res))

        threading.Thread(target=_worker, daemon=True).start()

    def _display_features(self, res):
        if "error" in res:
            messagebox.showerror("Lỗi", res["error"])
            self.result_count_var.set("")
            return
        features = res.get("features", [])
        if not features:
            messagebox.showinfo(
                "Thông báo",
                f"Không tìm thấy chuỗi chung nào đạt ngưỡng "
                f"{self.coverage_var.get()*100:.0f}% trên {res['total_samples']} mẫu."
            )
            self.result_count_var.set("Không tìm thấy đặc trưng")
            return

        for idx, feat in enumerate(features, start=1):
            self.tree.insert("", "end", values=(
                idx,
                feat["string"],
                f"{feat['appearance_count']}/{res['total_samples']}",
                f"{feat['percentage']:.1f}%"
            ))

        self.result_count_var.set(
            f"— {len(features)} đặc trưng tìm được từ {res['total_samples']} mẫu"
        )
        messagebox.showinfo(
            "Thành công",
            f"Đã quét {res['total_samples']} mẫu.\n"
            f"Tìm thấy {len(features)} chuỗi đặc trưng chung!"
        )
