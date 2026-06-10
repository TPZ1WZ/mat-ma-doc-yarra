import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core.state import AppState
from core.yara_score import YaraScoreAnalyzer
from core.theme import *


class ReportsScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.score_analyzer = YaraScoreAnalyzer()
        self._build_ui()
        self._refresh_reports_list()

    def _build_ui(self):
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="QUẢN LÝ, ĐỌC BÁO CÁO VÀ PHÂN TÍCH ĐIỂM LUẬT YARA",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 10))

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # ── Tab 1: Reports viewer ─────────────────────────────────
        self._tab_viewer = tk.Frame(self.nb, bg=CONT_BG)
        self.nb.add(self._tab_viewer, text="  Xem Báo Cáo  ")
        self._build_viewer_tab()

        # ── Tab 2: Rule Score Report ──────────────────────────────
        self._tab_score = tk.Frame(self.nb, bg=CONT_BG)
        self.nb.add(self._tab_score, text="  Rule Score Report  ")
        self._build_score_tab()

    # ─────── Tab 1: Viewer ───────────────────────────────────────
    def _build_viewer_tab(self):
        tab = self._tab_viewer

        top_frame = tk.Frame(tab, bg=CONT_BG)
        top_frame.pack(fill="x", pady=(8, 4), padx=8)

        tk.Button(top_frame, text="Tải lại danh sách", font=("Segoe UI", 9), bg="#34495E", fg="#FFFFFF",
                  bd=0, padx=10, pady=4, cursor="hand2", command=self._refresh_reports_list).pack(side="left")
        tk.Button(top_frame, text="Xóa file đã chọn", font=("Segoe UI", 9), bg="#C0392B", fg="#FFFFFF",
                  bd=0, padx=10, pady=4, cursor="hand2", command=self._delete_selected_file).pack(side="left", padx=6)
        tk.Label(top_frame, text="(Hiển thị file .md, .csv, .yar trong reports/ và rules/)",
                 font=("Segoe UI", 8, "italic"), bg=CONT_BG, fg="#95A5A6").pack(side="left", padx=8)

        paned = tk.PanedWindow(tab, orient="horizontal", bg="#BDC3C7", sashwidth=4)
        paned.pack(fill="both", expand=True, padx=8, pady=4)

        left = tk.Frame(paned, bg=CONT_BG)
        self.files_listbox = tk.Listbox(left, font=("Segoe UI", 9), bd=1, relief="solid", selectbackground="#2980B9")
        self.files_listbox.pack(fill="both", expand=True)
        self.files_listbox.bind("<<ListboxSelect>>", self._on_file_selected)
        paned.add(left, width=240)

        right = tk.Frame(paned, bg=CONT_BG)
        self.viewer_text = tk.Text(right, font=("Consolas", 9), bg=CARD_BG, fg=TEXT_H, bd=1, relief="solid", wrap="word")
        _sb = tk.Scrollbar(right, orient="vertical", command=self.viewer_text.yview)
        self.viewer_text.configure(yscrollcommand=_sb.set)
        self.viewer_text.pack(side="left", fill="both", expand=True)
        _sb.pack(side="right", fill="y")
        paned.add(right)

    def _refresh_reports_list(self):
        self.files_listbox.delete(0, tk.END)
        self.files_listbox._paths = []          # reset mỗi lần refresh
        files = []
        for directory in [self.state.reports_dir, self.state.rules_dir]:
            if os.path.isdir(directory):
                for f in os.listdir(directory):
                    if f.endswith((".md", ".csv", ".yar")):
                        files.append((os.path.getmtime(os.path.join(directory, f)), directory, f))
        files.sort(reverse=True)
        for _, directory, fname in files:
            label = f"[rules] {fname}" if directory == self.state.rules_dir else fname
            self.files_listbox.insert(tk.END, label)
            self.files_listbox._paths.append(os.path.join(directory, fname))

    def _delete_selected_file(self):
        sel = self.files_listbox.curselection()
        if not sel:
            messagebox.showinfo("Thông báo", "Chưa chọn file nào.")
            return
        idx = sel[0]
        paths = getattr(self.files_listbox, "_paths", [])
        if idx >= len(paths):
            return
        full_path = paths[idx]
        fname = os.path.basename(full_path)
        if not messagebox.askyesno("Xác nhận xóa", f"Bạn có chắc muốn xóa file:\n{fname}?"):
            return
        try:
            os.remove(full_path)
            self.viewer_text.delete("1.0", tk.END)
            self._refresh_reports_list()
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể xóa file: {str(e)}")

    def _on_file_selected(self, event):
        sel = self.files_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        paths = getattr(self.files_listbox, "_paths", [])
        if idx >= len(paths):
            return
        full_path = paths[idx]
        self.viewer_text.delete("1.0", tk.END)
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                self.viewer_text.insert(tk.END, f.read())
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể đọc file: {str(e)}")

    # ─────── Tab 2: Score Report ─────────────────────────────────
    def _build_score_tab(self):
        tab = self._tab_score
        self._score_data = []
        self._selected_yar_path = None   # None = tất cả files trong rules/

        # ── Hàng 1: Nguồn phân tích ──────────────────────────────
        src_row = tk.Frame(tab, bg=CONT_BG)
        src_row.pack(fill="x", padx=8, pady=(8, 4))
        tk.Label(src_row, text="Nguồn:", font=("Segoe UI", 9),
                 bg=CONT_BG, fg=TEXT_N).pack(side="left")
        self._yar_source_var = tk.StringVar(value="Tất cả file trong rules/")
        tk.Entry(src_row, textvariable=self._yar_source_var,
                 font=("Segoe UI", 9), bd=1, relief="solid",
                 state="readonly").pack(side="left", fill="x", expand=True, padx=(6, 6))
        tk.Button(src_row, text="Browse .yar", font=("Segoe UI", 9),
                  bg="#475569", fg="#FFFFFF", bd=0, padx=8, pady=3,
                  cursor="hand2", command=self._browse_yar_file).pack(side="left", padx=(0, 4))
        tk.Button(src_row, text="Tất cả", font=("Segoe UI", 9),
                  bg="#64748B", fg="#FFFFFF", bd=0, padx=8, pady=3,
                  cursor="hand2", command=self._use_all_yar_files).pack(side="left")

        # ── Hàng 2: Nút hành động ────────────────────────────────
        btn_row = tk.Frame(tab, bg=CONT_BG)
        btn_row.pack(fill="x", padx=8, pady=(0, 6))
        tk.Button(btn_row, text="▶  Phân Tích Điểm", font=("Segoe UI", 9, "bold"),
                  bg="#8E44AD", fg="#FFFFFF", relief="flat", bd=0, padx=12, pady=5,
                  cursor="hand2", command=self._run_score_analysis).pack(side="left")
        tk.Button(btn_row, text="Xuất CSV", font=("Segoe UI", 9), bg="#27AE60", fg="#FFFFFF",
                  bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._export_score_csv).pack(side="left", padx=8)
        tk.Button(btn_row, text="↺  Reset", font=("Segoe UI", 9), bg="#C0392B", fg="#FFFFFF",
                  bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._reset_score_tab).pack(side="left")

        # ── Stats cards ──────────────────────────────────────────
        stats_frame = tk.Frame(tab, bg=CONT_BG)
        stats_frame.pack(fill="x", padx=8, pady=(0, 6))
        self._score_stat_vars = {}
        for label in ["Tổng luật", "Max Score", "Avg Score", "Min Score"]:
            s = tk.Frame(stats_frame, bg=CARD_SHD)
            s.pack(side="left", padx=(0, 8))
            card = tk.Frame(s, bg=CARD_BG, highlightbackground=CARD_BDR, highlightthickness=1)
            card.pack(padx=(0, 2), pady=(0, 2), ipadx=14, ipady=5)
            v = tk.StringVar(value="—")
            tk.Label(card, textvariable=v, font=("Segoe UI", 16, "bold"),
                     bg=CARD_BG, fg=TEXT_H).pack()
            tk.Label(card, text=label, font=("Segoe UI", 8), bg=CARD_BG, fg=TEXT_M).pack()
            self._score_stat_vars[label] = v

        # ── Biểu đồ có scrollbar ngang ──────────────────────────
        cf_shadow = tk.Frame(tab, bg=CARD_SHD)
        cf_shadow.pack(fill="x", padx=8, pady=(0, 6))
        cf_card = tk.Frame(cf_shadow, bg=CARD_BG,
                           highlightbackground=CARD_BDR, highlightthickness=1)
        cf_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))
        cf_hdr = tk.Frame(cf_card, bg="#EEF3FC")
        cf_hdr.pack(fill="x")
        tk.Label(cf_hdr, text="  Biểu đồ Score theo từng rule (cuộn ngang nếu nhiều rule)",
                 font=("Segoe UI", 9, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=4, pady=6).pack(anchor="w")
        tk.Frame(cf_card, bg=CARD_BDR, height=1).pack(fill="x")
        chart_wrap = tk.Frame(cf_card, bg=CARD_BG)
        chart_wrap.pack(fill="x", padx=5, pady=(5, 0))
        self.chart_canvas = tk.Canvas(chart_wrap, height=120, bg=CARD_BG,
                                      bd=0, highlightthickness=0)
        self.chart_canvas.pack(fill="x")
        self._chart_xsb = tk.Scrollbar(cf_card, orient="horizontal",
                                        command=self.chart_canvas.xview)
        self._chart_xsb.pack(fill="x", padx=5, pady=(0, 4))
        self.chart_canvas.configure(xscrollcommand=self._chart_xsb.set)

        # ── Bảng kết quả ────────────────────────────────────────
        table_frame = tk.Frame(tab, bg=CONT_BG)
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        self.score_tree = ttk.Treeview(
            table_frame,
            columns=("rule", "file", "score", "rating", "strings", "short", "generic", "warnings"),
            show="headings"
        )
        headers = [
            ("rule",     "Tên Rule",      200),
            ("file",     "File nguồn",    140),
            ("score",    "Điểm",           55),
            ("rating",   "Xếp loại",       80),
            ("strings",  "Strings",         65),
            ("short",    "Ngắn",            55),
            ("generic",  "Generic",         65),
            ("warnings", "Cảnh báo",        70),
        ]
        for col, text, width in headers:
            self.score_tree.heading(col, text=text)
            self.score_tree.column(col, width=width,
                                   anchor="center" if col not in ("rule", "file") else "w")
        self.score_tree.bind("<<TreeviewSelect>>", self._on_score_row_select)

        sb_v = ttk.Scrollbar(table_frame, orient="vertical",   command=self.score_tree.yview)
        sb_h = ttk.Scrollbar(table_frame, orient="horizontal", command=self.score_tree.xview)
        self.score_tree.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        self.score_tree.pack(side="left", fill="both", expand=True)
        sb_v.pack(side="right", fill="y")
        sb_h.pack(side="bottom", fill="x")

        # ── Panel cảnh báo chi tiết ──────────────────────────────
        warn_shadow = tk.Frame(tab, bg=CARD_SHD)
        warn_shadow.pack(fill="x", padx=8, pady=(0, 8))
        warn_card = tk.Frame(warn_shadow, bg=CARD_BG,
                             highlightbackground=CARD_BDR, highlightthickness=1)
        warn_card.pack(fill="both", padx=(0, 2), pady=(0, 2))
        warn_hdr = tk.Frame(warn_card, bg="#FFF7ED")
        warn_hdr.pack(fill="x")
        tk.Label(warn_hdr, text="  Chi tiết cảnh báo — click vào dòng bất kỳ trong bảng",
                 font=("Segoe UI", 9, "bold"), bg="#FFF7ED", fg="#92400E",
                 padx=4, pady=5).pack(anchor="w")
        tk.Frame(warn_card, bg=CARD_BDR, height=1).pack(fill="x")
        self.warn_text = tk.Text(warn_card, height=4, font=("Segoe UI", 9),
                                  bg=CARD_BG, fg=TEXT_H, bd=0, wrap="word",
                                  state="disabled", padx=8, pady=6)
        self.warn_text.pack(fill="x")

    # ── Score tab handlers ────────────────────────────────────────
    def _browse_yar_file(self):
        path = filedialog.askopenfilename(
            title="Chọn file luật YARA cần phân tích điểm",
            initialdir=self.state.rules_dir,
            filetypes=[("YARA Rules", "*.yar"), ("All files", "*.*")]
        )
        if path:
            self._selected_yar_path = path
            self._yar_source_var.set(os.path.basename(path))

    def _use_all_yar_files(self):
        self._selected_yar_path = None
        self._yar_source_var.set("Tất cả file trong rules/")

    def _reset_score_tab(self):
        self._score_data = []
        self._selected_yar_path = None
        self._yar_source_var.set("Tất cả file trong rules/")
        for v in self._score_stat_vars.values():
            v.set("—")
        for row in self.score_tree.get_children():
            self.score_tree.delete(row)
        self.chart_canvas.delete("all")
        self.chart_canvas.configure(scrollregion=(0, 0, 0, 0))
        self.warn_text.config(state="normal")
        self.warn_text.delete("1.0", tk.END)
        self.warn_text.config(state="disabled")

    def _on_score_row_select(self, _event=None):
        sel = self.score_tree.selection()
        if not sel:
            return
        rule_name = self.score_tree.item(sel[0])["values"][0]
        rule_data = next((r for r in self._score_data if r["rule_name"] == rule_name), None)
        if not rule_data:
            return
        warnings = rule_data.get("warnings", [])
        self.warn_text.config(state="normal")
        self.warn_text.delete("1.0", tk.END)
        if warnings:
            for i, w in enumerate(warnings, 1):
                self.warn_text.insert(tk.END, f"  {i}. ⚠  {w}\n")
        else:
            self.warn_text.insert(tk.END,
                f"  ✓  Rule '{rule_name}' không có cảnh báo — đạt chất lượng tốt.")
        self.warn_text.config(state="disabled")

    def _run_score_analysis(self):
        if self._selected_yar_path:
            yar_files = [self._selected_yar_path]
        else:
            rules_dir = self.state.rules_dir
            if not os.path.isdir(rules_dir):
                messagebox.showinfo("Thông báo", f"Thư mục rules/ không tồn tại: {rules_dir}")
                return
            yar_files = [os.path.join(rules_dir, f)
                         for f in os.listdir(rules_dir) if f.endswith(".yar")]
        if not yar_files:
            messagebox.showinfo("Thông báo", "Chưa có file luật .yar nào để phân tích.")
            return

        all_rules = []
        for yar_path in yar_files:
            result = self.score_analyzer.analyze_rule_file(yar_path)
            if "error" not in result:
                for r in result.get("rules", []):
                    r["file"] = os.path.basename(yar_path)
                    all_rules.append(r)

        if not all_rules:
            messagebox.showinfo("Thông báo", "Không phân tích được rule nào.")
            return

        self._score_data = all_rules
        self._display_score_results(all_rules)

    def _display_score_results(self, rules: list):
        for row in self.score_tree.get_children():
            self.score_tree.delete(row)
        self.warn_text.config(state="normal")
        self.warn_text.delete("1.0", tk.END)
        self.warn_text.config(state="disabled")

        scores = [r["score"] for r in rules]
        self._score_stat_vars["Tổng luật"].set(str(len(rules)))
        self._score_stat_vars["Max Score"].set(str(max(scores)))
        self._score_stat_vars["Avg Score"].set(str(round(sum(scores) / len(scores), 1)))
        self._score_stat_vars["Min Score"].set(str(min(scores)))

        for r in sorted(rules, key=lambda x: x["score"], reverse=True):
            self.score_tree.insert("", "end", values=(
                r["rule_name"],
                r.get("file", ""),
                r["score"],
                r["rating"],
                r["string_count"],
                r.get("short_strings", 0),
                r.get("generic_strings", 0),
                len(r.get("warnings", [])),
            ))

        self._draw_chart(rules)

    def _draw_chart(self, rules: list):
        canvas = self.chart_canvas
        canvas.delete("all")
        canvas.update_idletasks()

        H = 110
        BAR_W = 28
        GAP = 6
        PADDING = 20
        color_map = {"Excellent": "#27AE60", "Good": "#3498DB", "Fair": "#E67E22", "Poor": "#C0392B"}

        sorted_rules = sorted(rules, key=lambda x: x["score"], reverse=True)
        n = len(sorted_rules)
        if n == 0:
            return

        total_w = PADDING * 2 + n * (BAR_W + GAP)
        canvas_w = max(canvas.winfo_width() or 600, total_w)
        canvas.configure(scrollregion=(0, 0, total_w, H + 10))

        for i, r in enumerate(sorted_rules):
            x0 = PADDING + i * (BAR_W + GAP)
            bar_h = int((r["score"] / 100) * (H - 20))
            y0 = H - bar_h - 5
            color = color_map.get(r["rating"], "#95A5A6")
            canvas.create_rectangle(x0, y0, x0 + BAR_W, H - 5, fill=color, outline="")
            canvas.create_text(x0 + BAR_W // 2, y0 - 7,
                               text=str(r["score"]), font=("Segoe UI", 7), fill=TEXT_H)

    def _export_score_csv(self):
        if not self._score_data:
            messagebox.showinfo("Thông báo", "Chưa có dữ liệu điểm. Nhấn 'Phân Tích Điểm' trước.")
            return
        import csv
        out_path = os.path.join(self.state.reports_dir, "rule_score_report.csv")
        try:
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Rule Name", "File", "Score", "Rating",
                                  "Strings", "Short Strings", "Generic Strings", "Warnings"])
                for r in self._score_data:
                    writer.writerow([
                        r["rule_name"], r.get("file", ""), r["score"], r["rating"],
                        r["string_count"], r.get("short_strings", 0),
                        r.get("generic_strings", 0),
                        "; ".join(r.get("warnings", []))
                    ])
            messagebox.showinfo("Thành công", f"Đã xuất CSV tại:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
