import os
import tkinter as tk
from tkinter import messagebox, ttk
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
            self.files_listbox._paths = getattr(self.files_listbox, "_paths", [])
            self.files_listbox._paths.append(os.path.join(directory, fname))

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

        top = tk.Frame(tab, bg=CONT_BG)
        top.pack(fill="x", padx=8, pady=8)

        tk.Button(top, text="Phân Tích Điểm Tất Cả Luật", font=("Segoe UI", 9, "bold"), bg="#8E44AD", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2", command=self._run_score_analysis).pack(side="left")

        tk.Button(top, text="Xuất CSV", font=("Segoe UI", 9), bg="#27AE60", fg="#FFFFFF",
                  bd=0, padx=10, pady=5, cursor="hand2", command=self._export_score_csv).pack(side="left", padx=8)

        # Summary stats
        stats_frame = tk.Frame(tab, bg=CONT_BG)
        stats_frame.pack(fill="x", padx=8, pady=(0, 6))
        self._score_stat_vars = {}
        for label in ["Tổng luật", "Max Score", "Avg Score", "Min Score"]:
            s = tk.Frame(stats_frame, bg=CARD_SHD)
            s.pack(side="left", padx=(0, 8))
            card = tk.Frame(s, bg=CARD_BG,
                            highlightbackground=CARD_BDR, highlightthickness=1)
            card.pack(padx=(0, 2), pady=(0, 2), ipadx=14, ipady=5)
            v = tk.StringVar(value="—")
            tk.Label(card, textvariable=v, font=("Segoe UI", 16, "bold"),
                     bg=CARD_BG, fg=TEXT_H).pack()
            tk.Label(card, text=label, font=("Segoe UI", 8),
                     bg=CARD_BG, fg=TEXT_M).pack()
            self._score_stat_vars[label] = v

        # Score bar chart (canvas)
        cf_shadow = tk.Frame(tab, bg=CARD_SHD)
        cf_shadow.pack(fill="x", padx=8, pady=(0, 6))
        cf_card = tk.Frame(cf_shadow, bg=CARD_BG,
                           highlightbackground=CARD_BDR, highlightthickness=1)
        cf_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))
        cf_hdr = tk.Frame(cf_card, bg="#EEF3FC")
        cf_hdr.pack(fill="x")
        tk.Label(cf_hdr, text="  Biểu đồ Max Score theo từng rule",
                 font=("Segoe UI", 9, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=4, pady=6).pack(anchor="w")
        tk.Frame(cf_card, bg=CARD_BDR, height=1).pack(fill="x")
        self.chart_canvas = tk.Canvas(cf_card, height=120, bg=CARD_BG,
                                      bd=0, highlightthickness=0)
        self.chart_canvas.pack(fill="x", padx=5, pady=5)

        # Table
        table_frame = tk.Frame(tab, bg=CONT_BG)
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.score_tree = ttk.Treeview(
            table_frame,
            columns=("rule", "score", "rating", "strings", "short", "generic", "warnings"),
            show="headings"
        )
        headers = [
            ("rule",     "Tên Rule",         200),
            ("score",    "Điểm",              60),
            ("rating",   "Xếp loại",          90),
            ("strings",  "Strings",           70),
            ("short",    "Ngắn",              60),
            ("generic",  "Generic",           70),
            ("warnings", "Cảnh báo",         120),
        ]
        for col, text, width in headers:
            self.score_tree.heading(col, text=text)
            self.score_tree.column(col, width=width, anchor="center" if col != "rule" else "w")

        sb_v = ttk.Scrollbar(table_frame, orient="vertical",   command=self.score_tree.yview)
        sb_h = ttk.Scrollbar(table_frame, orient="horizontal", command=self.score_tree.xview)
        self.score_tree.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)
        self.score_tree.pack(side="left", fill="both", expand=True)
        sb_v.pack(side="right", fill="y")
        sb_h.pack(side="bottom", fill="x")

        self._score_data = []

    def _run_score_analysis(self):
        rules_dir = self.state.rules_dir
        if not os.path.isdir(rules_dir):
            messagebox.showinfo("Thông báo", f"Thư mục rules/ không tồn tại: {rules_dir}")
            return

        yar_files = [os.path.join(rules_dir, f) for f in os.listdir(rules_dir) if f.endswith(".yar")]
        if not yar_files:
            messagebox.showinfo("Thông báo", "Chưa có file luật .yar nào trong thư mục rules/.")
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
        # Clear table
        for row in self.score_tree.get_children():
            self.score_tree.delete(row)

        scores = [r["score"] for r in rules]
        self._score_stat_vars["Tổng luật"].set(str(len(rules)))
        self._score_stat_vars["Max Score"].set(str(max(scores)))
        self._score_stat_vars["Avg Score"].set(str(round(sum(scores) / len(scores), 1)))
        self._score_stat_vars["Min Score"].set(str(min(scores)))

        for r in sorted(rules, key=lambda x: x["score"], reverse=True):
            self.score_tree.insert("", "end", values=(
                r["rule_name"],
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
        W = canvas.winfo_width() or 600
        H = 110
        padding = 30
        bar_area_w = W - padding * 2
        n = min(len(rules), 20)
        if n == 0:
            return

        bar_w = max(6, bar_area_w // n - 4)
        max_score = 100
        color_map = {"Excellent": "#27AE60", "Good": "#3498DB", "Fair": "#E67E22", "Poor": "#C0392B"}

        sorted_rules = sorted(rules, key=lambda x: x["score"], reverse=True)[:n]
        for i, r in enumerate(sorted_rules):
            x0 = padding + i * (bar_area_w // n)
            bar_h = int((r["score"] / max_score) * (H - 20))
            y0 = H - bar_h - 5
            color = color_map.get(r["rating"], "#95A5A6")
            canvas.create_rectangle(x0, y0, x0 + bar_w, H - 5, fill=color, outline="")
            canvas.create_text(x0 + bar_w // 2, y0 - 5, text=str(r["score"]), font=("Segoe UI", 7), fill=TEXT_H)

    def _export_score_csv(self):
        if not self._score_data:
            messagebox.showinfo("Thông báo", "Chưa có dữ liệu điểm. Nhấn 'Phân Tích Điểm' trước.")
            return
        import csv
        out_path = os.path.join(self.state.reports_dir, "rule_score_report.csv")
        try:
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Rule Name", "Score", "Rating", "Strings", "Short Strings", "Generic Strings", "Warnings"])
                for r in self._score_data:
                    writer.writerow([r["rule_name"], r["score"], r["rating"], r["string_count"],
                                     r.get("short_strings", 0), r.get("generic_strings", 0), len(r.get("warnings", []))])
            messagebox.showinfo("Thành công", f"Đã xuất CSV tại:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))
