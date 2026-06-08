import os
import re
import math
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core.state import AppState
from core.sample_analyzer import SampleAnalyzer
from core.analyst_report import AnalystReportGenerator
from core.analysis_common import format_file_size
from core.theme import *

# Behavior hint rules: (category, display_name, keywords)
BEHAVIOR_HINTS = [
    ("Network",            "Network Activity",      ["http", "https", "socket", "connect", "recv", "send", "wget", "curl", "urldownloadtofile", "internetopen", "wininet"]),
    ("Persistence",        "Persistence",           ["runonce", "currentversion\\run", "schtasks", "startup", "autorun", "regsetvalueex"]),
    ("Process Injection",  "Process Injection",     ["writeprocessmemory", "createremotethread", "ntcreatethreadexx", "virtualalloc", "mapviewoffile"]),
    ("Credential Access",  "Credential Access",     ["lsass", "mimikatz", "sekurlsa", "wdigest", "sam\\", "ntds.dit", "credentialsfrom"]),
    ("Shell Execution",    "Shell Execution",       ["cmd.exe", "powershell", "wscript", "cscript", "mshta", "regsvr32", "rundll32", "shell32"]),
    ("File Operations",    "File Manipulation",     ["createfile", "writefile", "deletefile", "copyfile", "movefile", "setfileattributes"]),
    ("Anti-Analysis",      "Anti-Analysis",         ["isdebuggerpresent", "checkremotedebuggerpresent", "sleep(", "vmware", "virtualbox", "sandbox"]),
]

RISK_THRESHOLDS = [(5, "CRITICAL", "#C0392B"), (3, "HIGH", "#E67E22"), (1, "MEDIUM", "#F39C12"), (0, "LOW", "#27AE60")]


def detect_behavior_hints(strings: list) -> list:
    all_text = " ".join(s.lower() for s in strings)
    hits = []
    for cat, display, keywords in BEHAVIOR_HINTS:
        matched = [kw for kw in keywords if kw in all_text]
        if matched:
            hits.append({"category": cat, "display": display, "keywords": matched})
    return hits


def calculate_entropy(file_path: str) -> float:
    try:
        with open(file_path, "rb") as f:
            data = f.read(1024 * 1024)  # Đọc tối đa 1MB
        if not data:
            return 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        for c in counts:
            if c:
                p = c / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0


def get_risk_score(behavior_hints: list, entropy: float, is_pe: bool) -> int:
    score = len(behavior_hints)
    if entropy > 7.0:
        score += 2
    elif entropy > 6.5:
        score += 1
    return score


class AnalyzeScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.analyzer = SampleAnalyzer()
        self.report_gen = AnalystReportGenerator()
        self.last_analysis_result = None
        self._build_ui()

    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="PHÂN TÍCH TĨNH MẪU MÃ ĐỘC",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 10))

        # Mode toggle
        mode_frame = tk.Frame(self, bg=CONT_BG)
        mode_frame.pack(fill="x", padx=20, pady=(0, 8))
        self.mode_var = tk.StringVar(value="single")
        tk.Radiobutton(mode_frame, text="Phân tích mẫu đơn lẻ", variable=self.mode_var, value="single",
                       bg=CONT_BG, font=("Segoe UI", 10), command=self._toggle_mode).pack(side="left")
        tk.Radiobutton(mode_frame, text="Phân tích theo folder (Batch Mode)", variable=self.mode_var, value="batch",
                       bg=CONT_BG, font=("Segoe UI", 10), command=self._toggle_mode).pack(side="left", padx=15)

        # ── Single mode card ──────────────────────────────────────
        _sf = tk.Frame(self, bg=CARD_SHD)
        _sf.pack(fill="x", padx=20, pady=(0, 8))
        self.single_frame = _sf
        _sfc = tk.Frame(_sf, bg=CARD_BG, highlightbackground=CARD_BDR, highlightthickness=1)
        _sfc.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))
        _sfh = tk.Frame(_sfc, bg="#EEF3FC")
        _sfh.pack(fill="x")
        tk.Frame(_sfc, bg=ACE_BLUE, height=3).place(x=0, y=0, relwidth=1)
        tk.Label(_sfh, text="Chọn mẫu phân tích đơn lẻ",
                 font=("Segoe UI", 10, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=14, pady=8).pack(anchor="w")
        tk.Frame(_sfc, bg=CARD_BDR, height=1).pack(fill="x")
        _sfb = tk.Frame(_sfc, bg=CARD_BG)
        _sfb.pack(fill="x", padx=12, pady=8)
        self.file_path_var = tk.StringVar()
        tk.Entry(_sfb, textvariable=self.file_path_var,
                 font=("Segoe UI", 10), bd=1, relief="solid"
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(_sfb, text="Browse…", font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._browse_file).pack(side="left", padx=(0, 8))
        tk.Button(_sfb, text="▶  Chạy Phân Tích",
                  font=("Segoe UI", 9, "bold"), bg=ACE_GREEN, fg="#FFFFFF",
                  relief="flat", bd=0, padx=15, pady=5, cursor="hand2",
                  command=self._run_single).pack(side="left")

        # ── Batch mode card ───────────────────────────────────────
        _bf = tk.Frame(self, bg=CARD_SHD)
        self.batch_frame = _bf
        _bfc = tk.Frame(_bf, bg=CARD_BG, highlightbackground=CARD_BDR, highlightthickness=1)
        _bfc.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))
        _bfh = tk.Frame(_bfc, bg="#EEF3FC")
        _bfh.pack(fill="x")
        tk.Frame(_bfc, bg=ACE_ORANGE, height=3).place(x=0, y=0, relwidth=1)
        tk.Label(_bfh, text="Chọn thư mục chứa nhiều mẫu (Batch Mode)",
                 font=("Segoe UI", 10, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=14, pady=8).pack(anchor="w")
        tk.Frame(_bfc, bg=CARD_BDR, height=1).pack(fill="x")
        _bfb = tk.Frame(_bfc, bg=CARD_BG)
        _bfb.pack(fill="x", padx=12, pady=8)
        self.batch_dir_var = tk.StringVar()
        tk.Entry(_bfb, textvariable=self.batch_dir_var,
                 font=("Segoe UI", 10), bd=1, relief="solid"
                 ).pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(_bfb, text="Browse…", font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._browse_dir).pack(side="left", padx=(0, 8))
        tk.Button(_bfb, text="◉  Quét Toàn Folder",
                  font=("Segoe UI", 9, "bold"), bg=ACE_ORANGE, fg="#FFFFFF",
                  relief="flat", bd=0, padx=15, pady=5, cursor="hand2",
                  command=self._run_batch).pack(side="left")

        # ── Notebook: tabs kết quả ────────────────────────────────
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=20, pady=(4, 0))

        # Tab 1: Tổng quan
        self._tab_info = tk.Frame(self.nb, bg=CARD_BG)
        self.nb.add(self._tab_info, text="  Tổng quan  ")
        self.result_text = self._make_text(self._tab_info, bg=CARD_BG, fg=TEXT_H)

        # Tab 2: Behavior Hints + Risk Score
        self._tab_behavior = tk.Frame(self.nb, bg=CARD_BG)
        self.nb.add(self._tab_behavior, text="  Behavior Hints  ")
        self._build_behavior_tab()

        # Tab 3: Strings
        self._tab_strings = tk.Frame(self.nb, bg=CARD_BG)
        self.nb.add(self._tab_strings, text="  Strings  ")
        self.strings_text = self._make_text(self._tab_strings, bg=CARD_BG, fg=TEXT_H, font=("Consolas", 9))

        # Tab 4: Batch results
        self._tab_batch = tk.Frame(self.nb, bg=CARD_BG)
        self.nb.add(self._tab_batch, text="  Batch Results  ")
        self._build_batch_tab()

        # Nút Export
        self.btn_export = tk.Button(
            self, text="Xuất Báo Cáo (.md)", font=("Segoe UI", 10, "bold"),
            bg="#2980B9", fg="#FFFFFF", relief="flat", bd=0, pady=6, padx=20, state="disabled",
            cursor="hand2", command=self._export_report
        )
        self.btn_export.pack(anchor="e", padx=20, pady=8)

    def _make_text(self, parent, **kwargs) -> tk.Text:
        f = tk.Frame(parent, bg=CARD_BG)
        f.pack(fill="both", expand=True, padx=4, pady=4)
        txt = tk.Text(f, font=kwargs.pop("font", ("Consolas", 10)), bd=0, relief="flat", wrap="word", **kwargs)
        sb = tk.Scrollbar(f, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return txt

    def _build_behavior_tab(self):
        tab = self._tab_behavior
        self.risk_var = tk.StringVar(value="—")
        self.risk_lbl = tk.Label(tab, textvariable=self.risk_var, font=("Segoe UI", 28, "bold"), bg=CARD_BG, fg="#95A5A6")
        self.risk_lbl.pack(pady=8)

        self.entropy_var = tk.StringVar(value="Entropy: —")
        tk.Label(tab, textvariable=self.entropy_var, font=("Segoe UI", 10), bg=CARD_BG, fg=TEXT_M).pack()

        self.behavior_tree = ttk.Treeview(tab, columns=("category", "keywords"), show="headings", height=10)
        self.behavior_tree.heading("category", text="Loại hành vi")
        self.behavior_tree.heading("keywords", text="Từ khóa phát hiện")
        self.behavior_tree.column("category", width=200, anchor="w")
        self.behavior_tree.column("keywords", width=400, anchor="w")
        sb = ttk.Scrollbar(tab, orient="vertical", command=self.behavior_tree.yview)
        self.behavior_tree.configure(yscrollcommand=sb.set)
        self.behavior_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        sb.pack(side="right", fill="y", pady=8, padx=(0, 8))

    def _build_batch_tab(self):
        tab = self._tab_batch

        # Bottom bar (pack first so treeview fills remaining space)
        bottom = tk.Frame(tab, bg=CARD_BG)
        bottom.pack(side="bottom", fill="x", pady=(2, 0))
        self.batch_summary_var = tk.StringVar(value="")
        tk.Label(bottom, textvariable=self.batch_summary_var,
                 font=("Segoe UI", 9, "italic"), bg=CARD_BG, fg=TEXT_M).pack(side="left", padx=8)
        tk.Button(bottom, text="Xuất kết quả CSV", font=("Segoe UI", 9), bg="#27AE60", fg="#FFFFFF",
                  bd=0, padx=10, pady=4, cursor="hand2",
                  command=self._export_batch_csv).pack(side="right", padx=8, pady=2)

        # Treeview + scrollbars
        tree_frame = tk.Frame(tab, bg=CARD_BG)
        tree_frame.pack(side="top", fill="both", expand=True)

        self.batch_tree = ttk.Treeview(
            tree_frame,
            columns=("name", "size", "entropy", "risk", "behaviors", "sha256"),
            show="headings"
        )
        self.batch_tree.heading("name",      text="Tên file")
        self.batch_tree.heading("size",      text="Kích thước")
        self.batch_tree.heading("entropy",   text="Entropy")
        self.batch_tree.heading("risk",      text="Risk")
        self.batch_tree.heading("behaviors", text="Behaviors")
        self.batch_tree.heading("sha256",    text="SHA256")

        self.batch_tree.column("name",      width=220, anchor="w")
        self.batch_tree.column("size",      width=90,  anchor="center")
        self.batch_tree.column("entropy",   width=80,  anchor="center")
        self.batch_tree.column("risk",      width=90,  anchor="center")
        self.batch_tree.column("behaviors", width=100, anchor="center")
        self.batch_tree.column("sha256",    width=220, anchor="w")

        sb_v = ttk.Scrollbar(tree_frame, orient="vertical",   command=self.batch_tree.yview)
        sb_h = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.batch_tree.xview)
        self.batch_tree.configure(yscrollcommand=sb_v.set, xscrollcommand=sb_h.set)

        sb_h.pack(side="bottom", fill="x")
        sb_v.pack(side="right",  fill="y")
        self.batch_tree.pack(side="left", fill="both", expand=True)
        self.batch_tree.bind("<<TreeviewSelect>>", self._on_batch_select)

        self._batch_results = []

    # ─────────────────────────────────────────────────────────────
    def _toggle_mode(self):
        if self.mode_var.get() == "single":
            self.batch_frame.pack_forget()
            self.single_frame.pack(fill="x", padx=20, pady=(0, 8), before=self.nb)
        else:
            self.single_frame.pack_forget()
            self.batch_frame.pack(fill="x", padx=20, pady=(0, 8), before=self.nb)

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Chọn mẫu mã độc cần phân tích", filetypes=[("All Files", "*.*")])
        if path:
            self.file_path_var.set(path)
            self.state.selected_single_sample = path

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Chọn thư mục chứa nhiều mẫu")
        if d:
            self.batch_dir_var.set(d)

    # ─── Single mode ─────────────────────────────────────────────
    def _run_single(self):
        path = self.file_path_var.get().strip()
        if not path:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file mẫu trước!")
            return

        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, "[*] Đang phân tích tĩnh...\n")
        self.btn_export.config(state="disabled")

        def _worker():
            res = self.analyzer.analyze_sample(path)
            entropy = calculate_entropy(path)
            behaviors = detect_behavior_hints(res.get("strings", []))
            risk = get_risk_score(behaviors, entropy, res.get("pe_details", {}).get("is_pe", False))
            res["entropy"] = entropy
            res["behaviors"] = behaviors
            res["risk_score"] = risk
            self.after(0, lambda: self._display_single(res))

        threading.Thread(target=_worker, daemon=True).start()

    def _display_single(self, res):
        if "error" in res:
            messagebox.showerror("Lỗi", res["error"])
            return

        self.last_analysis_result = res
        self.btn_export.config(state="normal")

        # Tab tổng quan
        self.result_text.delete("1.0", tk.END)
        lines = [
            "=== THÔNG TIN TỆP TIN ===",
            f"Tên file    : {res['file_name']}",
            f"Kích thước  : {format_file_size(res['file_size'])}",
            f"MD5         : {res['hashes']['md5']}",
            f"SHA1        : {res['hashes']['sha1']}",
            f"SHA256      : {res['hashes']['sha256']}",
            f"Entropy     : {res['entropy']} {'(Có thể bị pack/mã hóa!)' if res['entropy'] > 7.0 else ''}",
            f"Strings     : {res['strings_count']} chuỗi trích xuất",
            "",
            "=== CẤU TRÚC PE ===",
        ]
        pe = res["pe_details"]
        if pe["is_pe"]:
            lines.append("Định dạng: Windows PE (Portable Executable)")
            lines.append(f"Sections ({len(pe['sections'])}):")
            for s in pe["sections"]:
                lines.append(f"  - {s['name']}  (VSize: {s['virtual_size']}, RawSize: {s['raw_size']})")
            lines.append(f"\nDLL Imports ({len(pe['imports'])}):")
            for dll, funcs in list(pe["imports"].items())[:5]:
                lines.append(f"  + {dll} ({len(funcs)} funcs)")
        else:
            lines.append("Định dạng: Không phải file PE (Script / Document / Archive...)")

        self.result_text.insert(tk.END, "\n".join(lines))

        # Tab behavior
        for row in self.behavior_tree.get_children():
            self.behavior_tree.delete(row)
        risk_val = res["risk_score"]
        for threshold, label, color in RISK_THRESHOLDS:
            if risk_val >= threshold:
                self.risk_var.set(f"Risk: {label}")
                self.risk_lbl.config(fg=color)
                break
        self.entropy_var.set(f"Entropy: {res['entropy']}  {'⚠ Nghi bị pack' if res['entropy'] > 7.0 else '✓ Bình thường'}")
        for bh in res["behaviors"]:
            self.behavior_tree.insert("", "end", values=(bh["display"], ", ".join(bh["keywords"])))
        if not res["behaviors"]:
            self.behavior_tree.insert("", "end", values=("—", "Không phát hiện hành vi đáng ngờ"))

        # Tab strings
        self.strings_text.delete("1.0", tk.END)
        for s in res.get("strings", [])[:200]:
            self.strings_text.insert(tk.END, s + "\n")
        if res.get("strings_count", 0) > 200:
            self.strings_text.insert(tk.END, f"\n... và {res['strings_count'] - 200} chuỗi khác.\n")

        self.nb.select(0)

    def _on_batch_select(self, _event=None):
        sel = self.batch_tree.selection()
        if not sel:
            return
        idx = self.batch_tree.index(sel[0])
        if idx >= len(self._batch_results):
            return
        r = self._batch_results[idx]
        print(f"[DEBUG] Selected idx={idx} file={r['file_name'][:40]} strings={len(r.get('strings',[]))}")
        folder = self.batch_dir_var.get().strip()
        fp = os.path.join(folder, r["file_name"])
        if not os.path.isfile(fp):
            # Thu tim trong subfolder
            for root, dirs, files in os.walk(folder):
                if r["file_name"] in files:
                    fp = os.path.join(root, r["file_name"])
                    break

        # Cap nhat Behavior Hints tab
        self.risk_var.set(str(r["risk_score"]))
        self.entropy_var.set(f"Entropy: {r['entropy']}")
        for row in self.behavior_tree.get_children():
            self.behavior_tree.delete(row)
        if r["behaviors"]:
            for b in r["behaviors"]:
                self.behavior_tree.insert("", "end", values=(b["display"], ", ".join(b["keywords"])))
        else:
            self.behavior_tree.insert("", "end", values=("—", "Không phát hiện hành vi đáng ngờ"))

        # Cap nhat Strings tab
        self.strings_text.delete("1.0", tk.END)
        strings = r.get("strings", [])
        if not strings and os.path.isfile(fp):
            strings = self.analyzer.extract_strings(fp)
        for s in strings[:300]:
            self.strings_text.insert(tk.END, s + "\n")
        if len(strings) > 300:
            self.strings_text.insert(tk.END, f"\n... và {len(strings) - 300} chuỗi khác.\n")

        # Cap nhat Tong quan tab
        self.result_text.delete("1.0", tk.END)
        pe = r.get("pe_details", {"is_pe": False, "sections": [], "imports": {}})
        lines = [
            "=== THÔNG TIN TỆP TIN ===",
            f"Tên file    : {r['file_name']}",
            f"Kích thước  : {format_file_size(r['file_size'])}",
            f"SHA256      : {r['sha256']}",
            f"Entropy     : {r['entropy']}  {'(Có thể bị pack/mã hóa!)' if r['entropy'] > 7.0 else ''}",
            f"Behaviors   : {len(r['behaviors'])} loại phát hiện",
            "",
            "=== CẤU TRÚC PE ===",
        ]
        if pe.get("is_pe"):
            lines.append(f"Sections ({len(pe.get('sections', []))}):")
            for s in pe.get("sections", []):
                lines.append(f"  - {s['name']}  (VSize: {s['virtual_size']}, RawSize: {s['raw_size']})")
            lines.append(f"\nDLL Imports ({len(pe.get('imports', {}))}):")
            for dll, funcs in list(pe.get("imports", {}).items())[:5]:
                lines.append(f"  + {dll} ({len(funcs)} funcs)")
        else:
            lines.append("Định dạng: Không phải file PE (Script / Document / Archive...)")
        self.result_text.insert(tk.END, "\n".join(lines))

        # Switch sang tab Tong quan de hien thi ket qua
        self.nb.select(0)

    # ─── Batch mode ──────────────────────────────────────────────
    def _run_batch(self):
        folder = self.batch_dir_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn thư mục hợp lệ!")
            return

        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)
        self.batch_summary_var.set("Đang quét...")
        self._batch_results = []
        self.nb.select(3)

        def _worker():
            files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
            results = []
            for fp in files:
                try:
                    res = self.analyzer.analyze_sample(fp)
                    if "error" in res:
                        continue
                    entropy = calculate_entropy(fp)
                    behaviors = detect_behavior_hints(res.get("strings", []))
                    risk_score = get_risk_score(behaviors, entropy, res.get("pe_details", {}).get("is_pe", False))
                    results.append({
                        "file_name": res["file_name"],
                        "file_size": res["file_size"],
                        "sha256": res["hashes"]["sha256"],
                        "entropy": entropy,
                        "risk_score": risk_score,
                        "behaviors": behaviors,
                        "strings": res.get("strings", []),
                        "pe_details": res.get("pe_details", {"is_pe": False, "sections": [], "imports": {}}),
                    })
                except Exception:
                    continue
            self.after(0, lambda: self._display_batch(results))

        threading.Thread(target=_worker, daemon=True).start()

    def _display_batch(self, results):
        self._batch_results = sorted(results, key=lambda x: x["risk_score"], reverse=True)
        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)

        for r in self._batch_results:
            risk_val = r["risk_score"]
            risk_label = "LOW"
            for threshold, label, _ in RISK_THRESHOLDS:
                if risk_val >= threshold:
                    risk_label = label
                    break
            self.batch_tree.insert("", "end", values=(
                r["file_name"],
                format_file_size(r["file_size"]),
                str(r["entropy"]),
                risk_label,
                len(r["behaviors"]),
                r["sha256"][:32] + "..."
            ))

        self.batch_summary_var.set(f"Đã quét {len(results)} mẫu. Xem kết quả theo Risk Score giảm dần.")

    def _export_batch_csv(self):
        if not self._batch_results:
            messagebox.showinfo("Thông báo", "Chưa có kết quả batch để xuất.")
            return
        import csv
        out_path = os.path.join(self.state.reports_dir, "batch_analysis_results.csv")
        try:
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["File Name", "Size", "SHA256", "Entropy", "Risk Score", "Behavior Count"])
                for r in self._batch_results:
                    writer.writerow([r["file_name"], r["file_size"], r["sha256"], r["entropy"], r["risk_score"], len(r["behaviors"])])
            messagebox.showinfo("Thành công", f"Đã xuất CSV tại:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    def _export_report(self):
        if not self.last_analysis_result:
            return
        path = self.report_gen.generate_single_report(self.last_analysis_result, self.state.reports_dir)
        if path:
            messagebox.showinfo("Thành công", f"Báo cáo đã xuất tại:\n{path}")
        else:
            messagebox.showerror("Lỗi", "Không thể xuất file báo cáo.")
