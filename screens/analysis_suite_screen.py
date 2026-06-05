import os
import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from core.state import AppState
from core.family_signature import FamilySignatureGenerator
from core.quality_gate import RuleDoctor
from core.family_passport import FamilyPassportGenerator
from core.analyst_report import AnalystReportGenerator
from core.analysis_common import write_markdown_report
from core.theme import *


# ── IOC patterns ────────────────────────────────────────────────
IOC_PATTERNS = {
    "IPv4":         re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "URL":          re.compile(r'https?://[^\s"\'<>]+'),
    "Domain":       re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|cc|ru|tk|pw|top|xyz)\b', re.IGNORECASE),
    "Email":        re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "Registry Key": re.compile(r'HKEY_[A-Z_]+\\[^\s"\']+', re.IGNORECASE),
    "Named Pipe":   re.compile(r'\\\\\.\\pipe\\[^\s"\']+', re.IGNORECASE),
    "Windows Path": re.compile(r'[A-Za-z]:\\[^\s"\'<>|:?*]+'),
    "Mutex":        re.compile(r'(?:mutex|event|semaphore)[^\s"\']{0,40}', re.IGNORECASE),
}

# ── MITRE ATT&CK heuristic mapping ─────────────────────────────
MITRE_MAP = [
    ("T1059.001", "PowerShell",             ["powershell", "invoke-expression", "iex", "encodedcommand"]),
    ("T1059.003", "Windows Command Shell",  ["cmd.exe", "command.com", "/c ", "cmd /k"]),
    ("T1053.005", "Scheduled Task",         ["schtasks", "taskschd", "at.exe"]),
    ("T1547.001", "Registry Run Keys",      ["run\\\\", "runonce", "currentversion\\run"]),
    ("T1055",     "Process Injection",       ["writeprocessmemory", "createremotethread", "ntcreatethreadexx", "virtualalloc"]),
    ("T1071.001", "Web Protocols (C2)",     ["http://", "https://", "user-agent", "post", "get /"]),
    ("T1218",     "System Binary Proxy",    ["regsvr32", "mshta", "wscript", "cscript", "rundll32", "certutil"]),
    ("T1003",     "Credential Dumping",     ["lsass", "mimikatz", "sekurlsa", "wdigest", "ntds.dit"]),
    ("T1082",     "System Info Discovery",  ["getcomputername", "getusernamea", "systeminfo", "getsysteminfo"]),
    ("T1083",     "File & Dir Discovery",   ["findfile", "getfilesizex", "enumfiles", "findfirstfile"]),
]


class AnalysisSuiteScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.sig_generator = FamilySignatureGenerator()
        self.doctor = RuleDoctor()
        self.passport_gen = FamilyPassportGenerator()

        self._family_res = None
        self._rule_text = ""
        self._doctor_res = None
        self._build_ui()

    # ─────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="CENTER OF EXCELLENCE: FAMILY DNA LAB SUITE",
                 font=FONT_TITLE, bg=CONT_BG, fg=TEXT_H).pack(side="left")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 10))

        # ── Input card ────────────────────────────────────────────
        inp_shadow = tk.Frame(self, bg=CARD_SHD)
        inp_shadow.pack(fill="x", padx=20, pady=(0, 10))
        inp_card = tk.Frame(inp_shadow, bg=CARD_BG,
                            highlightbackground=CARD_BDR, highlightthickness=1)
        inp_card.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

        inp_hdr = tk.Frame(inp_card, bg="#EEF3FC")
        inp_hdr.pack(fill="x")
        tk.Frame(inp_card, bg=ACE_PURPLE, height=3).place(x=0, y=0, relwidth=1)
        tk.Label(inp_hdr, text="Cấu hình phân tích",
                 font=("Segoe UI", 10, "bold"), bg="#EEF3FC", fg=TEXT_H,
                 padx=14, pady=8).pack(anchor="w")
        tk.Frame(inp_card, bg=CARD_BDR, height=1).pack(fill="x")

        inp_body = tk.Frame(inp_card, bg=CARD_BG)
        inp_body.pack(fill="x", padx=12, pady=10)

        tk.Label(inp_body, text="File luật .yar (tùy chọn):",
                 font=("Segoe UI", 10), bg=CARD_BG, fg=TEXT_N).pack(side="left")
        self.rule_path_var = tk.StringVar()
        tk.Entry(inp_body, textvariable=self.rule_path_var,
                 font=("Segoe UI", 10), bd=1, relief="solid", width=42
                 ).pack(side="left", padx=(8, 8))
        tk.Button(inp_body, text="Browse .yar",
                  font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._browse_rule).pack(side="left", padx=(0, 16))
        tk.Button(
            inp_body, text="▶  Chạy Toàn Bộ Phân Tích",
            font=("Segoe UI", 10, "bold"), bg=ACE_PURPLE, fg="#FFFFFF",
            relief="flat", bd=0, padx=15, pady=5, cursor="hand2",
            command=self._run_all
        ).pack(side="left")

        # Notebook (7 tabs)
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        self._tab_quality   = self._make_tab("Quality Gate")
        self._tab_doctor    = self._make_tab("Rule Doctor")
        self._tab_ioc       = self._make_tab("IOC Extractor")
        self._tab_mitre     = self._make_tab("MITRE Mapping")
        self._tab_dna       = self._make_tab("Family DNA Lab")
        self._tab_report    = self._make_tab("Analyst Report")
        self._tab_passport  = self._make_tab("Family Passport")

        self._build_quality_tab()
        self._build_doctor_tab()
        self._build_ioc_tab()
        self._build_mitre_tab()
        self._build_dna_tab()
        self._build_report_tab()
        self._build_passport_tab()

    def _make_tab(self, title: str) -> tk.Frame:
        frame = tk.Frame(self.nb, bg=CONT_BG)
        self.nb.add(frame, text=f"  {title}  ")
        return frame

    def _make_text_area(self, parent) -> tk.Text:
        f = tk.Frame(parent, bg=CONT_BG)
        f.pack(fill="both", expand=True, padx=10, pady=8)
        txt = tk.Text(f, font=("Consolas", 9), bg=CARD_BG, fg=TEXT_H, bd=1, relief="solid", wrap="word")
        sb = tk.Scrollbar(f, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return txt

    def _browse_rule(self):
        f = filedialog.askopenfilename(
            title="Chọn file luật YARA",
            initialdir=self.state.rules_dir,
            filetypes=[("YARA Rules", "*.yar"), ("All files", "*.*")]
        )
        if f:
            self.rule_path_var.set(f)

    # ─────── TAB 1: Quality Gate ─────────────────────────────────
    def _build_quality_tab(self):
        tab = self._tab_quality
        tk.Label(tab, text="Cổng kiểm soát chất lượng PASS / WARNING / FAIL", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        self.qg_verdict_var = tk.StringVar(value="──  Chưa phân tích  ──")
        self.qg_verdict_lbl = tk.Label(tab, textvariable=self.qg_verdict_var, font=("Segoe UI", 20, "bold"), bg=CONT_BG, fg="#95A5A6")
        self.qg_verdict_lbl.pack(pady=6)

        metrics_frame = tk.Frame(tab, bg=CONT_BG)
        metrics_frame.pack(fill="x", padx=10, pady=4)
        self._qg_metrics = {}
        for name in ["Score", "Strings", "Short Strings", "Generic Strings", "Condition"]:
            row = tk.Frame(metrics_frame, bg=CONT_BG)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{name}:", font=("Segoe UI", 9, "bold"), bg=CONT_BG, fg=TEXT_H, width=16, anchor="w").pack(side="left")
            val_lbl = tk.Label(row, text="—", font=("Segoe UI", 9), bg=CONT_BG, fg=TEXT_M, anchor="w")
            val_lbl.pack(side="left")
            self._qg_metrics[name] = val_lbl

        self.qg_warn_text = self._make_text_area(tab)

    def _update_quality_tab(self, doctor_res: dict):
        score = doctor_res["score"]
        metrics = doctor_res["metrics"]

        if score >= 80:
            verdict, color = "✓  PASS", "#27AE60"
        elif score >= 50:
            verdict, color = "⚠  WARNING", "#E67E22"
        else:
            verdict, color = "✗  FAIL", "#C0392B"

        self.qg_verdict_var.set(verdict)
        self.qg_verdict_lbl.config(fg=color)

        self._qg_metrics["Score"].config(text=f"{score} / 100")
        self._qg_metrics["Strings"].config(text=str(metrics.get("total_strings", "—")))
        self._qg_metrics["Short Strings"].config(text=str(metrics.get("short_strings_count", "—")))
        self._qg_metrics["Generic Strings"].config(text=str(metrics.get("generic_strings_count", "—")))
        self._qg_metrics["Condition"].config(text=metrics.get("condition_complexity", "—"))

        self.qg_warn_text.config(state="normal")
        self.qg_warn_text.delete("1.0", tk.END)
        warnings = doctor_res.get("warnings", [])
        if not warnings:
            self.qg_warn_text.insert(tk.END, "✓  Không có cảnh báo nào. Rule đạt chuẩn chất lượng cao!\n")
        else:
            for i, w in enumerate(warnings, 1):
                self.qg_warn_text.insert(tk.END, f"[{i}] {w}\n\n")
        self.qg_warn_text.config(state="disabled")

    # ─────── TAB 2: Rule Doctor ───────────────────────────────────
    def _build_doctor_tab(self):
        tab = self._tab_doctor
        tk.Label(tab, text="Rule Doctor – Rà soát lỗi thiết kế luật YARA", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        score_row = tk.Frame(tab, bg=CONT_BG)
        score_row.pack(fill="x", padx=10)
        tk.Label(score_row, text="Điểm chất lượng:", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(side="left")
        self.doctor_score_var = tk.StringVar(value="-- / 100")
        tk.Label(score_row, textvariable=self.doctor_score_var, font=("Segoe UI", 22, "bold"), bg=CONT_BG, fg="#D35400").pack(side="left", padx=10)
        self.doctor_rating_var = tk.StringVar(value="")
        tk.Label(score_row, textvariable=self.doctor_rating_var, font=("Segoe UI", 10), bg=CONT_BG, fg=TEXT_M).pack(side="left")

        self.doctor_text = self._make_text_area(tab)

    def _update_doctor_tab(self, doctor_res: dict):
        self.doctor_score_var.set(f"{doctor_res['score']} / 100")
        self.doctor_rating_var.set(doctor_res.get("rating", ""))

        self.doctor_text.config(state="normal")
        self.doctor_text.delete("1.0", tk.END)
        warnings = doctor_res.get("warnings", [])
        if not warnings:
            self.doctor_text.insert(tk.END, "✓  Rule Doctor không ghi nhận khuyết tật nào. Luật có cấu trúc rất tốt!\n")
        else:
            for i, w in enumerate(warnings, 1):
                self.doctor_text.insert(tk.END, f"⚠  Cảnh báo #{i}: {w}\n\n")
        self.doctor_text.config(state="disabled")

    # ─────── TAB 3: IOC Extractor ────────────────────────────────
    def _build_ioc_tab(self):
        tab = self._tab_ioc
        tk.Label(tab, text="Trích xuất Chỉ Báo Tấn Công (IOC) từ nội dung rule", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        # Treeview for IOCs
        tree_frame = tk.Frame(tab, bg=CONT_BG)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=4)

        self.ioc_tree = ttk.Treeview(tree_frame, columns=("type", "value"), show="headings")
        self.ioc_tree.heading("type", text="Loại IOC")
        self.ioc_tree.heading("value", text="Giá trị")
        self.ioc_tree.column("type", width=140, anchor="w")
        self.ioc_tree.column("value", width=500, anchor="w")

        ioc_sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ioc_tree.yview)
        self.ioc_tree.configure(yscrollcommand=ioc_sb.set)
        self.ioc_tree.pack(side="left", fill="both", expand=True)
        ioc_sb.pack(side="right", fill="y")

        self.ioc_count_var = tk.StringVar(value="")
        tk.Label(tab, textvariable=self.ioc_count_var, font=("Segoe UI", 9, "italic"), bg=CONT_BG, fg=TEXT_M).pack(anchor="w", padx=10)

    def _update_ioc_tab(self, rule_text: str):
        for item in self.ioc_tree.get_children():
            self.ioc_tree.delete(item)

        found = {}
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = set(pattern.findall(rule_text))
            if matches:
                found[ioc_type] = sorted(matches)

        total = 0
        for ioc_type, values in found.items():
            for val in values:
                self.ioc_tree.insert("", "end", values=(ioc_type, val))
                total += 1

        if total == 0:
            self.ioc_tree.insert("", "end", values=("—", "Không tìm thấy IOC nào trong nội dung rule."))
        self.ioc_count_var.set(f"Tổng cộng: {total} IOC tìm thấy")

    # ─────── TAB 4: MITRE Mapping ────────────────────────────────
    def _build_mitre_tab(self):
        tab = self._tab_mitre
        tk.Label(tab, text="Ánh xạ heuristic lên ma trận MITRE ATT&CK (cần analyst kiểm chứng)", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        tree_frame = tk.Frame(tab, bg=CONT_BG)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=4)

        self.mitre_tree = ttk.Treeview(tree_frame, columns=("id", "technique", "evidence"), show="headings")
        self.mitre_tree.heading("id", text="ID")
        self.mitre_tree.heading("technique", text="Kỹ thuật ATT&CK")
        self.mitre_tree.heading("evidence", text="Từ khóa phát hiện được")
        self.mitre_tree.column("id", width=100, anchor="center")
        self.mitre_tree.column("technique", width=200, anchor="w")
        self.mitre_tree.column("evidence", width=350, anchor="w")

        mitre_sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.mitre_tree.yview)
        self.mitre_tree.configure(yscrollcommand=mitre_sb.set)
        self.mitre_tree.pack(side="left", fill="both", expand=True)
        mitre_sb.pack(side="right", fill="y")

        tk.Label(tab, text="⚠  Đây là kết quả heuristic tĩnh. Analyst cần kiểm chứng thêm trước khi kết luận.",
                 font=("Segoe UI", 8, "italic"), bg=CONT_BG, fg="#E67E22").pack(anchor="w", padx=10, pady=4)

    def _update_mitre_tab(self, rule_text: str):
        for item in self.mitre_tree.get_children():
            self.mitre_tree.delete(item)

        content_lower = rule_text.lower()
        found_any = False
        for tid, technique, keywords in MITRE_MAP:
            matched = [kw for kw in keywords if kw.lower() in content_lower]
            if matched:
                self.mitre_tree.insert("", "end", values=(tid, technique, ", ".join(matched)))
                found_any = True

        if not found_any:
            self.mitre_tree.insert("", "end", values=("—", "Không ánh xạ được kỹ thuật nào", "—"))

    # ─────── TAB 5: Family DNA Lab ───────────────────────────────
    def _build_dna_tab(self):
        tab = self._tab_dna
        tk.Label(tab, text="Hồ sơ DNA – Vân tay đặc trưng chung của họ mã độc", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        summary_row = tk.Frame(tab, bg=CONT_BG)
        summary_row.pack(fill="x", padx=10)
        self._dna_vars = {}
        for label in ["Tên họ", "Tổng mẫu", "Đặc trưng chung", "Coverage tối thiểu"]:
            r = tk.Frame(summary_row, bg=CONT_BG)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=f"{label}:", font=("Segoe UI", 9, "bold"), bg=CONT_BG, fg=TEXT_H, width=22, anchor="w").pack(side="left")
            v = tk.StringVar(value="—")
            tk.Label(r, textvariable=v, font=("Segoe UI", 9), bg=CONT_BG, fg=TEXT_H).pack(side="left")
            self._dna_vars[label] = v

        tk.Label(tab, text="Top đặc trưng chung (DNA features):", font=("Segoe UI", 9, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=(8, 2))
        self.dna_text = self._make_text_area(tab)

    def _update_dna_tab(self, family_res: dict):
        self._dna_vars["Tên họ"].set(family_res.get("family_name", "—"))
        self._dna_vars["Tổng mẫu"].set(str(family_res.get("total_samples", "—")))
        features = family_res.get("features", [])
        self._dna_vars["Đặc trưng chung"].set(str(len(features)))
        self._dna_vars["Coverage tối thiểu"].set(str(family_res.get("min_appearance_required", "—")))

        self.dna_text.config(state="normal")
        self.dna_text.delete("1.0", tk.END)
        for feat in features[:30]:
            self.dna_text.insert(tk.END, f"[{feat['percentage']:.1f}%]  {feat['string']}\n")
        if len(features) > 30:
            self.dna_text.insert(tk.END, f"... và {len(features) - 30} đặc trưng khác.\n")
        self.dna_text.config(state="disabled")

    # ─────── TAB 6: Analyst Report ───────────────────────────────
    def _build_report_tab(self):
        tab = self._tab_report
        tk.Label(tab, text="Analyst Report – Tổng hợp báo cáo phân tích chuyên sâu", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        btn_row = tk.Frame(tab, bg=CONT_BG)
        btn_row.pack(fill="x", padx=10)
        tk.Button(btn_row, text="Tạo Analyst Report (.md)", font=("Segoe UI", 9, "bold"), bg="#2980B9", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2", command=self._export_analyst_report).pack(side="left")

        self.report_text = self._make_text_area(tab)

    def _update_report_tab(self, family_res: dict, doctor_res: dict):
        family_name = family_res.get("family_name", "Unknown")
        features = family_res.get("features", [])
        warnings = doctor_res.get("warnings", [])
        score = doctor_res.get("score", 0)

        report_lines = [
            f"# BÁO CÁO PHÂN TÍCH: {family_name}",
            "",
            "## Executive Summary",
            f"- Tổng số mẫu phân tích: {family_res.get('total_samples', 0)}",
            f"- Số đặc trưng chung trích xuất: {len(features)}",
            f"- Điểm chất lượng luật (Rule Doctor): {score}/100  [{doctor_res.get('rating', '')}]",
            "",
            "## Key Findings",
        ]
        for feat in features[:10]:
            report_lines.append(f"- [{feat['percentage']:.1f}%] `{feat['string']}`")

        report_lines += [
            "",
            "## Rule Quality Assessment",
        ]
        if warnings:
            for w in warnings:
                report_lines.append(f"- ⚠ {w}")
        else:
            report_lines.append("- ✓ Rule không có cảnh báo chất lượng.")

        report_lines += [
            "",
            "## Recommendations",
            "- Kiểm tra tỷ lệ False Positive trên tập Goodware trước khi triển khai.",
            "- Xem xét mở rộng tập mẫu nếu số đặc trưng chung còn ít.",
            "- Sử dụng Analysis Suite > Quality Gate để xác nhận rule sẵn sàng deploy.",
        ]

        content = "\n".join(report_lines)
        self.report_text.config(state="normal")
        self.report_text.delete("1.0", tk.END)
        self.report_text.insert(tk.END, content)
        self.report_text.config(state="disabled")

    def _export_analyst_report(self):
        if not self._family_res:
            messagebox.showwarning("Cảnh báo", "Chưa có dữ liệu phân tích. Nhấn 'Chạy Toàn Bộ Phân Tích' trước.")
            return
        content = self.report_text.get("1.0", tk.END)
        family_name = self._family_res.get("family_name", "Unknown")
        safe = "".join(c if c.isalnum() else "_" for c in family_name)
        out_path = os.path.join(self.state.reports_dir, f"analyst_report_{safe}.md")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Thành công", f"Báo cáo đã xuất tại:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", str(e))

    # ─────── TAB 7: Family Passport ──────────────────────────────
    def _build_passport_tab(self):
        tab = self._tab_passport
        tk.Label(tab, text="Family Passport – Hồ sơ căn cước họ mã độc", font=("Segoe UI", 10, "bold"), bg=CONT_BG, fg=TEXT_H).pack(anchor="w", padx=10, pady=8)

        btn_row = tk.Frame(tab, bg=CONT_BG)
        btn_row.pack(fill="x", padx=10)
        tk.Button(btn_row, text="Xuất Family Passport (.md + .csv)", font=("Segoe UI", 9, "bold"), bg="#8E44AD", fg="#FFFFFF",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2", command=self._export_passport).pack(side="left")

        self.passport_text = self._make_text_area(tab)

    def _update_passport_tab(self, family_res: dict, doctor_res: dict):
        family_name = family_res.get("family_name", "Unknown")
        samples = family_res.get("samples", [])
        features = family_res.get("features", [])
        score = doctor_res.get("score", 0)

        lines = [
            f"MALWARE FAMILY PASSPORT",
            f"{'─' * 50}",
            f"Family Name : {family_name}",
            f"Samples     : {len(samples)}",
            f"DNA Features: {len(features)}",
            f"Rule Score  : {score}/100  [{doctor_res.get('rating', '')}]",
            "",
            "Top Strings (DNA):",
        ]
        for feat in features[:10]:
            lines.append(f"  [{feat['percentage']:.0f}%] {feat['string']}")

        lines += ["", "Sample Hashes (SHA256):"]
        for s in samples[:5]:
            lines.append(f"  {s['file_name']} → {s['sha256'][:24]}...")

        content = "\n".join(lines)
        self.passport_text.config(state="normal")
        self.passport_text.delete("1.0", tk.END)
        self.passport_text.insert(tk.END, content)
        self.passport_text.config(state="disabled")

    def _export_passport(self):
        if not self._family_res or not self._doctor_res:
            messagebox.showwarning("Cảnh báo", "Chưa có dữ liệu. Nhấn 'Chạy Toàn Bộ Phân Tích' trước.")
            return
        path = self.passport_gen.generate_family_passport(self._family_res, self._doctor_res, self.state.reports_dir)
        if path:
            messagebox.showinfo("Thành công", f"Đã xuất hồ sơ tại:\n{self.state.reports_dir}")
        else:
            messagebox.showerror("Lỗi", "Không thể xuất Family Passport.")

    # ─────── Run all ─────────────────────────────────────────────
    def _run_all(self):
        target_dir = self.state.selected_family_dir
        rule_path = self.rule_path_var.get().strip()

        if not target_dir or not os.path.exists(target_dir):
            messagebox.showwarning("Cảnh báo", "Vui lòng qua 'Quản lý họ mã độc' để chọn thư mục mẫu trước!")
            return

        def _worker():
            family_res = self.sig_generator.process_family_directory(target_dir)
            if "error" in family_res:
                self.after(0, lambda: messagebox.showerror("Lỗi", family_res["error"]))
                return

            rule_text = ""
            if rule_path and os.path.isfile(rule_path):
                try:
                    with open(rule_path, "r", encoding="utf-8", errors="replace") as f:
                        rule_text = f.read()
                except Exception:
                    pass

            if not rule_text:
                rule_text = self.sig_generator.generate_yara_rule(family_res)

            doctor_res = self.doctor.evaluate_rule(rule_text)
            self.after(0, lambda: self._populate_all_tabs(family_res, doctor_res, rule_text))

        threading.Thread(target=_worker, daemon=True).start()

    def _populate_all_tabs(self, family_res: dict, doctor_res: dict, rule_text: str):
        self._family_res = family_res
        self._rule_text = rule_text
        self._doctor_res = doctor_res

        self._update_quality_tab(doctor_res)
        self._update_doctor_tab(doctor_res)
        self._update_ioc_tab(rule_text)
        self._update_mitre_tab(rule_text)
        self._update_dna_tab(family_res)
        self._update_report_tab(family_res, doctor_res)
        self._update_passport_tab(family_res, doctor_res)

        messagebox.showinfo("Hoàn tất", "Phân tích toàn diện xong! Xem kết quả ở các tab.")
