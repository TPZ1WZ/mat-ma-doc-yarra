import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from core.state import AppState
from core.runner import BackgroundRunner
from core.yargen_command import YarGenCommandBuilder, PRESETS
from core.theme import *


def _card_section(parent, title, subtitle=""):
    """Returns the inner content frame of a styled card section."""
    wrapper = tk.Frame(parent, bg=CARD_SHD)
    wrapper.pack(fill="x", padx=20, pady=(0, 12))

    inner = tk.Frame(wrapper, bg=CARD_BG,
                     highlightbackground=CARD_BDR, highlightthickness=1)
    inner.pack(fill="both", expand=True, padx=(0, 2), pady=(0, 2))

    # Header strip
    hdr = tk.Frame(inner, bg="#EEF3FC")
    hdr.pack(fill="x")
    tk.Frame(inner, bg=ACE_BLUE, height=3).place(x=0, y=0, relwidth=1)
    hdr_inner = tk.Frame(hdr, bg="#EEF3FC")
    hdr_inner.pack(fill="x", padx=14, pady=(10, 8))
    tk.Label(hdr_inner, text=title, font=("Segoe UI", 11, "bold"),
             bg="#EEF3FC", fg=TEXT_H, anchor="w").pack(anchor="w")
    if subtitle:
        tk.Label(hdr_inner, text=subtitle, font=("Segoe UI", 9, "italic"),
                 bg="#EEF3FC", fg=TEXT_M, anchor="w").pack(anchor="w")

    tk.Frame(inner, bg=CARD_BDR, height=1).pack(fill="x")

    body = tk.Frame(inner, bg=CARD_BG)
    body.pack(fill="x", padx=14, pady=12)
    return body


class GenerateScreen(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=CONT_BG)
        self.state = AppState()
        self.runner = BackgroundRunner()
        self._advanced_mode = False
        self._build_ui()

    def _build_ui(self):
        # ── Page header ───────────────────────────────────────────────
        hdr = tk.Frame(self, bg=CONT_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="Sinh luật Yara với YarGen",
                 font=("Segoe UI", 16, "bold"),
                 bg=CONT_BG, fg=TEXT_H).pack(side="left", anchor="w")
        tk.Frame(self, bg=CARD_BDR, height=1).pack(fill="x", padx=24, pady=(0, 16))

        # ── yarGen advanced ───────────────────────────────────────────
        body2 = _card_section(
            self,
            "Sinh luật nâng cao với yarGen.py",
            "Chạy yarGen.py với preset tùy chỉnh và xem lệnh sẽ thực thi trước khi khởi chạy"
        )

        # Row 1: Output file
        row2 = tk.Frame(body2, bg=CARD_BG)
        row2.pack(fill="x", pady=(0, 8))
        tk.Label(row2, text="File đầu ra (.yar):", font=("Segoe UI", 10),
                 bg=CARD_BG, fg=TEXT_N, width=18, anchor="w").pack(side="left")
        self.out_var = tk.StringVar()
        self.out_var.trace_add("write", lambda *_: self._update_preview())
        entry2 = tk.Entry(row2, textvariable=self.out_var, font=("Segoe UI", 10),
                          bd=1, relief="solid", highlightthickness=0)
        entry2.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Button(row2, text="Browse…",
                  font=("Segoe UI", 9), bg="#475569", fg="#FFFFFF",
                  bd=0, padx=10, pady=4, cursor="hand2",
                  command=self._browse_out).pack(side="left")

        # Row 3: Preset + toggle
        row3 = tk.Frame(body2, bg=CARD_BG)
        row3.pack(fill="x", pady=(0, 8))
        tk.Label(row3, text="Preset:", font=("Segoe UI", 10),
                 bg=CARD_BG, fg=TEXT_N, width=18, anchor="w").pack(side="left")

        self.preset_var = tk.StringVar(value="Beginner")
        preset_names = list(PRESETS.keys())
        preset_menu = tk.OptionMenu(row3, self.preset_var, *preset_names,
                                    command=self._on_preset_change)
        preset_menu.config(font=("Segoe UI", 10), bg=CARD_BG, bd=1,
                           relief="solid", highlightthickness=0)
        preset_menu.pack(side="left", padx=(0, 12))

        self.preset_desc_var = tk.StringVar(value=PRESETS["Beginner"]["description"])
        tk.Label(row3, textvariable=self.preset_desc_var,
                 font=("Segoe UI", 9, "italic"),
                 bg=CARD_BG, fg=TEXT_M).pack(side="left", fill="x", expand=True)

        self.mode_btn = tk.Button(
            row3, text="⚙  Advanced Mode",
            font=("Segoe UI", 9, "bold"), bg=ACE_PURPLE, fg="#FFFFFF",
            relief="flat", bd=0, padx=12, pady=4, cursor="hand2",
            command=self._toggle_mode
        )
        self.mode_btn.pack(side="right")

        # ── Advanced options (hidden by default) ──────────────────────
        self.adv_frame = tk.Frame(body2, bg=CARD_BG)

        self.cb_nosimple_var = tk.BooleanVar(value=True)
        self.cb_nomagic_var  = tk.BooleanVar(value=True)
        self.cb_opcodes_var  = tk.BooleanVar(value=False)
        self.cb_strings_var  = tk.BooleanVar(value=False)
        self.score_var       = tk.StringVar(value="")

        opts_row = tk.Frame(self.adv_frame, bg=CARD_BG)
        opts_row.pack(fill="x", pady=(6, 2))

        tk.Label(opts_row, text="Flags:", font=("Segoe UI", 10),
                 bg=CARD_BG, fg=TEXT_N, width=18, anchor="w").pack(side="left")
        for text, var in [
            ("--nosimple", self.cb_nosimple_var),
            ("--nomagic",  self.cb_nomagic_var),
            ("--opcodes",  self.cb_opcodes_var),
            ("--strings",  self.cb_strings_var),
        ]:
            tk.Checkbutton(opts_row, text=text, variable=var,
                           bg=CARD_BG, font=("Segoe UI", 10),
                           command=self._update_preview
                           ).pack(side="left", padx=8)

        score_row = tk.Frame(self.adv_frame, bg=CARD_BG)
        score_row.pack(fill="x", pady=4)
        tk.Label(score_row, text="-z Score threshold:", font=("Segoe UI", 10),
                 bg=CARD_BG, fg=TEXT_N, width=18, anchor="w").pack(side="left")
        score_entry = tk.Entry(score_row, textvariable=self.score_var,
                               font=("Segoe UI", 10),
                               bd=1, relief="solid", width=8)
        score_entry.pack(side="left", padx=(0, 8))
        score_entry.bind("<KeyRelease>", lambda _: self._update_preview())
        tk.Label(score_row, text="(để trống = mặc định yarGen)",
                 font=("Segoe UI", 9, "italic"),
                 bg=CARD_BG, fg=TEXT_M).pack(side="left")

        # ── Command Preview ───────────────────────────────────────────
        self._prev_hdr = tk.Frame(body2, bg=CARD_BG)
        prev_hdr = self._prev_hdr
        prev_hdr.pack(fill="x", pady=(12, 4))
        tk.Label(prev_hdr, text="Command Preview",
                 font=("Segoe UI", 10, "bold"),
                 bg=CARD_BG, fg=ACE_TEAL).pack(side="left")
        tk.Label(prev_hdr, text=" — lệnh sẽ được thực thi",
                 font=("Segoe UI", 9, "italic"),
                 bg=CARD_BG, fg=TEXT_M).pack(side="left")

        preview_wrap = tk.Frame(body2, bg="#1A1A2E",
                                highlightbackground="#3A3A5C", highlightthickness=1)
        preview_wrap.pack(fill="x", pady=(0, 12))

        self.preview_text = tk.Text(
            preview_wrap, height=3, font=("Consolas", 10),
            bg="#1A1A2E", fg="#98C379", bd=0, wrap="word",
            state="disabled", padx=10, pady=8,
            insertbackground="#FFFFFF", selectbackground="#3A3A5C"
        )
        self.preview_text.pack(fill="x")

        # Action buttons
        btn_row = tk.Frame(body2, bg=CARD_BG)
        btn_row.pack(fill="x")

        tk.Button(
            btn_row, text="▶  Bắt đầu sinh luật Yara",
            font=("Segoe UI", 10, "bold"),
            bg=ACE_GREEN, fg="#FFFFFF",
            relief="flat", bd=0, padx=18, pady=8, cursor="hand2",
            command=self._run_yargen_generation
        ).pack(side="left")

        tk.Button(
            btn_row, text="Copy Command",
            font=("Segoe UI", 9), bg="#64748B", fg="#FFFFFF",
            bd=0, padx=12, pady=8, cursor="hand2",
            command=self._copy_command
        ).pack(side="left", padx=(10, 0))

        # Pre-fill output path from state
        if self.state.selected_family_dir:
            family_name = os.path.basename(self.state.selected_family_dir.rstrip(r"\/"))
            safe = "".join(c if c.isalnum() else "_" for c in family_name)
            self.out_var.set(os.path.join(self.state.rules_dir, f"yargen_{safe}.yar"))

        self._update_preview()

    # ── Handlers ─────────────────────────────────────────────────────
    def _on_preset_change(self, preset_name):
        self.preset_desc_var.set(PRESETS.get(preset_name, {}).get("description", ""))
        if preset_name == "Custom" and not self._advanced_mode:
            self._toggle_mode()
        self._update_preview()

    def _toggle_mode(self):
        self._advanced_mode = not self._advanced_mode
        if self._advanced_mode:
            self.adv_frame.pack(fill="x", before=self._prev_hdr)
            self.mode_btn.config(text="⚙  Basic Mode", bg="#64748B")
        else:
            self.adv_frame.pack_forget()
            self.mode_btn.config(text="⚙  Advanced Mode", bg=ACE_PURPLE)
        self._update_preview()

    def _browse_out(self):
        f = filedialog.asksaveasfilename(
            title="Chọn vị trí lưu file luật YARA",
            defaultextension=".yar",
            initialdir=self.state.rules_dir,
            filetypes=[("YARA Rules", "*.yar"), ("All files", "*.*")]
        )
        if f:
            self.out_var.set(f)

    def _build_cmd_list(self):
        yargen_path = os.path.join(self.state.base_dir, "yarGen.py")
        builder = YarGenCommandBuilder(yargen_path)
        preset = self.preset_var.get()
        malware_dir = self.state.selected_family_dir or "<thư_mục_mẫu>"
        out_path = self.out_var.get().strip() or os.path.join(self.state.rules_dir, "output.yar")

        if self._advanced_mode or preset == "Custom":
            return builder.build(
                malware_dir, out_path, preset="Custom",
                nosimple=self.cb_nosimple_var.get(),
                nomagic=self.cb_nomagic_var.get(),
                opcodes=self.cb_opcodes_var.get(),
                strings=self.cb_strings_var.get(),
                score=self.score_var.get().strip(),
            )
        return builder.build(malware_dir, out_path, preset=preset)

    def _update_preview(self):
        cmd = self._build_cmd_list()
        parts = [f'"{p}"' if " " in p and not p.startswith("-") else p for p in cmd]
        self.preview_text.config(state="normal")
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert(tk.END, " ".join(parts))
        self.preview_text.config(state="disabled")

    def _copy_command(self):
        cmd_str = self.preview_text.get("1.0", tk.END).strip()
        self.clipboard_clear()
        self.clipboard_append(cmd_str)
        messagebox.showinfo("Đã sao chép", "Lệnh đã được sao chép vào clipboard.")

    def _run_yargen_generation(self):
        malware_dir = self.state.selected_family_dir
        out_path = self.out_var.get().strip()

        if not malware_dir or not os.path.isdir(malware_dir):
            messagebox.showwarning(
                "Cảnh báo",
                "Chưa chọn thư mục mẫu.\nVui lòng qua màn hình 'Family' để chọn thư mục trước!"
            )
            return

        yargen_script = os.path.join(self.state.base_dir, "yarGen.py")
        if not os.path.exists(yargen_script):
            messagebox.showerror(
                "Thiếu yarGen.py",
                "Không tìm thấy yarGen.py trong thư mục dự án.\n\n"
                "Tải yarGen từ: github.com/Neo23x0/yarGen"
            )
            return

        if not out_path:
            family_name = os.path.basename(malware_dir.rstrip(r"\/"))
            safe = "".join(c if c.isalnum() else "_" for c in family_name)
            out_path = os.path.join(self.state.rules_dir, f"yargen_{safe}.yar")
            self.out_var.set(out_path)

        cmd = self._build_cmd_list()
        cmd[3] = malware_dir
        cmd[5] = out_path

        status = self.runner.start_task(cmd, cwd=self.state.base_dir)
        if status:
            messagebox.showinfo(
                "Thông báo",
                "Tiến trình yarGen đã kích hoạt ẩn thành công!\n"
                "Chuyển sang màn hình 'Monitor' để xem tiến trình."
            )
            if self.state.navigate_callback:
                self.state.navigate_callback("Monitor")
        else:
            messagebox.showerror("Lỗi",
                                 "Không thể kích hoạt tiến trình con. Kiểm tra lại cấu hình Python.")
