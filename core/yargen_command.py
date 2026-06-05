import os
import sys
from typing import List, Dict, Any

PRESETS = {
    "Beginner": {
        "description": "Cân bằng cho lần chạy đầu, dành cho người mới",
        "args": ["--nosimple", "--nomagic"],
        "score": None,
        "opcodes": False,
    },
    "PE Deep": {
        "description": "Phân tích PE sâu hơn, bao gồm opcode (chậm hơn)",
        "args": ["--nosimple", "--nomagic", "--opcodes"],
        "score": None,
        "opcodes": True,
    },
    "Script Malware": {
        "description": "PS1, JS, VBS, BAT/CMD – tập trung strings script",
        "args": ["--nosimple", "--nomagic", "--strings"],
        "score": None,
        "opcodes": False,
    },
    "Webshell": {
        "description": "PHP, ASP, ASPX, JSP – tập trung chuỗi webshell",
        "args": ["--nosimple", "--nomagic", "--strings"],
        "score": None,
        "opcodes": False,
    },
    "Fast Scan": {
        "description": "Demo/triage nhanh, dùng DB runtime nhẹ",
        "args": ["--nosimple", "--nomagic"],
        "score": None,
        "opcodes": False,
    },
    "Loose Debug": {
        "description": "Kiểm tra khi sinh 0 rule – không dùng làm rule cuối",
        "args": [],
        "score": None,
        "opcodes": False,
    },
    "Custom": {
        "description": "Tự chọn các tham số tùy ý",
        "args": [],
        "score": None,
        "opcodes": False,
    },
}


class YarGenCommandBuilder:
    def __init__(self, yargen_path: str, python_exe: str = None):
        self.yargen_path = yargen_path
        self.python_exe = python_exe or sys.executable

    def build(
        self,
        malware_dir: str,
        output_path: str,
        preset: str = "Beginner",
        nosimple: bool = True,
        nomagic: bool = True,
        opcodes: bool = False,
        strings: bool = False,
        score: str = "",
        extra_flags: List[str] = None,
    ) -> List[str]:
        """Xây dựng danh sách lệnh CLI yarGen.py đầy đủ."""
        cmd = [self.python_exe, self.yargen_path, "-m", malware_dir, "-o", output_path, "--excludegood"]

        # Áp dụng preset
        if preset and preset != "Custom" and preset in PRESETS:
            preset_args = PRESETS[preset]["args"]
            for arg in preset_args:
                if arg not in cmd:
                    cmd.append(arg)
        else:
            # Chế độ Custom: dùng checkbox thủ công
            if nosimple and "--nosimple" not in cmd:
                cmd.append("--nosimple")
            if nomagic and "--nomagic" not in cmd:
                cmd.append("--nomagic")
            if opcodes and "--opcodes" not in cmd:
                cmd.append("--opcodes")
            if strings and "--strings" not in cmd:
                cmd.append("--strings")

        if score:
            cmd.extend(["-z", str(score)])

        if extra_flags:
            for flag in extra_flags:
                if flag and flag not in cmd:
                    cmd.append(flag)

        return cmd

    def preview(
        self,
        malware_dir: str,
        output_path: str,
        preset: str = "Beginner",
        nosimple: bool = True,
        nomagic: bool = True,
        opcodes: bool = False,
        strings: bool = False,
        score: str = "",
        extra_flags: List[str] = None,
    ) -> str:
        """Trả về chuỗi lệnh dạng con người đọc được để hiện trong Command Preview."""
        cmd = self.build(malware_dir, output_path, preset, nosimple, nomagic, opcodes, strings, score, extra_flags)
        parts = []
        for part in cmd:
            if " " in part and not part.startswith("-"):
                parts.append(f'"{part}"')
            else:
                parts.append(part)
        return " ".join(parts)

    @staticmethod
    def get_preset_names() -> List[str]:
        return list(PRESETS.keys())

    @staticmethod
    def get_preset_description(preset: str) -> str:
        return PRESETS.get(preset, {}).get("description", "")
