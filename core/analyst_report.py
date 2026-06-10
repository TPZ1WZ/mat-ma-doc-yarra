import os
import datetime
from typing import Dict, Any, List
from core.analysis_common import format_file_size, write_markdown_report

_RISK_THRESHOLDS = [(5, "CRITICAL"), (3, "HIGH"), (1, "MEDIUM"), (0, "LOW")]

def _risk_label(score: int) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


class AnalystReportGenerator:
    def __init__(self):
        pass

    def generate_single_report(self, sample_info: Dict[str, Any], report_dir: str) -> str:
        """Tổng hợp kết quả phân tích tĩnh của một mẫu và xuất ra file Markdown (.md)"""
        file_name = sample_info.get("file_name", "unknown_sample")
        safe_file_name = "".join([c if c.isalnum() else "_" for c in file_name])
        report_path = os.path.join(report_dir, f"analyst_report_{safe_file_name}.md")

        # Chuẩn bị nội dung cho từng mục trong báo cáo
        metadata = {
            "Tên tệp tin": file_name,
            "Đường dẫn thực tế": sample_info.get("file_path", "N/A"),
            "Kích thước": format_file_size(sample_info.get("file_size", 0)),
            "Mã băm MD5": sample_info.get("hashes", {}).get("md5", "N/A"),
            "Mã băm SHA256": sample_info.get("hashes", {}).get("sha256", "N/A"),
            "Tổng số chuỗi trích xuất": sample_info.get("strings_count", 0)
        }

        pe_details = sample_info.get("pe_details", {})
        pe_summary = []
        if pe_details.get("is_pe", False):
            pe_summary.append("**Cấu trúc định dạng**: Windows Portable Executable (PE)")
            pe_summary.append(f"**Số lượng phân vùng (Sections)**: {len(pe_details.get('sections', []))}")
            for sec in pe_details.get("sections", []):
                pe_summary.append(f"  * Phân vùng `{sec['name']}` (Virtual Size: {sec['virtual_size']}, Raw Size: {sec['raw_size']})")
            
            imports_dict = pe_details.get("imports", {})
            pe_summary.append(f"**Số thư viện liên kết động (DLLs) hiện có**: {len(imports_dict)}")
        else:
            pe_summary.append("**Cấu trúc định dạng**: Không phải file PE hệ thống Windows (Có thể là Script, Document, v.v.)")

        # Lấy tối đa 20 chuỗi đầu tiên làm minh họa trong báo cáo để tránh file quá dài
        strings_sample = [f"`{s}`" for s in sample_info.get("strings", [])[:20]]
        if sample_info.get("strings_count", 0) > 20:
            strings_sample.append(f"... Và {sample_info.get('strings_count', 0) - 20} chuỗi ký tự khác.")

        # Gom toàn bộ cấu trúc báo cáo
        sections = {
            "1. Thông Tin Tổng Quan (Metadata)": metadata,
            "2. Phân Tích Cấu Trúc Định Dạng PE": pe_summary,
            "3. Danh Sách Chuỗi Ký Tự Trích Xuất Tiêu Biểu": strings_sample
        }

        # Ghi file thông qua module common
        success = write_markdown_report(report_path, f"BÁO CÁO PHÂN TÍCH TĨNH MẪU MÃ ĐỘC: {file_name}", sections)
        return report_path if success else ""

    def generate_batch_report(self, batch_results: List[Dict[str, Any]],
                               folder_path: str, report_dir: str) -> str:
        """Tổng hợp kết quả batch scan toàn bộ folder thành 1 file Markdown duy nhất."""
        folder_name = os.path.basename(folder_path.rstrip("/\\")) if folder_path else "batch"
        safe_name = "".join(c if c.isalnum() else "_" for c in folder_name)
        report_path = os.path.join(report_dir, f"batch_report_{safe_name}.md")
        today = datetime.date.today().isoformat()

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                # ── Tiêu đề ──────────────────────────────────────────
                f.write("# BÁO CÁO PHÂN TÍCH TĨNH BATCH\n\n")
                f.write(f"**Thư mục phân tích:** `{folder_path}`  \n")
                f.write(f"**Tổng số mẫu:** {len(batch_results)}  \n")
                f.write(f"**Ngày tạo:** {today}  \n\n")
                f.write("---\n\n")

                # ── Bảng tóm tắt ─────────────────────────────────────
                f.write("## Tóm Tắt Tất Cả Mẫu\n\n")
                f.write("| # | Tên file | Kích thước | Entropy | Risk | Behaviors | SHA256 |\n")
                f.write("|---|----------|-----------|---------|------|-----------|--------|\n")
                for i, r in enumerate(batch_results, 1):
                    sha_short = r["sha256"][:16] + "..."
                    f.write(f"| {i} | `{r['file_name']}` | {format_file_size(r['file_size'])} "
                            f"| {r['entropy']} | **{_risk_label(r['risk_score'])}** "
                            f"| {len(r['behaviors'])} | `{sha_short}` |\n")
                f.write("\n---\n\n")

                # ── Chi tiết từng mẫu ────────────────────────────────
                f.write("## Chi Tiết Từng Mẫu\n\n")
                for i, r in enumerate(batch_results, 1):
                    pack_warn = " ⚠ Nghi bị pack/mã hóa" if r["entropy"] > 7.0 else ""
                    f.write(f"### {i}. {r['file_name']}\n\n")
                    f.write("| Thuộc tính | Giá trị |\n")
                    f.write("|------------|--------|\n")
                    f.write(f"| SHA256 | `{r['sha256']}` |\n")
                    f.write(f"| Kích thước | {format_file_size(r['file_size'])} |\n")
                    f.write(f"| Entropy | {r['entropy']}{pack_warn} |\n")
                    f.write(f"| Risk | **{_risk_label(r['risk_score'])}** |\n\n")

                    # Behavior hints
                    f.write("#### Behavior Hints\n\n")
                    if r["behaviors"]:
                        for b in r["behaviors"]:
                            f.write(f"* **{b['display']}**: {', '.join(b['keywords'])}\n")
                    else:
                        f.write("* Không phát hiện hành vi đáng ngờ\n")
                    f.write("\n")

                    # PE structure
                    pe = r.get("pe_details", {})
                    f.write("#### Cấu Trúc PE\n\n")
                    if pe.get("is_pe"):
                        secs = pe.get("sections", [])
                        sec_names = ", ".join(f"`{s['name']}`" for s in secs)
                        f.write(f"* Sections ({len(secs)}): {sec_names}\n")
                        dlls = list(pe.get("imports", {}).keys())
                        dll_str = ", ".join(f"`{d}`" for d in dlls[:5])
                        extra = f" ... và {len(dlls) - 5} DLL khác" if len(dlls) > 5 else ""
                        f.write(f"* DLLs ({len(dlls)}): {dll_str}{extra}\n")
                    else:
                        f.write("* Không phải file PE\n")
                    f.write("\n")

                    # Top 10 strings
                    strings = r.get("strings", [])
                    if strings:
                        f.write("#### Chuỗi Đặc Trưng (Top 10)\n\n")
                        for s in strings[:10]:
                            f.write(f"* `{s}`\n")
                        if len(strings) > 10:
                            f.write(f"* ... và {len(strings) - 10} chuỗi khác\n")
                        f.write("\n")

                    f.write("---\n\n")

            return report_path
        except Exception as e:
            print(f"Lỗi khi xuất batch report: {e}")
            return ""