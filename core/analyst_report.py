import os
from typing import Dict, Any
from core.analysis_common import format_file_size, write_markdown_report

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