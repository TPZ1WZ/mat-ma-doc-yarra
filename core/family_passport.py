import os
import csv
from typing import Dict, Any
from core.analysis_common import write_markdown_report

class FamilyPassportGenerator:
    def __init__(self):
        pass

    def generate_family_passport(self, family_data: Dict[str, Any], doctor_result: Dict[str, Any], report_dir: str) -> str:
        """
        Tổng hợp toàn bộ hồ sơ "Vân tay sinh học - Family DNA Lab" cho cả một họ mẫu.
        Xuất ra một file tổng hợp .md và hai file bảng biểu .csv đi kèm.
        """
        family_name = family_data.get("family_name", "Unknown_Family")
        safe_family_name = "".join([c if c.isalnum() else "_" for c in family_name])
        
        base_report_name = f"family_dna_{safe_family_name}"
        md_report_path = os.path.join(report_dir, f"{base_report_name}.md")
        csv_features_path = os.path.join(report_dir, f"{base_report_name}_features.csv")
        csv_samples_path = os.path.join(report_dir, f"{base_report_name}_samples.csv")

        # 1. Tạo file dữ liệu bảng biểu CSV cho danh sách mẫu
        try:
            with open(csv_samples_path, mode='w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["File Name", "SHA256"])
                for s in family_data.get("samples", []):
                    writer.writerow([s["file_name"], s["sha256"]])
        except Exception as e:
            print(f"Lỗi khi ghi file CSV mẫu: {str(e)}")

        # 2. Tạo file dữ liệu bảng biểu CSV cho các đặc trưng chung tìm được
        try:
            with open(csv_features_path, mode='w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["String Feature", "Appearance Count", "Coverage Percentage"])
                for feat in family_data.get("features", []):
                    writer.writerow([feat["string"], feat["appearance_count"], f"{feat['percentage']:.2f}%"])
        except Exception as e:
            print(f"Lỗi khi ghi file CSV đặc trưng: {str(e)}")

        # 3. Gom cấu trúc nội dung để xuất file báo cáo tổng hợp Markdown (.md)
        summary = {
            "Tên họ mã độc": family_name,
            "Tổng số lượng mẫu nghiên cứu": family_data.get("total_samples", 0),
            "Số lượng đặc trưng chung trích xuất": len(family_data.get("features", [])),
            "Điểm số đánh giá chất lượng luật (Rule Doctor)": f"{doctor_result.get('score', 0)}/100",
            "Phân cấp chất lượng luật": doctor_result.get("rating", "N/A")
        }

        sample_list_md = [f"`{s['file_name']}` (SHA256: `{s['sha256'][:16]}...`)" for s in family_data.get("samples", [])]
        
        feature_list_md = []
        for feat in family_data.get("features", [])[:15]: # Lấy top 15 đặc trưng xuất sắc nhất
            feature_list_md.append(f"Khớp trên **{feat['percentage']:.1f}%** số mẫu $\\rightarrow$ Chuỗi: `{feat['string']}`")
        if len(family_data.get("features", [])) > 15:
            feature_list_md.append(f"... Và {len(family_data.get('features', [])) - 15} đặc trưng chung khác được ghi nhận trong file phụ lục CSV.")

        doctor_warnings = doctor_result.get("warnings", [])
        if not doctor_warnings:
            doctor_warnings = ["Không có cảnh báo nghiêm trọng nào. Luật cấu trúc rất tốt!"]

        # Các gợi ý heuristic hỗ trợ phân tích định hướng
        heuristic_tips = [
            "Kiểm tra kỹ các chuỗi có tỷ lệ coverage 100% để tìm địa chỉ IP C2 hoặc chuỗi cấu hình cố định của mã độc.",
            "Nếu điểm số Rule Doctor thấp, hãy thử giảm bớt các chuỗi quá ngắn hoặc tăng tham số coverage khi sinh luật.",
            "Nên sử dụng file dữ liệu Goodware sạch trong màn hình Validate để chạy rà soát loại trừ False Positive trước khi đóng gói phân phối."
        ]

        sections = {
            "1. Tóm Tắt Hồ Sơ (Executive Summary)": summary,
            "2. Danh Sách Các Tệp Mẫu Thuộc Họ": sample_list_md,
            "3. Top Đặc Trưng Mã Vạch Thống Nhất (DNA Features)": feature_list_md,
            "4. Đánh Giá Khuyết Tật Luật & Cảnh Báo (Rule Doctor)": doctor_warnings,
            "5. Hướng Dẫn & Khuyến Nghị Cho Chuyên Viên Vận Hành": heuristic_tips
        }

        success = write_markdown_report(md_report_path, f"HỒ SƠ VÂN TAY SỐ (MALWARE FAMILY PASSPORT): {family_name}", sections)
        return md_report_path if success else ""