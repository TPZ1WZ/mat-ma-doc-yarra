import os
from typing import List, Dict, Any
from core.sample_analyzer import SampleAnalyzer

class FamilySignatureGenerator:
    def __init__(self):
        self.analyzer = SampleAnalyzer()
        # Bộ lọc blacklist cơ bản để loại bỏ nhiễu hệ thống (Anti-False Positive)
        self.blacklist_strings = {
            "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll", "ole32.dll",
            "getprocaddress", "getmodulehandlea", "loadlibrarya", "exitprocess",
            ".text", ".data", ".rsrc", ".reloc", ".idata", ".rdata",
            "this program cannot be run in DOS mode", "microsoft", "windows",
            "padding", "programfiles", "appdata", "localsettings"
        }

    def _is_blacklisted(self, string: str) -> bool:
        """Kiểm tra xem chuỗi có thuộc danh sách nhiễu hệ thống hoặc quá ngắn không"""
        s_lower = string.strip().lower()
        if len(s_lower) < 4:
            return True
        if s_lower in self.blacklist_strings:
            return True
        # Loại bỏ các chuỗi chỉ toàn ký tự lặp lại hoặc bảng chữ cái đơn thuần
        if len(set(s_lower)) <= 2:
            return True
        return False

    def process_family_directory(self, dir_path: str, coverage: float = 0.6) -> Dict[str, Any]:
        """
        Quét thư mục chứa họ mã độc và trích xuất các đặc trưng chung
        - coverage: Tỷ lệ mẫu tối thiểu phải chứa chuỗi đặc trưng (0.0 đến 1.0)
        """
        if not os.path.isdir(dir_path):
            return {"error": f"Thư mục không tồn tại: {dir_path}"}

        # Lấy danh sách tất cả file trong thư mục họ mã độc
        sample_files = [
            os.path.join(dir_path, f) for f in os.listdir(dir_path) 
            if os.path.isfile(os.path.join(dir_path, f))
        ]
        
        total_samples = len(sample_files)
        if total_samples == 0:
            return {"error": "Thư mục không chứa mẫu mã độc nào."}

        # Lưu trữ tần suất xuất hiện của từng chuỗi trên toàn bộ tập mẫu
        string_frequency: Dict[str, int] = {}
        samples_analyzed = []

        for sample_path in sample_files:
            # Gọi tầng core/sample_analyzer để trích xuất tĩnh
            res = self.analyzer.analyze_sample(sample_path)
            if "error" in res:
                continue
            
            samples_analyzed.append({
                "file_name": res["file_name"],
                "sha256": res["hashes"]["sha256"]
            })

            # Điểm danh các chuỗi xuất hiện trong mẫu này (sử dụng set để không trùng lặp trong cùng 1 mẫu)
            unique_strings_in_sample = set(res["strings"])
            for s in unique_strings_in_sample:
                if self._is_blacklisted(s):
                    continue
                string_frequency[s] = string_frequency.get(s, 0) + 1

        # Lọc các chuỗi đạt tỷ lệ bao phủ (coverage) mong muốn
        common_features = []
        min_appearance = max(1, int(total_samples * coverage))

        for string, count in string_frequency.items():
            if count >= min_appearance:
                common_features.append({
                    "string": string,
                    "appearance_count": count,
                    "percentage": (count / total_samples) * 100
                })

        # Sắp xếp đặc trưng theo độ phổ biến giảm dần và độ dài chuỗi
        common_features.sort(key=lambda x: (x["appearance_count"], len(x["string"])), reverse=True)

        return {
            "family_name": os.path.basename(dir_path.rstrip(r"\/")),
            "total_samples": total_samples,
            "min_appearance_required": min_appearance,
            "samples": samples_analyzed,
            "features": common_features
        }

    def generate_yara_rule(self, family_data: Dict[str, Any], max_features: int = 20) -> str:
        """Dựa trên đặc trưng chung đã trích xuất để sinh chuỗi luật YARA hoàn chỉnh"""
        family_name = family_data.get("family_name", "Unknown_Malware_Family")
        # Chuẩn hóa tên họ mã độc để phù hợp với quy tắc đặt tên luật YARA (không chứa ký tự đặc biệt)
        safe_name = "".join([c if c.isalnum() else "_" for c in family_name])
        
        features = family_data.get("features", [])[:max_features]
        total_samples = family_data.get("total_samples", 1)

        rule_lines = [
            f"rule MalFamily_{safe_name} {{",
            "    meta:",
            f'        description = "Auto-generated rule for {family_name} family"',
            '        author = "Automated Malware Family YARA Signature Generator"',
            f'        total_samples_analyzed = {total_samples}',
            "    strings:"
        ]

        # Điền các chuỗi đặc trưng vào phần định nghĩa strings của luật
        if not features:
            # Dự phòng nếu tập mẫu không tìm thấy điểm chung nào để tránh gãy logic biên dịch
            rule_lines.append('        $dummy_fallback = "NEVER_MATCH_ANY_SAMPLE_DUE_TO_NO_COMMON_STRINGS"')
        else:
            for i, feat in enumerate(features):
                # Escape các dấu nháy kép và ký tự đặc biệt có trong chuỗi để tránh lỗi cú pháp YARA
                escaped_str = feat["string"].replace('\\', '\\\\').replace('"', '\\"')
                rule_lines.append(f'        $str_{i} = "{escaped_str}" ascii wide')

        rule_lines.append("    condition:")
        
        if not features:
            rule_lines.append("        false")
        else:
            # Điều kiện tối thiểu: Phải khớp ít nhất 1/2 số lượng đặc trưng được chọn đưa vào luật
            min_match = max(1, len(features) // 2)
            rule_lines.append(f"        {min_match} of them")

        rule_lines.append("}")
        return "\n".join(rule_lines)
    
