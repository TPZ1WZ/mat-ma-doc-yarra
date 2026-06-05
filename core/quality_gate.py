import re
from typing import Dict, List, Any

class RuleDoctor:
    def __init__(self):
        # Tập hợp các từ khóa hoặc chuỗi đặc trưng quá ngắn/phổ biến dễ gây FP
        self.generic_indicators = [
            "text", "data", "code", "file", "path", "user", "error", "system",
            "run", "start", "stop", "open", "close", "read", "write", "load"
        ]

    def evaluate_rule(self, rule_text: str) -> Dict[str, Any]:
        """
        Phân tích chuyên sâu và chấm điểm chất lượng cho luật YARA
        Thang điểm: 100 (Giảm dần dựa trên các lỗi thiết kế luật phát hiện được)
        """
        score = 100
        warnings = []
        metrics = {
            "total_strings": 0,
            "short_strings_count": 0,
            "generic_strings_count": 0,
            "has_wide_and_ascii": False,
            "condition_complexity": "Low"
        }

        # 1. Trích xuất toàn bộ các dòng định nghĩa chuỗi trong block strings:
        # Tìm các đoạn nằm giữa dấu nháy kép để phân tích nội dung chuỗi ký tự
        string_definitions = re.findall(r'\s*\$[a-zA-Z0-9_]*\s*=\s*"([^"]+)"', rule_text)
        metrics["total_strings"] = len(string_definitions)

        if metrics["total_strings"] == 0:
            score -= 50
            warnings.append("Luật không chứa bất kỳ chuỗi đặc trưng nào (Chỉ có fallback hoặc logic rỗng). Nguy cơ False Negative cực cao.")
        else:
            # Kiểm tra chi tiết chất lượng từng chuỗi
            for s in string_definitions:
                # Điểm trừ nếu chuỗi quá ngắn (dưới 5 ký tự)
                if len(s) < 5:
                    metrics["short_strings_count"] += 1
                
                # Điểm trừ nếu chuỗi chứa các từ khóa quá phổ biến trong lập trình thông thường
                if any(gen in s.lower() for gen in self.generic_indicators):
                    metrics["generic_strings_count"] += 1

            # Trừ điểm dựa trên tỷ lệ chuỗi chất lượng kém
            if metrics["short_strings_count"] > 0:
                deduction = min(20, metrics["short_strings_count"] * 4)
                score -= deduction
                warnings.append(f"Phát hiện {metrics['short_strings_count']} chuỗi có độ dài quá ngắn (< 5 ký tự). Rất dễ bị trùng khớp nhầm với file sạch.")

            if metrics["generic_strings_count"] > 0:
                deduction = min(15, metrics["generic_strings_count"] * 3)
                score -= deduction
                warnings.append(f"Phát hiện {metrics['generic_strings_count']} chuỗi chứa từ khóa phổ biến (generic). Có thể tăng tỷ lệ False Positive.")

        # 2. Kiểm tra các modifier bổ trợ (ascii, wide)
        if "ascii" in rule_text.lower() and "wide" in rule_text.lower():
            metrics["has_wide_and_ascii"] = True
        else:
            score -= 10
            warnings.append("Luật không sử dụng đồng thời cả hai modifier 'ascii' và 'wide'. Có thể bỏ sót mã độc nếu chúng đổi cơ chế mã hóa chuỗi.")

        # 3. Phân tích điều kiện kích hoạt (Condition)
        condition_match = re.search(r'condition:\s*(.*)', rule_text, re.DOTALL | re.IGNORECASE)
        if condition_match:
            condition_str = condition_match.group(1).strip().strip('}')
            
            # Đánh giá độ chặt chẽ của điều kiện
            if "any of them" in condition_str.lower() or "1 of them" in condition_str.lower():
                score -= 15
                metrics["condition_complexity"] = "Weak"
                warnings.append("Điều kiện kích hoạt quá lỏng lẻo ('any of them' hoặc '1 of them'). Chỉ cần 1 chuỗi ngắn khớp là báo động, nguy cơ FP rất cao.")
            elif "all of them" in condition_str.lower():
                metrics["condition_complexity"] = "Strict"
            else:
                metrics["condition_complexity"] = "Medium"

        # Giới hạn điểm số không được âm
        score = max(0, score)

        # Phân cấp chất lượng luật dựa trên điểm số cuối cùng
        if score >= 80:
            rating = "Excellent (Luật có độ tin cậy cao, sẵn sàng triển khai)"
        elif score >= 60:
            rating = "Good (Luật chạy ổn định, cần giám sát thêm FP)"
        elif score >= 40:
            rating = "Fair (Luật ở mức trung bình, nên tinh chỉnh lại chuỗi)"
        else:
            rating = "Poor (Chất lượng luật kém, nguy cơ báo động giả hoặc lọt lưới rất cao)"

        return {
            "score": score,
            "rating": rating,
            "metrics": metrics,
            "warnings": warnings
        }