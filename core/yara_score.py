import re
from typing import Dict, List, Any


class YaraScoreAnalyzer:
    """Phân tích và chấm điểm từng rule trong file .yar."""

    GENERIC_STRINGS = {
        "text", "data", "code", "file", "path", "user", "error", "system",
        "run", "start", "stop", "open", "close", "read", "write", "load",
        "this", "that", "null", "none", "true", "false", "http", "www",
    }

    def analyze_rule_file(self, rule_path: str) -> Dict[str, Any]:
        """
        Đọc file .yar và phân tích điểm từng rule.
        Trả về dict tổng hợp và danh sách kết quả từng rule.
        """
        try:
            with open(rule_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return {"error": str(e), "rules": []}

        rules = self._split_rules(content)
        if not rules:
            return {"error": "Không tìm thấy rule nào trong file.", "rules": []}

        analyzed = [self._score_single_rule(name, body) for name, body in rules]

        scores = [r["score"] for r in analyzed]
        return {
            "rule_count": len(analyzed),
            "max_score": max(scores),
            "min_score": min(scores),
            "avg_score": round(sum(scores) / len(scores), 1),
            "rules": analyzed,
        }

    def _split_rules(self, content: str) -> List[tuple]:
        """Tách từng rule riêng lẻ từ nội dung file .yar."""
        pattern = re.compile(r'rule\s+(\w+)\s*(?::[^\{]*)?\{([^}]*(?:\{[^}]*\}[^}]*)*)\}', re.DOTALL)
        return [(m.group(1), m.group(0)) for m in pattern.finditer(content)]

    def _score_single_rule(self, rule_name: str, rule_text: str) -> Dict[str, Any]:
        score = 100
        warnings = []
        metrics = {}

        # Đếm chuỗi định nghĩa trong block strings:
        string_defs = re.findall(r'\$\w*\s*=\s*"([^"]*)"', rule_text)
        string_count = len(string_defs)
        metrics["string_count"] = string_count

        # Đếm chuỗi ngắn (< 5 ký tự)
        short_count = sum(1 for s in string_defs if len(s) < 5)
        metrics["short_strings"] = short_count
        if short_count > 0:
            deduction = min(20, short_count * 4)
            score -= deduction
            warnings.append(f"{short_count} chuỗi quá ngắn (< 5 ký tự)")

        # Đếm chuỗi generic
        generic_count = sum(
            1 for s in string_defs
            if any(g in s.lower() for g in self.GENERIC_STRINGS)
        )
        metrics["generic_strings"] = generic_count
        if generic_count > 0:
            deduction = min(15, generic_count * 3)
            score -= deduction
            warnings.append(f"{generic_count} chuỗi chứa từ khóa phổ biến")

        # Kiểm tra thiếu modifier ascii/wide
        has_ascii = "ascii" in rule_text.lower()
        has_wide = "wide" in rule_text.lower()
        metrics["has_ascii"] = has_ascii
        metrics["has_wide"] = has_wide
        if not (has_ascii and has_wide):
            score -= 10
            warnings.append("Thiếu cả hai modifier 'ascii' và 'wide'")

        # Phân tích điều kiện
        cond_match = re.search(r'condition:\s*(.*?)(?:\}|$)', rule_text, re.DOTALL | re.IGNORECASE)
        condition_str = cond_match.group(1).strip().rstrip('}').strip() if cond_match else ""
        if "any of them" in condition_str.lower() or "1 of them" in condition_str.lower():
            score -= 15
            warnings.append("Điều kiện quá lỏng: 'any of them'")

        # Kiểm tra thiếu metadata
        has_meta = "meta:" in rule_text.lower()
        metrics["has_meta"] = has_meta
        if not has_meta:
            score -= 5
            warnings.append("Không có block meta")

        score = max(0, score)

        if score >= 80:
            rating = "Excellent"
        elif score >= 60:
            rating = "Good"
        elif score >= 40:
            rating = "Fair"
        else:
            rating = "Poor"

        return {
            "rule_name": rule_name,
            "score": score,
            "rating": rating,
            "string_count": string_count,
            "short_strings": short_count,
            "generic_strings": generic_count,
            "warnings": warnings,
            "metrics": metrics,
        }
