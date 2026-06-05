import os
import re
from typing import List, Dict, Any

def format_file_size(size_in_bytes: int) -> str:
    """Biến đổi kích thước tệp tin từ byte sang định dạng dễ đọc (KB, MB)"""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} Bytes"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    else:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"

def sanitize_yara_rule_name(name: str) -> str:
    """Chuẩn hóa một chuỗi bất kỳ thành tên hợp lệ tuân thủ cú pháp luật YARA"""
    # Chỉ giữ lại chữ cái, số và dấu gạch dưới. Thay thế khoảng trắng/ký tự lạ bằng dấu "_"
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Loại bỏ dấu gạch dưới lặp lại liên tiếp
    safe_name = re.sub(r'_+', '_', safe_name)
    # Cú pháp YARA không cho phép tên luật bắt đầu bằng số
    if safe_name and safe_name[0].isdigit():
        safe_name = "Rule_" + safe_name
    return safe_name.strip('_')

def read_file_safely(file_path: str, max_size_mb: int = 20) -> str:
    """Đọc tệp tin văn bản một cách an toàn, có giới hạn dung lượng để tránh treo RAM"""
    if not os.path.exists(file_path):
        return ""
    
    # Kiểm tra kích thước tệp tin trước khi nạp vào bộ nhớ
    if os.path.getsize(file_path) > max_size_mb * 1024 * 1024:
        return f"[ERROR] Kích thước file vượt quá giới hạn an toàn ({max_size_mb}MB)."

    try:
        # Thử đọc với mã hóa utf-8, nếu lỗi thì fallback sang hệ phòng thủ iso-8859-1
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"[ERROR] Không thể đọc file: {str(e)}"

def write_markdown_report(file_path: str, title: str, sections: Dict[str, Any]) -> bool:
    """Hỗ trợ xuất báo cáo phân tích nhanh ra định dạng cấu trúc Markdown (.md)"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"# {title}\n\n")
            f.write("---\n\n")
            
            for section_title, content in sections.items():
                f.write(f"## {section_title}\n")
                if isinstance(content, list):
                    for item in content:
                        f.write(f"* {item}\n")
                elif isinstance(content, dict):
                    for k, v in content.items():
                        f.write(f"* **{k}**: {v}\n")
                else:
                    f.write(f"{content}\n")
                f.write("\n")
        return True
    except Exception as e:
        print(f"Lỗi khi xuất báo cáo MD: {str(e)}")
        return False

def calculate_entropy(data: bytes) -> float:
    """Tính toán điểm số Entropy (độ hỗn loạn dữ liệu) để nhận diện mẫu có bị Pack/Encrypt hay không"""
    import math
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    # Đếm tần suất xuất hiện của tất cả các giá trị byte từ 0x00 đến 0xFF
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    # Tính toán theo công thức Shannon Entropy
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
        
    return entropy