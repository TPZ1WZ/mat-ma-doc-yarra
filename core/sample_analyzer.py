import os
import re
import hashlib
import pefile
from typing import Dict, List, Any

class SampleAnalyzer:
    def __init__(self):
        # Biểu thức chính quy để trích xuất các chuỗi ASCII và Wide (Unicode) có độ dài từ 4 ký tự trở lên
        self.ascii_regex = re.compile(br'[ -~]{4,}')
        self.wide_regex = re.compile(br'(?:[ -~]\x00){4,}')

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Tính toán các mã băm MD5, SHA1, SHA256 của tệp tin mẫu"""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        # Đọc theo từng block để tránh tràn bộ nhớ đối với các tệp tin lớn
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha1_hash.update(byte_block)
                sha256_hash.update(byte_block)

        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }

    def extract_strings(self, file_path: str) -> List[str]:
        """Trích xuất toàn bộ chuỗi ký tự (ASCII & Wide/Unicode) từ tệp tin nhị phân"""
        strings_found = set()
        try:
            with open(file_path, "rb") as f:
                data = f.read(2 * 1024 * 1024)  # Giới hạn 2MB

            # Trích xuất ASCII strings
            for match in self.ascii_regex.finditer(data):
                try:
                    strings_found.add(match.group().decode('ascii'))
                except:
                    continue

            # Trích xuất Wide strings (bỏ đi các byte rỗng \x00 xen kẽ)
            for match in self.wide_regex.finditer(data):
                try:
                    strings_found.add(match.group().decode('utf-16le'))
                except:
                    continue
        except Exception as e:
            print(f"Lỗi khi trích xuất strings từ {file_path}: {str(e)}")

        return sorted(list(strings_found))

    def analyze_pe_structure(self, file_path: str) -> Dict[str, Any]:
        """Phân tích cấu trúc file PE (Sections, Imports) nếu mẫu là file thực thi Windows"""
        pe_info = {
            "is_pe": False,
            "sections": [],
            "imports": {}
        }

        try:
            # Tải cấu trúc file PE bằng pefile (chỉ parse thông tin cần thiết để tối ưu tốc độ)
            pe = pefile.PE(file_path, fast_load=True)
            pe_info["is_pe"] = True

            # 1. Thu thập thông tin các phân vùng (Sections)
            for section in pe.sections:
                try:
                    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                except:
                    section_name = "unknown"
                
                pe_info["sections"].append({
                    "name": section_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData
                })

            # 2. Thu thập các hàm API hệ thống được import (Import Address Table)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    try:
                        dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    except:
                        continue
                    
                    imported_funcs = []
                    for imp in entry.imports:
                        if imp.name:
                            try:
                                imported_funcs.append(imp.name.decode('utf-8', errors='ignore'))
                            except:
                                continue
                    
                    if imported_funcs:
                        pe_info["imports"][dll_name] = imported_funcs

        except pefile.PEFormatError:
            # Không phải file PE (có thể là mã độc dạng script, PDF, docx, jar, v.v.)
            pe_info["is_pe"] = False
        except Exception as e:
            print(f"Lỗi khi parse cấu trúc PE của {file_path}: {str(e)}")

        return pe_info

    def analyze_sample(self, file_path: str) -> Dict[str, Any]:
        """Tổng hợp toàn bộ quá trình phân tích tĩnh trên một mẫu"""
        if not os.path.exists(file_path):
            return {"error": f"File không tồn tại: {file_path}"}

        file_size = os.path.getsize(file_path)
        hashes = self.calculate_hashes(file_path)
        pe_details = self.analyze_pe_structure(file_path)
        extracted_strings = self.extract_strings(file_path)

        return {
            "file_name": os.path.basename(file_path),
            "file_path": file_path,
            "file_size": file_size,
            "hashes": hashes,
            "pe_details": pe_details,
            "strings": extracted_strings,
            "strings_count": len(extracted_strings)
        }