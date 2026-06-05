import os
import subprocess
from typing import Dict, List, Any
from core.state import AppState

# Thử import các backend Python thuần (nếu được cài đặt trong venv)
try:
    import yara
    HAS_YARA_PYTHON = True
except ImportError:
    HAS_YARA_PYTHON = False

try:
    import yara_x
    HAS_YARA_X = True
except ImportError:
    HAS_YARA_X = False


class YaraEngine:
    def __init__(self):
        self.state = AppState()
        # Định vị file thực thi YARA CLI mặc định trên Windows
        self.cli_path = os.path.join(self.state.yara_3rdparty_dir, "yara64.exe")
        self.compiler_cli_path = os.path.join(self.state.yara_3rdparty_dir, "yarac64.exe")

    def check_backend_availability(self) -> Dict[str, bool]:
        """Kiểm tra xem hệ thống hiện đang khả dụng những backend YARA nào"""
        cli_available = os.path.exists(self.cli_path)
        return {
            "yara-python": HAS_YARA_PYTHON,
            "yara-x": HAS_YARA_X,
            "yara-cli": cli_available
        }

    def compile_rule_text(self, rule_text: str) -> Dict[str, Any]:
        """
        Biên dịch thử nghiệm nội dung luật YARA dạng văn bản thô để phát hiện lỗi cú pháp.
        Trả về kết quả Pass/Fail kèm thông báo lỗi chi tiết (nếu có).
        """
        backend = self.state.current_yara_backend
        backends_status = self.check_backend_availability()

        # Tự động hạ cấp sang backend khả dụng nếu cấu hình hiện tại không chạy được
        if not backends_status.get(backend, False):
            if backends_status["yara-python"]:
                backend = "yara-python"
            elif backends_status["yara-x"]:
                backend = "yara-x"
            elif backends_status["yara-cli"]:
                backend = "yara-cli"
            else:
                return {"success": False, "error": "Không tìm thấy bất kỳ YARA backend nào khả dụng trên hệ thống."}

        # 1. Biên dịch bằng yara-python
        if backend == "yara-python":
            try:
                yara.compile(source=rule_text)
                return {"success": True, "backend_used": "yara-python", "error": None}
            except yara.SyntaxError as e:
                return {"success": False, "backend_used": "yara-python", "error": str(e)}

        # 2. Biên dịch bằng yara-x
        elif backend == "yara-x":
            try:
                yara_x.compile(rule_text)
                return {"success": True, "backend_used": "yara-x", "error": None}
            except Exception as e:
                return {"success": False, "backend_used": "yara-x", "error": str(e)}

        # 3. Biên dịch bằng YARA CLI thông qua tệp tin tạm
        elif backend == "yara-cli":
            temp_rule_path = os.path.join(self.state.web_workspace_dir, "temp_compile_check.yar")
            try:
                with open(temp_rule_path, "w", encoding="utf-8") as f:
                    f.write(rule_text)
                
                # Gọi yara64.exe với cờ kiểm tra cú pháp (không quét)
                # Sử dụng NUL làm bia quét giả lập trên Windows để lấy cú pháp đầu ra
                result = subprocess.run(
                    [self.cli_path, temp_rule_path, "NUL"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5
                )
                
                # Nếu có lỗi cú pháp, tệp tin thực thi YARA sẽ đẩy thông báo vào stderr
                if result.returncode != 0 or result.stderr:
                    return {"success": False, "backend_used": "yara-cli", "error": result.stderr.strip()}
                return {"success": True, "backend_used": "yara-cli", "error": None}
            
            except Exception as e:
                return {"success": False, "backend_used": "yara-cli", "error": f"Lỗi thực thi CLI: {str(e)}"}
            finally:
                if os.path.exists(temp_rule_path):
                    try: os.remove(temp_rule_path)
                    except: pass

        return {"success": False, "error": "Backend cấu hình không hợp lệ."}

    def scan_target(self, rule_path: str, target_path: str) -> List[Dict[str, Any]]:
        """
        Sử dụng tệp tin luật (.yar) đã lưu để quét một tệp tin đơn lẻ hoặc một thư mục mục tiêu.
        Trả về danh sách các kết quả phát hiện (matches).
        """
        matches_found = []
        if not os.path.exists(rule_path) or not os.path.exists(target_path):
            return matches_found

        backend = self.state.current_yara_backend
        backends_status = self.check_backend_availability()

        # Kiểm tra tính sẵn sàng trước khi quét
        if not backends_status.get(backend, False):
            if backends_status["yara-python"]: backend = "yara-python"
            elif backends_status["yara-cli"]: backend = "yara-cli"
            else: return matches_found

        # A. Quét bằng yara-python
        if backend == "yara-python" and HAS_YARA_PYTHON:
            try:
                rules = yara.compile(filepath=rule_path)
                if os.path.isdir(target_path):
                    for root, _, files in os.walk(target_path):
                        for file in files:
                            full_p = os.path.join(root, file)
                            matches = rules.match(full_p)
                            if matches:
                                matches_found.append({"file": full_p, "rules": [m.rule for m in matches]})
                else:
                    matches = rules.match(target_path)
                    if matches:
                        matches_found.append({"file": target_path, "rules": [m.rule for m in matches]})
            except Exception as e:
                print(f"Lỗi scan bằng yara-python: {str(e)}")

        # B. Quét bằng YARA CLI (Thích hợp cho tập mẫu lớn hoặc chạy song song không block)
        elif backend == "yara-cli" or (not HAS_YARA_PYTHON and backends_status["yara-cli"]):
            try:
                # Lệnh gọi quét cơ bản: yara64.exe <file_luật> <đường_dẫn_mục_tiêu>
                # Thêm cờ -r nếu quét đệ quy toàn bộ thư mục con
                cmd = [self.cli_path, rule_path, target_path]
                if os.path.isdir(target_path):
                    cmd.insert(1, "-r")

                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
                
                # Output của YARA CLI dạng: Tên_luật Đường_dẫn_file_bị_dính
                if result.stdout:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        parts = line.split(" ", 1)
                        if len(parts) == 2:
                            rule_name, matched_file = parts[0], parts[1]
                            matches_found.append({"file": matched_file, "rules": [rule_name]})
            except Exception as e:
                print(f"Lỗi scan bằng YARA CLI: {str(e)}")

        return matches_found