import os
import sys
import subprocess
import threading
from typing import List, Callable, Optional
from core.state import AppState

class BackgroundRunner:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.state = AppState()
        self.current_process: Optional[subprocess.Popen] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self._initialized = True

    def _read_output_stream(self, process: subprocess.Popen, callback: Optional[Callable[[str], None]]):
        """Đọc liên tục từng dòng dữ liệu từ stdout và stderr của tiến trình con"""
        # Đọc luồng ra tiêu chuẩn (stdout)
        if process.stdout:
            for line in iter(process.stdout.readline, ""):
                cleaned_line = line.strip()
                if cleaned_line:
                    # Đẩy dữ liệu vào hệ thống lưu trữ log toàn cục
                    self.state.append_log(cleaned_line)
                    # Gọi hàm callback phụ trợ phục vụ cập nhật UI nếu có
                    if callback:
                        try: callback(cleaned_line)
                        except: pass

        # Đọc luồng báo lỗi (stderr) nếu tiến trình gặp sự cố gãy luồng
        if process.stderr:
            for line in iter(process.stderr.readline, ""):
                cleaned_line = line.strip()
                if cleaned_line:
                    warning_line = f"[WARNING/ERROR] {cleaned_line}"
                    self.state.append_log(warning_line)
                    if callback:
                        try: callback(warning_line)
                        except: pass

        # Chờ tiến trình kết thúc hoàn toàn để thu dọn tài nguyên hệ thống
        process.wait()
        self.state.append_log(f"--- Tiến trình kết thúc với mã trạng thái: {process.returncode} ---")

    def start_task(self, cmd_args: List[str], cwd: Optional[str] = None, callback: Optional[Callable[[str], None]] = None) -> bool:
        """
        Khởi chạy một câu lệnh hệ thống dưới nền ẩn bất đồng bộ.
        Trả về True nếu tiến trình khởi chạy thành công.
        """
        if self.current_process and self.current_process.poll() is None:
            self.state.append_log("[ERROR] Một tiến trình khác đang chạy dưới nền, không thể khởi chạy tác vụ mới.")
            return False

        # Thiết lập môi trường Python không buffer dữ liệu (Unbuffered output) 
        # Đảm bảo dữ liệu log xuất hiện ngay lập tức trên UI/Web thay vì bị kẹt trong cache bộ nhớ
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self.state.clear_log()
            self.state.append_log(f"[INFO] Bắt đầu thực thi lệnh: {' '.join(cmd_args)}")

            # Kích hoạt tiến trình con ẩn hoàn toàn cửa sổ đen (đối với môi trường Windows)
            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0  # SW_HIDE

            self.current_process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd if cwd else self.state.base_dir,
                env=env,
                text=True,
                startupinfo=startupinfo,
                bufsize=1  # Chế độ Line-buffered đọc dữ liệu theo dòng cực kỳ tối ưu
            )

            # Khởi tạo một tiểu trình (Thread) độc lập chuyên trách việc hứng dữ liệu log stream
            self.monitor_thread = threading.Thread(
                target=self._read_output_stream,
                args=(self.current_process, callback),
                daemon=True # Đảm bảo Thread tự giải phóng khi tắt ứng dụng chính
            )
            self.monitor_thread.start()
            return True

        except Exception as e:
            self.state.append_log(f"[FATAL ERROR] Lỗi khởi chạy tiến trình: {str(e)}")
            return False

    def terminate_current_task(self):
        """Cưỡng bức chấm dứt ngay lập tức tác vụ ngầm đang chạy (Nút bấm Stop/Abort)"""
        if self.current_process and self.current_process.poll() is None:
            try:
                self.state.append_log("[INFO] Đang gửi lệnh hủy tiến trình con...")
                self.current_process.terminate()
                # Chờ tối đa 3 giây để tiến trình tự dọn dẹp, nếu cứng đầu sẽ tiến hành Kill chết hẳn
                try:
                    self.current_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.current_process.kill()
                self.state.append_log("[INFO] Đã dừng tác vụ ngầm thành công.")
            except Exception as e:
                self.state.append_log(f"[ERROR] Lỗi phát sinh khi đóng tiến trình: {str(e)}")
        else:
            self.state.append_log("[INFO] Không có tác vụ ngầm nào đang hoạt động.")

    def is_running(self) -> bool:
        """Kiểm tra trạng thái xem tác vụ nền còn đang chạy hay không"""
        if self.current_process and self.current_process.poll() is None:
            return True
        return False