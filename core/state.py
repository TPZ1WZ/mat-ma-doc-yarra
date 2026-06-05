import os
import threading

class AppState:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        # Đảm bảo Thread-safe Singleton khi chạy đa luồng hoặc Web mode
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(AppState, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        
        # Thư mục gốc của dự án
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Đường dẫn các thư mục chức năng mặc định
        self.rules_dir = os.path.join(self.base_dir, "rules")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.dbs_dir = os.path.join(self.base_dir, "dbs")
        self.strings_out_dir = os.path.join(self.base_dir, "strings_out")
        self.web_workspace_dir = os.path.join(self.base_dir, "web_workspace")
        self.yara_3rdparty_dir = os.path.join(self.base_dir, "3rdparty", "yara")

        # Khởi tạo thư mục vật lý nếu chưa tồn tại
        self._ensure_directories()

        # Trạng thái cấu hình runtime
        self.selected_family_dir = ""
        self.selected_single_sample = ""
        self.current_yara_backend = "yara-python"  # Hoặc "cli", "yara-x"
        self.is_web_mode_running = False
        
        # Quản lý log thời gian thực (Real-time log buffer)
        self.log_buffer = []
        self.log_lock = threading.Lock()

        self.navigate_callback = None  # Set by MainApplication to allow screens to navigate
        self._initialized = True

    def _ensure_directories(self):
        """Tự động tạo các thư mục cần thiết nếu chưa có sẵn"""
        dirs = [
            self.rules_dir, 
            self.reports_dir, 
            self.dbs_dir, 
            self.strings_out_dir, 
            self.web_workspace_dir,
            self.yara_3rdparty_dir
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)

    def append_log(self, message: str):
        """Ghi log an toàn giữa các luồng (Thread-safe)"""
        with self.log_lock:
            self.log_buffer.append(message)
            # Giới hạn tối đa 2000 dòng log gần nhất để tránh tràn bộ nhớ
            if len(self.log_buffer) > 2000:
                self.log_buffer.pop(0)

    def clear_log(self):
        """Xóa sạch bộ đệm log"""
        with self.log_lock:
            self.log_buffer.clear()

    def get_logs(self):
        """Lấy toàn bộ danh sách log hiện tại"""
        with self.log_lock:
            return list(self.log_buffer)