# 📂 Cấu Trúc Cây Thư Mục Dự Án (Project Tree)

D:\Tai_lieu_hoc_tap\PhanTichMaDoc\DOAN
│   main.py                  # Điểm vào chính của ứng dụng Desktop (Tkinter)
│   app.py                   # Bộ điều phối luồng giao diện và chuyển đổi các Screen
│   web_server.py            # Local Web Server (Flask) xử lý Dashboard và SSE job
│   yarGen.py                # Bộ lõi sinh luật YARA tích hợp từ mã nguồn mở
│   requirements.txt         # Quản lý các thư viện phụ thuộc của dự án
│   README.md                # Tài liệu hướng dẫn tổng quan dự án
│   tree.md                  # Sơ đồ quản lý cấu trúc file hệ thống
│
├───core/                    # 🧠 TẦNG LÕI XỬ LÝ LOGIC (BACKEND)
│       state.py             # Quản lý trạng thái ứng dụng (Global State / Singleton)
│       sample_analyzer.py   # Phân tích mẫu đơn lẻ, tính hash, trích xuất PE tĩnh
│       family_signature.py  # Thuật toán tính toán Coverage, lọc nhiễu, tìm chuỗi chung
│       yara_engine.py       # Wrapper điều phối các YARA backend (CLI, yara-python)
│       runner.py            # Quản lý tiến trình chạy ngầm (Subprocess) và stream log
│       analysis_common.py   # Các hàm tiện ích dùng chung (đọc file, định dạng text)
│       quality_gate.py      # Bộ chấm điểm chất lượng luật và cảnh báo (Rule Doctor)
│       analyst_report.py    # Module kết xuất báo cáo phân tích tĩnh cá nhân
│       family_passport.py   # Module tổng hợp hồ sơ "vân tay" cho cả họ mã độc
│
├───screens/                 #  TẦNG GIAO DIỆN DESKTOP (TKINTER)
│       analyze_screen.py    # Màn hình phân tích mẫu đơn lẻ
│       family_screen.py     # Màn hình chọn tập mẫu theo họ
│       generate_screen.py   # Màn hình cấu hình tham số sinh luật YARA
│       monitor_screen.py    # Màn hình theo dõi log luồng thời gian thực
│       validate_screen.py   # Màn hình kiểm thử luật (Compile & Scan) với Goodware
│       reports_screen.py    # Màn hình quản lý các tệp báo cáo đã xuất
│       analysis_suite_screen.py # Màn hình chạy Family DNA Lab tổng hợp nâng cao
│       web_mode_screen.py   # Màn hình bật/tắt và hiển thị link Local Web Server
│
├───rules/                   #  Thư mục chứa các file luật YARA đầu ra (.yar)
├───reports/                 #  Thư mục chứa báo cáo phân tích xuất ra (.md, .csv)
├───strings_out/             #  Thư mục chứa chuỗi trích xuất trung gian của yarGen
├───dbs/                     #  Thư mục chứa cơ sở dữ liệu mẫu sạch (Goodware DB)
├───3rdparty/                #  Thư mục chứa công cụ bên thứ ba (YARA CLI portable)
└───web_workspace/           #  Không gian lưu trữ tạm thời cho các job chạy từ Web UI