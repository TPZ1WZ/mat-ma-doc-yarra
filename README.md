# Automated Malware Family YARA Signature Generator

Hệ thống hỗ trợ phân tích tĩnh và tự động hóa quy trình trích xuất đặc trưng chung, sinh chữ ký YARA, kiểm thử chất lượng luật và xuất báo cáo nghiên cứu cho từng họ mã độc (Malware Family).

Dự án được phát triển song song hai giao diện: **Desktop GUI (Tkinter)** và **Local Web Mode (Flask)** đáp ứng nhu cầu phân tích linh hoạt.

---

##  Mục Tiêu Đề Tài
* **Tự động hóa toàn diện:** Thay vì viết tay, hệ thống tự động bóc tách và tìm ra điểm chung (chuỗi ASCII/Wide) giữa nhiều mẫu trong cùng họ dựa trên tỷ lệ bao phủ (`coverage`).
* **Lọc nhiễu thông minh (Rule Doctor):** Loại bỏ hoàn toàn các chuỗi runtime, bảng chữ cái, hàm API Windows phổ biến nhằm giảm tối đa tỷ lệ báo động giả (False Positive).
* **Family DNA Lab:** Xây dựng hồ sơ "vân tay sinh học" cho cả họ mã độc, ánh xạ kỹ nghệ tấn công lên ma trận MITRE ATT&CK.

---

##  Nguồn Mẫu Thử Nghiệm Chính
Dự án sử dụng kho dữ liệu mã độc thực tế phục vụ nghiên cứu từ hai nguồn lớn:
1. **VX-Underground (Samples/Families):** Kho lưu trữ các tập mẫu lớn có phân loại theo cấu trúc thư mục dòng họ rõ ràng.
2. **MalwareBazaar (Abuse.ch):** Trích xuất các mẫu được gắn tag cụ thể (Ví dụ tiêu biểu: `NetSupport` RAT).

>  **CẢNH BÁO AN TOÀN:** Dự án làm việc với các mẫu mã độc thực tế. Tuyệt đối chỉ thực thi, lưu trữ mẫu trong môi trường máy ảo cô lập (Sandbox/VM), không tắt Windows Defender trên máy thật và không chia sẻ các file mẫu ra ngoài môi trường an toàn.

---

##  Hướng Dẫn Cài Đặt và Cấu Hình

### Yêu cầu hệ thống
* Hệ điều hành: Windows 10 / 11
* Python bản: 3.10 trở lên
* Công cụ bổ sung: YARA CLI local (`yara64.exe`, `yarac64.exe`) đặt trong thư mục `3rdparty/yara/`.

### Các bước thiết lập nhanh
1. Di chuyển vào thư mục dự án và khởi tạo môi trường ảo:
```bash
   cd D:\Tai_lieu_hoc_tap\PhanTichMaDoc\DOAN
   python -m venv venv