import tkinter as tk
from app import MainApplication

def main():
    root = tk.Tk()
    root.title("Automated Malware Family YARA Signature Generator")
    
    # Thiết lập kích thước cửa sổ mặc định (Rộng x Cao)
    root.geometry("1200x750")
    root.minsize(1000, 650)
    
    # Khởi chạy ứng dụng chính
    app = MainApplication(root)
    
    # Vòng lặp vô hạn để duy trì giao diện Desktop
    root.mainloop()

if __name__ == "__main__":
    main()