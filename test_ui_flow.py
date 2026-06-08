"""Test toan bo flow: scan folder -> select row -> kiem tra data trong tabs"""
import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

import tkinter as tk
from app import MainApplication

FOLDER = r"C:\Users\shinc\Downloads\PTMD_TAN\cung-ho-ma-doc\ma-doc"

root = tk.Tk()
root.title("TEST")
root.geometry("1200x750")
app = MainApplication(root)

def run_test():
    # 1. Navigate to Samples screen
    app.show_screen("Analyze")
    root.update()

    screen = app.screens.get("Analyze")
    if not screen:
        print("FAIL: Khong tim thay AnalyzeScreen")
        root.destroy()
        return

    # 2. Switch sang Batch Mode
    screen.mode_var.set("batch")
    screen._toggle_mode()
    screen.batch_dir_var.set(FOLDER)
    root.update()
    print(f"[1] Batch mode set, folder = {FOLDER}")

    # 3. Chay scan
    screen._run_batch()
    print("[2] Scan started...")

    # 4. Doi scan xong (worker thread)
    def check_results():
        results = screen._batch_results
        print(f"[3] _batch_results count = {len(results)}")

        if not results:
            print("FAIL: Khong co ket qua sau scan")
            root.after(500, check_results)
            return

        # 5. Kiem tra treeview co rows khong
        children = screen.batch_tree.get_children()
        print(f"[4] Treeview rows = {len(children)}")

        # 6. Select row dau tien
        if children:
            screen.batch_tree.selection_set(children[0])
            screen.batch_tree.event_generate("<<TreeviewSelect>>")
            root.update()
            print(f"[5] Selected row 0: {screen.batch_tree.item(children[0])['values'][0]}")

        # 7. Kiem tra Tong quan tab
        tong_quan = screen.result_text.get("1.0", tk.END).strip()
        print(f"[6] Tong quan: {len(tong_quan)} chars")

        # 8. Kiem tra Strings tab
        strings_content = screen.strings_text.get("1.0", tk.END).strip()
        print(f"[7] Strings: {len(strings_content)} chars")

        # 9. Kiem tra Behavior Hints
        bh_rows = screen.behavior_tree.get_children()
        print(f"[8] Behavior rows = {len(bh_rows)}")

        # 10. Kiem tra nb hien tai dang o tab nao
        current_tab = screen.nb.index(screen.nb.select())
        print(f"[9] Current tab index = {current_tab}")

        if tong_quan and strings_content:
            print("PASS: Tat ca tabs deu co data!")
        else:
            print(f"FAIL: tong_quan={bool(tong_quan)} strings={bool(strings_content)}")

        root.after(1000, root.destroy)

    root.after(3000, check_results)

root.after(500, run_test)
root.mainloop()
