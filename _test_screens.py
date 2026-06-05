"""
Test script: khởi tạo từng Screen, phát hiện crash/error runtime.
Chạy có cửa sổ thật (không cần ảo) vì Windows có display.
"""
import sys, traceback, time
import tkinter as tk
from tkinter import ttk

ROOT_DIR = r"c:\Users\shinc\Downloads\PTMD_TAN\yarGen-main"
sys.path.insert(0, ROOT_DIR)

results = []

def try_screen(name, factory):
    try:
        root = tk.Tk()
        root.withdraw()
        frame = factory(root)
        root.update()      # xử lý một vòng events để widget vẽ xong
        root.update_idletasks()
        root.destroy()
        results.append((name, "PASS", ""))
        print(f"  [PASS] {name}")
    except Exception as e:
        tb = traceback.format_exc()
        results.append((name, "FAIL", str(e)))
        print(f"  [FAIL] {name}: {e}")
        print(f"         {tb.splitlines()[-1]}")

print("\n=== YARA Studio – Screen Load Test ===\n")

# Home
try_screen("HomeScreen", lambda r: __import__("screens.home_screen", fromlist=["HomeScreen"]).HomeScreen(r, navigate=lambda k: None))

# Setup
try_screen("SetupScreen", lambda r: __import__("screens.setup_screen", fromlist=["SetupScreen"]).SetupScreen(r))

# Analyze
try_screen("AnalyzeScreen", lambda r: __import__("screens.analyze_screen", fromlist=["AnalyzeScreen"]).AnalyzeScreen(r))

# Family
try_screen("FamilyScreen", lambda r: __import__("screens.family_screen", fromlist=["FamilyScreen"]).FamilyScreen(r))

# Generate
try_screen("GenerateScreen", lambda r: __import__("screens.generate_screen", fromlist=["GenerateScreen"]).GenerateScreen(r))

# Monitor
try_screen("MonitorScreen", lambda r: __import__("screens.monitor_screen", fromlist=["MonitorScreen"]).MonitorScreen(r))

# Validate
try_screen("ValidateScreen", lambda r: __import__("screens.validate_screen", fromlist=["ValidateScreen"]).ValidateScreen(r))

# Analysis Suite
try_screen("AnalysisSuiteScreen", lambda r: __import__("screens.analysis_suite_screen", fromlist=["AnalysisSuiteScreen"]).AnalysisSuiteScreen(r))

# Reports
try_screen("ReportsScreen", lambda r: __import__("screens.reports_screen", fromlist=["ReportsScreen"]).ReportsScreen(r))

# Web Mode
try_screen("WebModeScreen", lambda r: __import__("screens.web_mode_screen", fromlist=["WebModeScreen"]).WebModeScreen(r))

# App integration test
print("\n--- App integration (MainApplication) ---")
try:
    root = tk.Tk()
    root.withdraw()
    from app import MainApplication
    app = MainApplication(root)
    root.update()
    root.update_idletasks()
    # Switch to every screen
    for key in ["Home","Setup","Analyze","Family","Generate","Monitor","Validate","AnalysisSuite","Reports","WebMode"]:
        app.show_screen(key)
        root.update()
    root.destroy()
    results.append(("MainApplication + all screens", "PASS", ""))
    print("  [PASS] MainApplication + all screens switchable")
except Exception as e:
    results.append(("MainApplication", "FAIL", str(e)))
    print(f"  [FAIL] MainApplication: {e}")
    print(f"         {traceback.format_exc()}")

# Summary
passed = sum(1 for _, s, _ in results if s == "PASS")
failed = sum(1 for _, s, _ in results if s == "FAIL")
print(f"\n=== RESULT: {passed} PASS / {failed} FAIL / {len(results)} total ===")
if failed:
    print("\nFailed items:")
    for name, status, err in results:
        if status == "FAIL":
            print(f"  • {name}: {err}")
sys.exit(0 if failed == 0 else 1)
