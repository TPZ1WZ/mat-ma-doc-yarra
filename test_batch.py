import sys, os, traceback
sys.path.insert(0, os.path.dirname(__file__))
from screens.analyze_screen import calculate_entropy, detect_behavior_hints
from core.sample_analyzer import SampleAnalyzer

folder = r"C:\Users\shinc\Downloads\PTMD_TAN\cung-ho-ma-doc\ma-doc"
analyzer = SampleAnalyzer()
files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
print(f"Found {len(files)} files")

for fp in files:
    try:
        res = analyzer.analyze_sample(fp)
        if "error" in res:
            print(f"  ERROR: {res['error']}")
            continue
        entropy = calculate_entropy(fp)
        behaviors = detect_behavior_hints(res.get("strings", []))
        print(f"  OK: {os.path.basename(fp)[:50]}")
        print(f"      entropy={entropy}, strings={res.get('strings_count',0)}, behaviors={len(behaviors)}")
    except Exception:
        print(f"  EXCEPTION: {os.path.basename(fp)[:50]}")
        traceback.print_exc()
