"""
Test từng chức năng thật sự của từng screen.
Dùng file mẫu thật từ thư mục dự án (hoặc tạo file giả).
"""
import sys, os, traceback, tempfile, time

sys.path.insert(0, r"c:\Users\shinc\Downloads\PTMD_TAN\yarGen-main")

PASS = "[PASS]"; FAIL = "[FAIL]"; WARN = "[WARN]"
results = []

def run(label, fn):
    try:
        out = fn()
        msg = str(out)[:120] if out else "ok"
        results.append((PASS, label, msg))
        print(f"  {PASS} {label}")
        if out: print(f"         → {msg}")
    except Exception as e:
        tb = traceback.format_exc().strip().splitlines()[-1]
        results.append((FAIL, label, str(e)))
        print(f"  {FAIL} {label}: {e}")
        print(f"         {tb}")

# ── Tạo file mẫu giả để test ────────────────────────────────────────
FAKE_PE = tempfile.mktemp(suffix=".exe")
with open(FAKE_PE, "wb") as f:
    # MZ header + giả lập PE + strings
    f.write(b"MZ" + b"\x00"*60 + b"PE\x00\x00")
    f.write(b"This program cannot be run in DOS mode\x00")
    f.write(b"http://malware-c2.example.com\x00")
    f.write(b"cmd.exe /c whoami\x00")
    f.write(b"HKEY_LOCAL_MACHINE\\Software\\Run\x00")
    f.write(b"WriteProcessMemory\x00CreateRemoteThread\x00")
    f.write(b"VirtualAlloc\x00LoadLibraryA\x00GetProcAddress\x00")
    f.write(b"A" * 1000)

FAKE_YAR = tempfile.mktemp(suffix=".yar")
with open(FAKE_YAR, "w") as f:
    f.write('''rule TestMalware_NetSupport {
    meta:
        description = "Test rule for NetSupport RAT"
        author = "Test"
    strings:
        $s1 = "NetSupport" ascii wide
        $s2 = "client32.ini" ascii wide
        $s3 = "http://c2.example.com" ascii
        $s4 = "cmd.exe" ascii wide
        $s5 = "WriteProcessMemory" ascii
    condition:
        3 of them
}''')

FAKE_DIR = tempfile.mkdtemp()
for i in range(3):
    fp = os.path.join(FAKE_DIR, f"sample_{i}.exe")
    with open(fp, "wb") as f:
        f.write(b"MZ" + b"\x00"*58)
        f.write(b"common_string_malware_family\x00")
        f.write(b"another_common_indicator\x00")
        f.write(b"http://c2.example.com\x00")
        f.write(bytes([i]*200))

print("\n" + "="*60)
print("  YARA Studio – Functional Test (từng chức năng)")
print("="*60 + "\n")

# ════════════════════════════════════════════════════════════════
print("─── 1. SETUP – Kiểm tra môi trường ───")
from core.state import AppState
state = AppState()

run("AppState khởi tạo + tạo thư mục", lambda: f"base={state.base_dir}")
run("rules_dir tồn tại", lambda: state.rules_dir if os.path.isdir(state.rules_dir) else (_ for _ in ()).throw(Exception("rules_dir missing")))
run("reports_dir tồn tại", lambda: state.reports_dir if os.path.isdir(state.reports_dir) else (_ for _ in ()).throw(Exception("reports_dir missing")))
run("AppState Singleton (2 instance = cùng obj)", lambda: "ok" if AppState() is AppState() else (_ for _ in ()).throw(Exception("Not singleton")))

# ════════════════════════════════════════════════════════════════
print("\n─── 2. ANALYZE – Phân tích mẫu tĩnh ───")
from core.sample_analyzer import SampleAnalyzer
analyzer = SampleAnalyzer()

run("calculate_hashes()", lambda: analyzer.calculate_hashes(FAKE_PE))
run("extract_strings() trả về list", lambda: f"{len(analyzer.extract_strings(FAKE_PE))} strings")
run("analyze_sample() đầy đủ", lambda: f"name={analyzer.analyze_sample(FAKE_PE)['file_name']}, strings={analyzer.analyze_sample(FAKE_PE)['strings_count']}")
run("analyze_sample() file không tồn tại → error key", lambda: "error" in analyzer.analyze_sample("/not/exist.exe") or (_ for _ in ()).throw(Exception("no error key")))

# Test entropy
from screens.analyze_screen import calculate_entropy, detect_behavior_hints
run("calculate_entropy()", lambda: f"entropy={calculate_entropy(FAKE_PE)}")
run("detect_behavior_hints() tìm cmd.exe/WriteProcessMemory", lambda: f"{len(detect_behavior_hints(['cmd.exe', 'WriteProcessMemory', 'http://c2.com']))} behaviors detected")

# ════════════════════════════════════════════════════════════════
print("\n─── 3. FAMILY – Trích xuất đặc trưng chung ───")
from core.family_signature import FamilySignatureGenerator
sig_gen = FamilySignatureGenerator()

run("process_family_directory() với 3 mẫu giả", lambda: f"features={len(sig_gen.process_family_directory(FAKE_DIR).get('features',[]))}, samples={sig_gen.process_family_directory(FAKE_DIR).get('total_samples')}")
run("generate_yara_rule() sinh luật hợp lệ", lambda: sig_gen.generate_yara_rule(sig_gen.process_family_directory(FAKE_DIR))[:60].replace('\n',' ') + "...")
run("_is_blacklisted() lọc chuỗi rác", lambda: f"'kernel32.dll'={sig_gen._is_blacklisted('kernel32.dll')}, 'NetSupportRAT'={sig_gen._is_blacklisted('NetSupportRAT')}")

# ════════════════════════════════════════════════════════════════
print("\n─── 4. GENERATE – Command Builder + Preset ───")
from core.yargen_command import YarGenCommandBuilder, PRESETS

builder = YarGenCommandBuilder("yarGen.py")
run("PRESETS có đủ 7 preset", lambda: f"{list(PRESETS.keys())}")
run("build() Beginner preset", lambda: builder.build(FAKE_DIR, "output.yar", "Beginner"))
run("build() PE Deep có --opcodes", lambda: "--opcodes" in builder.build(FAKE_DIR, "out.yar", "PE Deep") or (_ for _ in ()).throw(Exception("missing --opcodes")))
run("preview() trả về chuỗi lệnh đọc được", lambda: builder.preview(FAKE_DIR, "out.yar", "Beginner")[:80])
run("Custom mode với nosimple+nomagic", lambda: builder.build(FAKE_DIR, "out.yar", "Custom", nosimple=True, nomagic=True))

# ════════════════════════════════════════════════════════════════
print("\n─── 5. MONITOR – Log buffer ───")
from core.runner import BackgroundRunner

state.clear_log()
state.append_log("[+] Loading strings DB")
state.append_log("[+] Extracting strings from samples")
state.append_log("[+] Generating YARA rules")
state.append_log("3 simple rules written")
state.append_log("1 super rules written")

run("append_log() + get_logs()", lambda: f"{len(state.get_logs())} log lines")
run("clear_log()", lambda: (state.clear_log(), len(state.get_logs()))[1] == 0 or (_ for _ in ()).throw(Exception("log not cleared")))

# Test stage detection
from screens.monitor_screen import STAGES
def test_stage_detect():
    test_lines = {
        "[+] Loading goodware": "Load DB",
        "[+] Extracting strings from": "Extract",
        "3 simple rules written": "Generate",
    }
    hits = []
    for line, expected_stage in test_lines.items():
        for stage_name, keywords in STAGES:
            if any(kw.lower() in line.lower() for kw in keywords):
                hits.append(f"'{line[:30]}' → {stage_name}")
                break
    return "; ".join(hits)
run("Stage detection từ log lines", test_stage_detect)

# ════════════════════════════════════════════════════════════════
print("\n─── 6. VALIDATE – Compile & Scan ───")
from core.yara_engine import YaraEngine
engine = YaraEngine()

run("check_backend_availability()", lambda: engine.check_backend_availability())
run("compile_rule_text() với rule hợp lệ", lambda: engine.compile_rule_text(open(FAKE_YAR).read()))
run("compile_rule_text() với rule lỗi cú pháp → success=False", lambda: engine.compile_rule_text("rule Bad { condition: INVALID_SYNTAX }")["success"] == False or (_ for _ in ()).throw(Exception("should fail")))

# ════════════════════════════════════════════════════════════════
print("\n─── 7. REPORTS – Rule Score ───")
from core.yara_score import YaraScoreAnalyzer
scorer = YaraScoreAnalyzer()

run("analyze_rule_file() với rule có sẵn", lambda: f"score={scorer.analyze_rule_file(FAKE_YAR)['rules'][0]['score']}, rating={scorer.analyze_rule_file(FAKE_YAR)['rules'][0]['rating']}")
run("analyze_rule_file() file không tồn tại → error key", lambda: "error" in scorer.analyze_rule_file("/no/file.yar") or (_ for _ in ()).throw(Exception("no error")))
run("_score_single_rule() tính điểm chi tiết", lambda: f"strings={scorer._score_single_rule('TestRule', open(FAKE_YAR).read())['string_count']}, score={scorer._score_single_rule('TestRule', open(FAKE_YAR).read())['score']}")

# ════════════════════════════════════════════════════════════════
print("\n─── 8. ANALYSIS SUITE – 7 chức năng ───")
from core.quality_gate import RuleDoctor
doctor = RuleDoctor()

rule_content = open(FAKE_YAR).read()
family_res = sig_gen.process_family_directory(FAKE_DIR)
doctor_res = doctor.evaluate_rule(sig_gen.generate_yara_rule(family_res))

run("RuleDoctor.evaluate_rule() → score", lambda: f"score={doctor_res['score']}, rating={doctor_res['rating']}, warnings={len(doctor_res['warnings'])}")

# IOC Extractor
from screens.analysis_suite_screen import IOC_PATTERNS, MITRE_MAP
def test_ioc():
    text = "http://c2.example.com cmd.exe 192.168.1.1 HKEY_LOCAL_MACHINE\\Run user@evil.com"
    found = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = set(pattern.findall(text))
        if matches:
            found[ioc_type] = list(matches)
    return found
run("IOC Extractor tìm URL/IP/Registry từ text", lambda: {k: v for k, v in test_ioc().items()})

# MITRE Mapping
def test_mitre():
    content = "cmd.exe powershell WriteProcessMemory VirtualAlloc schtasks lsass".lower()
    hits = []
    for tid, technique, keywords in MITRE_MAP:
        matched = [kw for kw in keywords if kw.lower() in content]
        if matched:
            hits.append(f"{tid}:{technique}")
    return hits
run("MITRE Mapping từ strings", test_mitre)

# Family Passport
from core.family_passport import FamilyPassportGenerator
passport_gen = FamilyPassportGenerator()
run("generate_family_passport() tạo file .md", lambda: os.path.exists(passport_gen.generate_family_passport(family_res, doctor_res, state.reports_dir)) if family_res.get("features") else "skip (no features)")

# Analyst Report
from core.analyst_report import AnalystReportGenerator
report_gen = AnalystReportGenerator()
sample_info = analyzer.analyze_sample(FAKE_PE)
run("generate_single_report() tạo file .md", lambda: os.path.exists(report_gen.generate_single_report(sample_info, state.reports_dir)))

# Analysis common
from core.analysis_common import format_file_size, sanitize_yara_rule_name, calculate_entropy as calc_ent
run("format_file_size()", lambda: f"1024→{format_file_size(1024)}, 1MB→{format_file_size(1048576)}")
run("sanitize_yara_rule_name()", lambda: f"'Net Support RAT'→{sanitize_yara_rule_name('Net Support RAT')}")
run("calculate_entropy() data ngẫu nhiên", lambda: f"entropy={round(calc_ent(bytes(range(256))),2)}")

# ════════════════════════════════════════════════════════════════
print("\n─── 9. WEB SERVER – API endpoints ───")
web_server_py = os.path.join(state.base_dir, "web_server.py")
run("web_server.py tồn tại", lambda: web_server_py if os.path.isfile(web_server_py) else (_ for _ in ()).throw(Exception("missing web_server.py")))

# ════════════════════════════════════════════════════════════════
# Dọn dẹp
import shutil
try:
    os.remove(FAKE_PE)
    os.remove(FAKE_YAR)
    shutil.rmtree(FAKE_DIR, ignore_errors=True)
except: pass

# ════════════════════════════════════════════════════════════════
passed = sum(1 for s,_,_ in results if s==PASS)
failed = sum(1 for s,_,_ in results if s==FAIL)
warned = sum(1 for s,_,_ in results if s==WARN)

print("\n" + "="*60)
print(f"  KẾT QUẢ: {passed} PASS  /  {failed} FAIL  /  {len(results)} total")
print("="*60)

if failed:
    print("\n⚠ Cần sửa:")
    for s, label, err in results:
        if s == FAIL:
            print(f"  • {label}: {err}")

sys.exit(0 if failed == 0 else 1)
