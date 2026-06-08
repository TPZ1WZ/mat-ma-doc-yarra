import os
import sys
import math

sys.path.insert(0, os.path.dirname(__file__))

from core.sample_analyzer import SampleAnalyzer

BEHAVIOR_HINTS = [
    ("Network",           ["http", "https", "socket", "connect", "recv", "send", "wget", "curl", "urldownloadtofile", "internetopen", "wininet"]),
    ("Persistence",       ["runonce", "currentversion\\run", "schtasks", "startup", "autorun", "regsetvalueex"]),
    ("Process Injection", ["writeprocessmemory", "createremotethread", "virtualalloc", "mapviewoffile"]),
    ("Credential Access", ["lsass", "mimikatz", "sekurlsa", "wdigest", "sam\\", "ntds.dit"]),
    ("Shell Execution",   ["cmd.exe", "powershell", "wscript", "cscript", "mshta", "regsvr32", "rundll32"]),
    ("File Operations",   ["createfile", "writefile", "deletefile", "copyfile", "movefile"]),
    ("Anti-Analysis",     ["isdebuggerpresent", "checkremotedebuggerpresent", "vmware", "virtualbox", "sandbox"]),
]

def calc_entropy(path):
    with open(path, "rb") as f:
        data = f.read(1024 * 1024)
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    e = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            e -= p * math.log2(p)
    return round(e, 3)

def detect_behaviors(strings):
    text = " ".join(s.lower() for s in strings)
    hits = []
    for cat, keywords in BEHAVIOR_HINTS:
        matched = [kw for kw in keywords if kw in text]
        if matched:
            hits.append((cat, matched))
    return hits

MA_DOC = r"C:\Users\shinc\Downloads\PTMD_TAN\ma-doc"
analyzer = SampleAnalyzer()

# Thu thap tat ca file mau (bo qua thu muc con va .zip)
samples = []
for root, dirs, files in os.walk(MA_DOC):
    for f in files:
        if f.endswith(".zip"):
            continue
        fp = os.path.join(root, f)
        samples.append(fp)

print(f"\n{'='*70}")
print(f"  BATCH ANALYSIS - {len(samples)} samples")
print(f"{'='*70}\n")

for fp in samples:
    name = os.path.basename(fp)
    size = os.path.getsize(fp)
    print(f"FILE: {name[:60]}")
    print(f"  Size    : {size/1024/1024:.2f} MB")

    entropy = calc_entropy(fp)
    print(f"  Entropy : {entropy}  {'[PACKED/ENCRYPTED?]' if entropy > 7.0 else ''}")

    hashes = analyzer.calculate_hashes(fp)
    print(f"  MD5     : {hashes['md5']}")
    print(f"  SHA256  : {hashes['sha256']}")

    strings = analyzer.extract_strings(fp)
    print(f"  Strings : {len(strings)} found")

    behaviors = detect_behaviors(strings)
    if behaviors:
        print(f"  Behaviors detected ({len(behaviors)}):")
        for cat, kws in behaviors:
            print(f"    [{cat}] {', '.join(kws[:5])}")
    else:
        print(f"  Behaviors: none detected")

    pe = analyzer.analyze_pe_structure(fp)
    if pe.get("is_pe"):
        imports = pe.get("imports", {})
        print(f"  PE Type : {pe.get('machine', 'unknown')} | Sections: {len(pe.get('sections', []))}")
        print(f"  Imports : {len(imports)} DLLs")

    risk = len(behaviors) + (2 if entropy > 7.0 else 1 if entropy > 6.5 else 0)
    level = "CRITICAL" if risk >= 5 else "HIGH" if risk >= 3 else "MEDIUM" if risk >= 1 else "LOW"
    print(f"  Risk    : {level} (score={risk})")
    print()
