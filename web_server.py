import os
import sys
import time
import json
import argparse
from flask import Flask, render_template_string, Response, request, jsonify, send_file

from core.state import AppState
from core.sample_analyzer import SampleAnalyzer
from core.family_signature import FamilySignatureGenerator
from core.yara_engine import YaraEngine
from core.runner import BackgroundRunner
from core.quality_gate import RuleDoctor

app = Flask(__name__)

state = AppState()
analyzer = SampleAnalyzer()
sig_generator = FamilySignatureGenerator()
yara_engine = YaraEngine()
runner = BackgroundRunner()
doctor = RuleDoctor()

_job_meta = {"start_time": None, "family": "", "output_yar": "", "rule_count": 0, "updates": 0, "stage": "Idle"}
_job_history = []

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>yarGen Generate Monitor – YARA Malware Analysis Studio</title>
<style>
:root{--bg:#0F172A;--card:#1E293B;--border:#334155;--text:#F8FAFC;--muted:#94A3B8;
--green:#10B981;--blue:#3B82F6;--yellow:#F59E0B;--red:#EF4444;--console:#020617;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;}
/* Nav */
nav{background:#1E293B;border-bottom:1px solid var(--border);padding:10px 24px;display:flex;align-items:center;gap:12px;}
nav .logo{font-size:15px;font-weight:700;color:var(--text);flex:1;}
nav .logo span{color:var(--green);}
nav a{padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;border:none;text-decoration:none;color:var(--muted);}
nav a:hover,nav a.active{background:var(--border);color:var(--text);}
/* Layout */
.wrap{max-width:1280px;margin:0 auto;padding:20px 24px;}
/* Status banner */
.banner{padding:12px 18px;border-radius:8px;margin-bottom:16px;font-size:14px;font-weight:600;border-left:4px solid;}
.banner.idle{background:#1E293B;border-color:var(--muted);color:var(--muted);}
.banner.running{background:#1C3B5A;border-color:var(--blue);color:#93C5FD;}
.banner.done{background:#064E3B;border-color:var(--green);color:#6EE7B7;}
.banner.error{background:#450A0A;border-color:var(--red);color:#FCA5A5;}
.banner-sub{font-size:12px;font-weight:400;margin-top:3px;opacity:.8;}
/* Stats bar */
.stats-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;}
.stat{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:8px 18px;font-size:13px;}
.stat label{color:var(--muted);font-size:11px;display:block;margin-bottom:2px;text-transform:uppercase;}
.stat span{font-weight:700;font-size:15px;}
.stat.ok span{color:var(--green);}
.stat.running span{color:var(--blue);}
/* Progress */
.prog-wrap{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px;}
.prog-bar-bg{background:#1E293B;border-radius:4px;height:10px;overflow:hidden;margin-top:8px;}
.prog-bar{height:100%;background:linear-gradient(90deg,var(--blue),var(--green));border-radius:4px;transition:width .5s;}
.prog-label{font-size:12px;color:var(--muted);margin-top:6px;text-align:right;}
/* Main grid */
.grid2{display:grid;grid-template-columns:1fr 380px;gap:16px;align-items:start;}
/* Log */
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;}
.card h3{font-size:13px;text-transform:uppercase;color:var(--muted);margin-bottom:12px;letter-spacing:.5px;}
.console{background:var(--console);border-radius:6px;padding:12px;height:280px;overflow-y:auto;
  font-family:Consolas,monospace;font-size:12.5px;line-height:1.7;color:#38BDF8;}
.console .l-ok{color:#6EE7B7;} .console .l-warn{color:var(--yellow);} .console .l-err{color:#FCA5A5;}
.console .l-info{color:#93C5FD;}
/* Rule preview */
.rule-box{background:var(--console);border-radius:6px;padding:12px;max-height:200px;overflow-y:auto;
  font-family:Consolas,monospace;font-size:11.5px;color:#C4B5FD;white-space:pre;}
/* Right panel */
.right-panel{display:flex;flex-direction:column;gap:16px;}
/* Form */
.form-group{margin-bottom:12px;}
.form-group label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px;}
.form-group input{width:100%;padding:9px 12px;background:#0F172A;border:1px solid var(--border);
  border-radius:5px;color:var(--text);font-size:13px;font-family:monospace;}
.form-group input:focus{outline:none;border-color:var(--blue);}
.btn{padding:9px 18px;border:none;border-radius:5px;font-size:13px;font-weight:600;cursor:pointer;transition:.2s;}
.btn-green{background:var(--green);color:#fff;} .btn-green:hover{background:#059669;}
.btn-red{background:var(--red);color:#fff;} .btn-red:hover{background:#DC2626;}
.btn-blue{background:var(--blue);color:#fff;} .btn-blue:hover{background:#2563EB;}
.btn-row{display:flex;gap:8px;flex-wrap:wrap;}
/* Downloads */
.dl-list{display:flex;flex-direction:column;gap:6px;}
.dl-item{display:flex;align-items:center;gap:8px;padding:8px 12px;background:#0F172A;
  border-radius:5px;border:1px solid var(--border);font-size:13px;text-decoration:none;color:var(--text);}
.dl-item:hover{border-color:var(--blue);color:var(--blue);}
.dl-icon{font-size:16px;}
/* History */
#historyPanel{display:none;}
.hist-item{padding:10px 14px;background:#0F172A;border-radius:5px;border:1px solid var(--border);margin-bottom:8px;font-size:13px;}
.hist-item .hf{font-weight:600;} .hist-item .hd{color:var(--muted);font-size:11px;margin-top:3px;}
</style>
</head>
<body>
<nav>
  <div class="logo">yarGen <span>Monitor</span> &nbsp;·&nbsp; <span style="color:var(--muted);font-size:12px;">YARA Malware Analysis Studio</span></div>
  <a href="#" class="active" onclick="showMain()">&#8962; Home</a>
  <a href="#" onclick="showHistory()">&#128337; Job History</a>
</nav>

<div class="wrap">
  <!-- Main panel -->
  <div id="mainPanel">
    <div id="banner" class="banner idle">
      <div>&#9679; Realtime monitor: <span id="bannerTitle">Chờ tác vụ...</span></div>
      <div class="banner-sub" id="bannerSub">Nhập đường dẫn thư mục mẫu và nhấn Khởi chạy.</div>
    </div>

    <div class="stats-bar">
      <div class="stat"><label>Status</label><span id="stStatus">Idle</span></div>
      <div class="stat"><label>Stage</label><span id="stStage">—</span></div>
      <div class="stat ok"><label>Rules</label><span id="stRules">0</span></div>
      <div class="stat"><label>Elapsed</label><span id="stElapsed">0s</span></div>
      <div class="stat"><label>Updates</label><span id="stUpdates">0</span></div>
    </div>

    <div class="prog-wrap">
      <div style="display:flex;justify-content:space-between;font-size:13px;">
        <span id="progText">Chờ khởi chạy...</span>
        <span id="progPct" style="color:var(--green);font-weight:700;">0%</span>
      </div>
      <div class="prog-bar-bg"><div class="prog-bar" id="progBar" style="width:0%"></div></div>
      <div class="prog-label" id="progLabel">Nhập thư mục họ mẫu bên phải và nhấn Khởi chạy.</div>
    </div>

    <div class="grid2">
      <!-- Left: Log + Rule -->
      <div style="display:flex;flex-direction:column;gap:16px;">
        <div class="card">
          <h3>&#128196; Live yarGen log <small style="font-weight:400;">(tự động scroll xuống cuối)</small></h3>
          <div id="consoleLog" class="console">--- Hệ thống sẵn sàng ---&#10;</div>
        </div>
        <div class="card" id="ruleCard" style="display:none;">
          <h3>&#9745; Generated candidate YARA rule (&#10003; Candidate đã được generate)</h3>
          <div id="rulePreview" class="rule-box"></div>
        </div>
        <div class="card" id="dlCard" style="display:none;">
          <h3>&#11015; Downloads</h3>
          <div class="dl-list" id="dlList"></div>
        </div>
      </div>

      <!-- Right: Config + Command -->
      <div class="right-panel">
        <div class="card">
          <h3>&#9881; Cấu hình tác vụ</h3>
          <div class="form-group">
            <label>Thư mục họ mẫu (Target Family Directory)</label>
            <input type="text" id="familyDir" placeholder="C:\\...\\test_samples\\NetSupport">
          </div>
          <div class="form-group">
            <label>Tên file output (.yar)</label>
            <input type="text" id="outputName" placeholder="output_rules.yar">
          </div>
          <div class="btn-row">
            <button class="btn btn-green" onclick="startJob()">&#9654; Khởi Chạy yarGen Ngầm</button>
            <button class="btn btn-red" onclick="stopJob()">&#9632; Dừng</button>
          </div>
        </div>

        <div class="card">
          <h3>&#128196; Command</h3>
          <div id="cmdPreview" style="background:#020617;border-radius:5px;padding:10px;
            font-family:Consolas,monospace;font-size:11.5px;color:#93C5FD;word-break:break-all;min-height:50px;">
            —
          </div>
          <button class="btn btn-blue" style="margin-top:8px;width:100%;" onclick="copyCmd()">&#128203; Copy Command</button>
        </div>
      </div>
    </div>
  </div>

  <!-- History panel -->
  <div id="historyPanel">
    <div class="card">
      <h3>&#128337; Job History</h3>
      <div id="histList" style="margin-top:8px;"></div>
    </div>
  </div>
</div>

<script>
let sse=null, elapsedTimer=null, startTs=null, updates=0;
const STAGES=["Idle","Preflight","Load DB","Extract","Generate","Validate","Done"];
const PROG={Idle:0,Preflight:10,"Load DB":30,Extract:55,Generate:80,Validate:92,Done:100};

function showMain(){document.getElementById('mainPanel').style.display='';document.getElementById('historyPanel').style.display='none';}
function showHistory(){
  document.getElementById('mainPanel').style.display='none';
  document.getElementById('historyPanel').style.display='';
  loadHistory();
}

function loadHistory(){
  fetch('/api/history').then(r=>r.json()).then(d=>{
    const el=document.getElementById('histList');
    if(!d.length){el.innerHTML='<p style="color:var(--muted);font-size:13px;">Chưa có job nào.</p>';return;}
    el.innerHTML=d.map(j=>`<div class="hist-item">
      <div class="hf">&#128196; ${j.family} &nbsp; <span style="color:var(--green)">${j.rules} rules</span></div>
      <div class="hd">${j.time} &nbsp;·&nbsp; ${j.elapsed}s &nbsp;·&nbsp; ${j.output}</div>
    </div>`).reverse().join('');
  });
}

function startJob(){
  const dir=document.getElementById('familyDir').value.trim();
  const out=document.getElementById('outputName').value.trim()||'web_output.yar';
  if(!dir){alert('Vui lòng nhập đường dẫn thư mục họ mẫu!');return;}
  log('cls');
  setBanner('running','Đang khởi chạy...','Gửi lệnh tới server...');
  fetch('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({directory:dir,output:out})})
  .then(r=>r.json()).then(d=>{
    if(d.success){
      document.getElementById('cmdPreview').textContent=d.command||'—';
      startElapsed();
      connectSSE();
    } else {alert('Lỗi: '+d.error);}
  }).catch(e=>alert('Lỗi kết nối: '+e));
}

function stopJob(){
  fetch('/api/abort',{method:'POST'}).then(r=>r.json()).then(d=>{
    log('[ABORT] '+d.message);
    setBanner('error','Đã dừng','Tác vụ bị ngắt bởi người dùng.');
    stopElapsed();
    if(sse){sse.close();}
  });
}

function connectSSE(){
  if(sse)sse.close();
  updates=0;
  sse=new EventSource('/events/stream');
  sse.onmessage=function(e){
    updates++;
    document.getElementById('stUpdates').textContent=updates;
    const line=e.data;
    log(line);
    updateStageFromLine(line);
    if(line.includes('---') && line.includes('kết thúc')){
      sse.close(); stopElapsed();
      fetchRuleAndFinish();
    }
  };
  sse.onerror=function(){sse.close(); stopElapsed();};
}

function updateStageFromLine(line){
  const l=line.toLowerCase();
  let stage='';
  if(l.includes('preflight')||l.includes('kiểm tra'))stage='Preflight';
  else if(l.includes('loading')||l.includes('goodware')||l.includes('load db'))stage='Load DB';
  else if(l.includes('extract')||l.includes('string'))stage='Extract';
  else if(l.includes('generat')||l.includes('rule'))stage='Generate';
  else if(l.includes('validat')||l.includes('compil'))stage='Validate';
  else if(l.includes('done')||l.includes('written')||l.includes('finish'))stage='Done';
  if(stage){
    document.getElementById('stStage').textContent=stage;
    document.getElementById('stStatus').textContent=stage==='Done'?'done':'running';
    const pct=PROG[stage]||0;
    document.getElementById('progBar').style.width=pct+'%';
    document.getElementById('progPct').textContent=pct+'%';
    document.getElementById('progText').textContent=stage==='Done'?'Rule generated, validation report exported, downloads ready.':('Stage: '+stage);
    if(stage==='Done')setBanner('done','Job đã hoàn tất','Job đã chạy xong. Xem kết quả bên dưới.');
  }
  // Count rules
  const m=line.match(/(\d+)\s*(simple|super)\s*rule/i);
  if(m){const cur=parseInt(document.getElementById('stRules').textContent)||0;
    document.getElementById('stRules').textContent=cur+parseInt(m[1]);}
}

function fetchRuleAndFinish(){
  fetch('/api/rule_preview').then(r=>r.json()).then(d=>{
    if(d.content){
      document.getElementById('ruleCard').style.display='';
      document.getElementById('rulePreview').textContent=d.content;
    }
    if(d.files && d.files.length){
      const dlCard=document.getElementById('dlCard');
      dlCard.style.display='';
      document.getElementById('dlList').innerHTML=d.files.map(f=>
        `<a class="dl-item" href="/api/download?file=${encodeURIComponent(f.path)}">
          <span class="dl-icon">&#128196;</span> ${f.name}
         </a>`).join('');
    }
    document.getElementById('progBar').style.width='100%';
    document.getElementById('progPct').textContent='100%';
    document.getElementById('progText').textContent='100% — Rule generated, validation report exported, downloads ready.';
    setBanner('done','Job đã hoàn tất','Job đã chạy xong. Xem kết quả bên dưới.');
  });
}

function log(msg){
  if(msg==='cls'){document.getElementById('consoleLog').innerHTML='';return;}
  const el=document.getElementById('consoleLog');
  const div=document.createElement('div');
  const l=msg.toLowerCase();
  if(l.includes('[+]')||l.includes('success')||l.includes('written'))div.className='l-ok';
  else if(l.includes('warn')||l.includes('[!]'))div.className='l-warn';
  else if(l.includes('error')||l.includes('[e]'))div.className='l-err';
  else if(l.includes('[*]')||l.includes('info'))div.className='l-info';
  div.textContent=msg;
  el.appendChild(div);
  el.scrollTop=el.scrollHeight;
}

function setBanner(type,title,sub){
  const b=document.getElementById('banner');
  b.className='banner '+type;
  document.getElementById('bannerTitle').textContent=title;
  document.getElementById('bannerSub').textContent=sub;
}

function startElapsed(){
  startTs=Date.now(); stopElapsed();
  elapsedTimer=setInterval(()=>{
    const s=Math.round((Date.now()-startTs)/1000);
    document.getElementById('stElapsed').textContent=s+'s';
  },1000);
}
function stopElapsed(){if(elapsedTimer){clearInterval(elapsedTimer);elapsedTimer=null;}}

function copyCmd(){
  const t=document.getElementById('cmdPreview').textContent;
  navigator.clipboard.writeText(t).then(()=>alert('Đã copy command!'));
}

// Poll status every 2s
setInterval(()=>{
  fetch('/api/status').then(r=>r.json()).then(d=>{
    if(!d.running && document.getElementById('stStatus').textContent==='running'){
      document.getElementById('stStatus').textContent='done';
    }
  });
},2000);
</script>
</body>
</html>"""


@app.route('/')
def index_dashboard():
    return render_template_string(HTML_DASHBOARD)


@app.route('/api/generate', methods=['POST'])
def api_generate():
    req = request.get_json() or {}
    target_dir = req.get("directory", "").strip()
    output_name = req.get("output", "web_output.yar").strip()

    if not target_dir or not os.path.exists(target_dir):
        return jsonify({"success": False, "error": "Đường dẫn không hợp lệ."})

    state.selected_family_dir = target_dir
    family_name = os.path.basename(target_dir.rstrip("/\\"))
    output_path = os.path.join(state.rules_dir, output_name if output_name.endswith('.yar') else output_name + '.yar')

    _job_meta["start_time"] = time.time()
    _job_meta["family"] = family_name
    _job_meta["output_yar"] = output_path
    _job_meta["rule_count"] = 0
    _job_meta["updates"] = 0
    _job_meta["stage"] = "Preflight"

    cmd = [
        sys.executable,
        os.path.join(state.base_dir, "yarGen.py"),
        "-m", target_dir,
        "-o", output_path,
        "--excludegood",
        "--nosimple", "--nomagic"
    ]

    success = runner.start_task(cmd, cwd=state.base_dir)
    if success:
        return jsonify({"success": True, "command": " ".join(cmd)})
    else:
        return jsonify({"success": False, "error": "Runner bận hoặc lỗi cấu hình."})


@app.route('/api/abort', methods=['POST'])
def api_abort():
    runner.terminate_current_task()
    return jsonify({"success": True, "message": "Đã gửi lệnh ngắt tiến trình."})


@app.route('/api/status')
def api_status():
    return jsonify({"running": runner.is_running(), "stage": _job_meta.get("stage", "Idle")})


@app.route('/api/rule_preview')
def api_rule_preview():
    yar_path = _job_meta.get("output_yar", "")
    content = ""
    if yar_path and os.path.exists(yar_path):
        try:
            with open(yar_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(8000)
        except Exception:
            pass

    files = []
    rules_dir = state.rules_dir
    reports_dir = state.reports_dir
    for d, exts in [(rules_dir, [".yar"]), (reports_dir, [".md", ".csv"])]:
        if os.path.isdir(d):
            for fname in sorted(os.listdir(d), key=lambda x: os.path.getmtime(os.path.join(d, x)), reverse=True)[:4]:
                if any(fname.endswith(e) for e in exts):
                    files.append({"name": fname, "path": os.path.join(d, fname)})

    return jsonify({"content": content, "files": files})


@app.route('/api/download')
def api_download():
    fpath = request.args.get("file", "")
    base = os.path.abspath(state.base_dir)
    fpath = os.path.abspath(fpath)
    if not fpath.startswith(base):
        return jsonify({"error": "Forbidden"}), 403
    if not os.path.isfile(fpath):
        return jsonify({"error": "File not found"}), 404
    return send_file(fpath, as_attachment=True)


@app.route('/api/history')
def api_history():
    return jsonify(_job_history)


@app.route('/events/stream')
def event_stream():
    def gen():
        last = 0
        state.append_log("[INFO] SSE stream connected.")
        while True:
            logs = state.get_logs()
            if len(logs) > last:
                for line in logs[last:]:
                    yield f"data: {line}\n\n"
                last = len(logs)
            if not runner.is_running() and last == len(logs):
                elapsed = round(time.time() - (_job_meta.get("start_time") or time.time()), 1)
                _job_history.append({
                    "family": _job_meta.get("family", "—"),
                    "rules": _job_meta.get("rule_count", 0),
                    "elapsed": elapsed,
                    "output": os.path.basename(_job_meta.get("output_yar", "")),
                    "time": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                yield "data: --- Tác vụ ngầm kết thúc. Ngắt luồng stream log SSE tự động. ---\n\n"
                break
            time.sleep(0.4)
    return Response(gen(), mimetype='text/event-stream')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8088)
    args = parser.parse_args()
    print(f"[*] Web server: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
