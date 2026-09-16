"""Local web GUI: Yettel brand colours in a Nostromo / MU-TH-UR terminal style.

Runs an HTTP server on 127.0.0.1 only. Every API call must carry the random
session token embedded in the page, so other sites cannot drive it.
"""
import json
import os
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List

from . import __version__
from .report import Finding, worst

TOKEN = secrets.token_urlsafe(24)

LOGO_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="205 203 967 274" class="logo"><g fill="currentColor">'
            '<path d="M443.26,214c-23.29,56.2-54,113.14-90.95,169v89.85H295.74V382.92c-36.61-55.83-67.29-112.77-90.22-169h64c12.2,35.5,30.32,71.73,54.72,107.23,24-35.5,42.89-71.73,55.46-107.23Z"/>'
            '<path d="M581.42,393.64H453.87c4.8,21.82,21.44,36.24,43.26,36.24,15.89,0,28.1-5.92,40.3-19.23l36.6,28.1c-17.38,27-47.33,38.45-79.12,38.45-51.76,0-96.13-33.64-96.13-98,0-55.82,37.71-95.76,91.69-95.76C554.43,283.46,588.82,333,581.42,393.64ZM453.87,359.26h73.57C526,341.51,513,327.09,491.21,327.09,470.14,327.09,457.2,340.4,453.87,359.26Z"/>'
            '<path d="M724.1,461.3c-12.57,8.51-34,15.9-54.72,15.9-39.56,0-64.7-22.55-64.7-63.59V251.3l54.72-10.72V287.9h49.54v46.59H659.4v70.25c0,14.79,7.76,22.18,22.18,22.18,8.5,0,17.38-3.7,25.88-8.87Z"/>'
            '<path d="M853.8,461.3c-12.57,8.51-34,15.9-54.72,15.9-39.56,0-64.7-22.55-64.7-63.59V251.3l54.72-10.72V287.9h49.54v46.59H789.1v70.25c0,14.79,7.76,22.18,22.18,22.18,8.51,0,17.38-3.7,25.88-8.87Z"/>'
            '<path d="M1037.63,393.64H910.07c4.81,21.82,21.45,36.24,43.26,36.24,15.9,0,28.1-5.92,40.3-19.23l36.6,28.1c-17.37,27-47.32,38.45-79.12,38.45-51.76,0-96.13-33.64-96.13-98,0-55.82,37.71-95.76,91.7-95.76C1010.64,283.46,1045,333,1037.63,393.64ZM910.07,359.26h73.58c-1.48-17.75-14.42-32.17-36.24-32.17C926.34,327.09,913.4,340.4,910.07,359.26Z"/>'
            '<path d="M1060.88,472.77V214l54.72-10.72V472.77Z"/>'
            '<path d="M1137.86,443.56c0-18.49,15.53-34,33.65-34a34.4,34.4,0,0,1,34,34c0,18.11-15.52,33.64-34,33.64C1153.39,477.2,1137.86,461.67,1137.86,443.56Z"/></g></svg>')

HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PQCHECK</title>
<style>
:root{--navy:#002340;--navy2:#001a30;--lime:#B4FF00;--ice:#C4DFE9;--grey:#99A7B3;--llime:#E1FF99;--pale:#E7F2F6;
 --amber:#E6A11E;--red:#FF5C5C;--mono:"Menlo","Consolas","DejaVu Sans Mono","Courier New",monospace}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--navy2);color:var(--lime);font-family:var(--mono);font-size:14px;line-height:1.45;
 text-transform:uppercase;letter-spacing:.04em;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:9;
 background:repeating-linear-gradient(0deg,rgba(0,0,0,.22) 0 1px,transparent 1px 3px)}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:8;
 background:radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,.55) 100%)}
.crt{min-height:100%;padding:18px 16px 40px;max-width:1180px;margin:0 auto;animation:flick 6s infinite}
@keyframes flick{0%,97%,100%{opacity:1}98%{opacity:.93}}
.bar{display:flex;justify-content:space-between;align-items:center;border:2px solid var(--lime);padding:8px 14px;
 box-shadow:0 0 12px rgba(180,255,0,.25),inset 0 0 12px rgba(180,255,0,.08)}
.bar .left{display:flex;align-items:center;gap:18px}
.logo{height:22px;color:var(--lime);display:block}
.sys{color:var(--ice);font-size:12px}
.cls{color:var(--ice);font-size:11px;border:1px solid var(--grey);padding:2px 8px}
h1{margin:22px 0 4px;font-size:22px;font-weight:normal;text-shadow:0 0 8px rgba(180,255,0,.6)}
h1 small{color:var(--ice);font-size:13px;margin-left:12px}
.sub{color:var(--grey);font-size:12px;margin-bottom:18px}
.panel{border:1px solid var(--lime);border-left-width:6px;padding:14px;margin-bottom:16px;background:rgba(0,35,64,.6)}
.panel h2{margin:0 0 10px;font-size:13px;color:var(--ice);font-weight:normal}
.panel h2::before{content:"■ ";color:var(--lime)}
.row{display:flex;gap:10px;flex-wrap:wrap}
select,input[type=text]{background:var(--navy);color:var(--lime);border:1px solid var(--lime);padding:9px 12px;
 font:inherit;text-transform:none;letter-spacing:0;outline:none;flex:1;min-width:200px}
select{flex:0 0 200px;text-transform:uppercase}
input::placeholder{color:var(--grey)}
input:focus,select:focus{box-shadow:0 0 0 2px var(--navy),0 0 0 3px var(--lime)}
button{background:var(--lime);color:var(--navy);border:0;padding:9px 22px;font:inherit;font-weight:bold;cursor:pointer;
 text-transform:uppercase}
button:hover{background:var(--llime)}
button:disabled{background:var(--grey);cursor:wait}
.ghost,a.btn{background:transparent;color:var(--lime);border:1px solid var(--lime);padding:6px 14px;font:inherit;text-transform:uppercase;text-decoration:none;font-size:12px;cursor:pointer}
.ghost:hover,a.btn:hover{background:rgba(180,255,0,.12)}
tr.click{cursor:pointer}tr.click:hover td{background:rgba(180,255,0,.06)}
.info{width:30px;height:30px;padding:0;border-radius:50%;font-weight:bold;font-family:Georgia,serif;text-transform:none;font-size:16px}
.modal{position:fixed;inset:0;background:rgba(0,10,20,.8);z-index:20;display:flex;align-items:center;justify-content:center;padding:16px}
.modal[hidden]{display:none}
.modal-box{background:var(--navy);border:2px solid var(--lime);box-shadow:0 0 24px rgba(180,255,0,.3);max-width:860px;width:100%;max-height:90vh;overflow:auto}
.modal-head{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--lime);color:var(--ice)}
.modal-body{padding:14px;text-transform:none;letter-spacing:0;font-size:13px;color:var(--pale)}
.modal-body p{margin:8px 0}.modal-body code{color:var(--lime)}.modal-body b{color:var(--lime)}
.modal-body pre{background:var(--navy2);border:1px solid var(--grey);padding:10px;color:var(--ice);overflow:auto}
table.rules td,table.rules th{font-size:12px;text-transform:none;letter-spacing:0}
.rows-ok{color:var(--lime)}.rows-err{color:var(--amber)}
.drop{margin-top:10px;border:1px dashed var(--grey);padding:14px;text-align:center;color:var(--grey);font-size:12px;cursor:pointer}
.drop.over{border-color:var(--lime);color:var(--lime);background:rgba(180,255,0,.06)}
.hint{color:var(--grey);font-size:11px;margin-top:8px}
#log{white-space:pre-wrap;min-height:60px;color:var(--ice)}
.cursor::after{content:"█";animation:blink 1s steps(1) infinite;margin-left:2px}
@keyframes blink{50%{opacity:0}}
.target{margin-top:14px;border-top:1px solid var(--grey);padding-top:10px}
.target .head{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;font-size:13px}
.target .head .name{color:var(--pale);text-transform:none;letter-spacing:0;word-break:break-all}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}
td,th{padding:5px 8px;text-align:left;vertical-align:top;border-bottom:1px solid rgba(153,167,179,.25)}
th{color:var(--ice);font-weight:normal;border-bottom:1px solid var(--grey)}
td.loc,td.note{text-transform:none;letter-spacing:0;color:var(--grey)}
td.alg{color:var(--pale);white-space:nowrap}
.v{display:inline-block;padding:1px 8px;border:1px solid;white-space:nowrap}
.v-QUANTUM_VULNERABLE{color:var(--red);border-color:var(--red);animation:alert 1.2s steps(1) infinite}
@keyframes alert{50%{background:rgba(255,92,92,.18)}}
.v-WEAK{color:var(--amber);border-color:var(--amber)}
.v-QUANTUM_SAFE,.v-HYBRID_PQC{color:var(--lime);border-color:var(--lime)}
.v-UNKNOWN{color:var(--ice);border-color:var(--ice)}
.v-INFO{color:var(--grey);border-color:var(--grey)}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:10px}
.tile{border:1px solid var(--grey);padding:10px;text-align:center}
.tile b{display:block;font-size:26px;font-weight:normal}
.tile span{font-size:11px;color:var(--grey)}
.foot{margin-top:30px;height:8px;background:var(--lime)}
.footnote{color:var(--grey);font-size:11px;margin-top:8px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
a{color:var(--ice)}
@media (max-width:600px){.bar{flex-direction:column;align-items:flex-start;gap:8px}select{flex:1 1 100%}}
</style></head>
<body><div class="crt">
<div class="bar">
  <div class="left">__LOGO__<span class="sys">PQCHECK // CRYPTO INVENTORY // v__VERSION__</span></div>
  <span class="cls">Company Internal</span>
</div>
<h1>Quantum-readiness inventory<small>Interface 2037 · Ready for inquiry</small></h1>
<div class="sub">Cryptographic algorithms in files, directories, websites, TLS and SSH endpoints · graded against NIST IR 8547</div>

<div class="panel">
  <h2>Request</h2>
  <form class="row" id="form" onsubmit="return false">
    <select id="cmd">
      <option value="file">FILE · file(s)</option>
      <option value="scan">SCAN · directory</option>
      <option value="tls">TLS · host[:port]</option>
      <option value="ssh">SSH · host[:port]</option>
      <option value="web">WEB · https://url</option>
    </select>
    <input id="target" type="text" placeholder="/path/to/file.pem   or   example.com   or   https://www.example.com   (no port = well-known ports are tried)" autofocus>
    <button id="run" type="submit">Run</button>
  </form>
  <div class="drop" id="drop">Or drop encrypted files here (they never leave this machine)</div>
  <div class="row" style="margin-top:10px;align-items:center">
    <button id="import" class="ghost" type="button">Import target list (CSV / XLSX)</button>
    <button id="import-info" class="ghost info" type="button" title="File rules">i</button>
    <a id="tpl" class="ghost btn" href="/template.csv" download="pqcheck-targets.csv">Download template</a>
    <span class="hint" id="import-status" style="margin:0"></span>
  </div>
  <input type="file" id="import-file" accept=".csv,.tsv,.txt,.xlsx" style="display:none">
  <div class="hint">Server listens on 127.0.0.1 only. For TLS/SSH the key exchange is the "harvest now, decrypt later" exposure; certificate / host-key signatures only matter at connection time.</div>
</div>

<div class="panel">
  <h2>Response</h2>
  <div id="log" class="cursor">MOTHER: WAITING FOR INPUT</div>
  <div id="summary"></div>
  <div id="out"></div>
</div>
<div class="panel">
  <h2>History <span class="hint" style="margin:0 0 0 10px">every run is saved to: <span id="dbpath" style="text-transform:none;letter-spacing:0"></span></span></h2>
  <div class="row" style="margin-bottom:8px">
    <button id="hist-runs" class="ghost">Runs</button>
    <button id="hist-inv" class="ghost">Inventory by target</button>
    <a id="exp-csv" class="ghost btn" href="#" download="pqcheck-history.csv">Export CSV</a>
    <a id="exp-json" class="ghost btn" href="#" download="pqcheck-history.json">Export JSON</a>
  </div>
  <div id="hist"></div>
</div>
<div class="modal" id="modal" hidden>
  <div class="modal-box">
    <div class="modal-head"><span>■ Target list file rules</span><button class="ghost" id="modal-close" type="button">Close</button></div>
    <div class="modal-body">
      <p><b>Formats:</b> CSV (comma, semicolon or tab separated), TXT (one target per line) or Excel <b>.xlsx</b> (first sheet). UTF-8. Lines starting with <code>#</code> are comments. Duplicates are dropped.</p>
      <p><b>Columns</b> (header row optional, any order, case-insensitive):</p>
      <table class="rules">
        <tr><th>Column</th><th>Accepted names</th><th>Values</th></tr>
        <tr><td>Purpose of the check</td><td><code>kind</code>, <code>type</code>, <code>check</code>, <code>purpose</code></td><td><code>tls</code> – TLS endpoint (key exchange, certificate) · <code>ssh</code> – SSH server · <code>web</code> – whole website (TLS versions, forward secrecy, chain, HSTS, third parties) · <code>file</code> / <code>scan</code> – local path. <b>Empty = auto-detect</b>: URL → web, port 22 → ssh, otherwise tls.</td></tr>
        <tr><td>IP or domain</td><td><code>host</code>, <code>target</code>, <code>ip</code>, <code>domain</code>, <code>address</code>, <code>url</code></td><td>Host name (<code>mail.example.com</code>), IPv4 (<code>10.0.0.12</code>), full URL for web checks (<code>https://portal.example.com</code>). <code>host:port</code> in one cell is also accepted.</td></tr>
        <tr><td>Port</td><td><code>port</code></td><td>1–65535, optional. <b>Empty = well-known ports are tried</b>: TLS 443, 8443, 465, 993, 995, 636, 4443, 9443 · SSH 22, 2222, 2200, 22222 · web 443, 8443.</td></tr>
        <tr><td>Note</td><td><code>note</code>, <code>comment</code></td><td>Free text, kept in the report.</td></tr>
      </table>
      <p><b>Without a header row:</b> 1 column = target · 2 columns = <code>target,port</code> or <code>kind,target</code> · 3 columns = <code>kind,target,port</code>.</p>
      <pre>kind,host,port,note
tls,www.example.com,,public website endpoint
tls,mail.example.com,465,SMTP submission
ssh,bastion.example.com,22,jump host
web,https://portal.example.com,,full website check
tls,10.0.0.12,8443,appliance management UI
,intranet.example.com,,auto-detected</pre>
      <p>Every row becomes one probe; the whole list is stored as a single <b>batch</b> run in History. Invalid rows are listed with their line number and skipped. Large lists take a few seconds per host.</p>
    </div>
  </div>
</div>
<div class="foot"></div>
<div class="footnote"><span>Yettel · Security</span><span>pqcheck __VERSION__ · <a href="https://github.com/krisztianhari-wq/pqcheck">github.com/krisztianhari-wq/pqcheck</a></span></div>
</div>
<script>
const TOKEN="__TOKEN__";
const log=document.getElementById('log'),out=document.getElementById('out'),sum=document.getElementById('summary');
const cmd=document.getElementById('cmd'),target=document.getElementById('target'),run=document.getElementById('run'),drop=document.getElementById('drop');
const ORDER=["QUANTUM_VULNERABLE","WEAK","UNKNOWN","INFO","HYBRID_PQC","QUANTUM_SAFE"];
let typer=null;function type(text){if(typer)clearInterval(typer);log.textContent="";let i=0;typer=setInterval(()=>{log.textContent+=text[i++]||"";if(i>=text.length){clearInterval(typer);typer=null}},8)}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function render(data){
  out.innerHTML="";const counts={};
  const by={};for(const f of data.findings){(by[f.target]=by[f.target]||[]).push(f);counts[f.verdict]=(counts[f.verdict]||0)+1}
  sum.innerHTML='<div class="summary">'+ORDER.filter(v=>counts[v]).map(v=>`<div class="tile"><b class="v-${v}" style="border:0;animation:none">${counts[v]}</b><span>${v.replace('_',' ')}</span></div>`).join('')+'</div>';
  for(const [t,items] of Object.entries(by)){
    const head=items.find(f=>f.location==="headline");
    const rows=items.filter(f=>f.location!=="headline");
    const w=head?head.note:worstOf(rows);
    const div=document.createElement('div');div.className='target';
    div.innerHTML=`<div class="head"><span class="name">&gt; ${esc(t)}</span><span class="v v-${esc(worstOf(rows))}">${esc(w)}</span></div>
    <table><tr><th>Verdict</th><th>Algorithm</th><th>Category</th><th>Where</th><th>Note</th></tr>`+
    rows.map(f=>`<tr><td><span class="v v-${esc(f.verdict)}">${esc(f.verdict)}</span></td><td class="alg">${esc(f.algorithm)}${f.bits?'-'+f.bits:''}</td><td>${esc(f.category)}</td><td class="loc">${esc(f.location)}</td><td class="note">${esc(f.note||'')}</td></tr>`).join('')+'</table>';
    out.appendChild(div);
  }
  type(`MOTHER: ${data.findings.length} FINDINGS · OVERALL ${data.overall||'NOTHING GRADED'}`);
}
function worstOf(rows){const g=rows.filter(f=>f.verdict!=="INFO").map(f=>ORDER.indexOf(f.verdict));return g.length?ORDER[Math.min(...g)]:"INFO"}
async function call(path,body,headers){
  run.disabled=true;type("MOTHER: PROCESSING REQUEST ...");out.innerHTML="";sum.innerHTML="";
  try{const r=await fetch(path,{method:'POST',headers:Object.assign({'X-Token':TOKEN},headers||{}),body});
    if(!r.ok){type("MOTHER: ERROR "+r.status+" · "+(await r.text()));return}
    render(await r.json());showRuns();
  }catch(e){type("MOTHER: UNABLE TO COMPLY · "+e)}finally{run.disabled=false}
}
run.onclick=()=>{if(run.disabled)return;const t=target.value.trim();if(!t){type("MOTHER: SPECIFY TARGET");return}
  call('/api/run',JSON.stringify({cmd:cmd.value,targets:t.split(/\s+/)}),{'Content-Type':'application/json'})};
document.getElementById('form').addEventListener('submit',e=>{e.preventDefault();run.onclick()});
target.addEventListener('input',()=>{const t=target.value.trim();if(!t)return;
  if(/^https?:\/\//i.test(t)){cmd.value='web'}else if(/^[\w.-]+\.[a-z]{2,}(:\d+)?(\s|$)/i.test(t)&&!/[\/\\]/.test(t)&&['file','scan'].includes(cmd.value)){cmd.value=/:22\b/.test(t)?'ssh':'tls'}});
target.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();run.onclick()}});
['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over')}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over')}));
drop.addEventListener('drop',async e=>{
  const files=[...e.dataTransfer.files];if(!files.length)return;
  const all=[];run.disabled=true;type("MOTHER: RECEIVING "+files.length+" FILE(S) ...");
  for(const f of files){const r=await fetch('/api/upload',{method:'POST',headers:{'X-Token':TOKEN,'X-Filename':encodeURIComponent(f.name)},body:await f.arrayBuffer()});
    if(r.ok){all.push(...(await r.json()).findings)}}
  run.disabled=false;render({findings:all,overall:worstOf(all)});showRuns();
});
async function api(path,body){const r=await fetch(path,{method:'POST',headers:{'X-Token':TOKEN,'Content-Type':'application/json'},body:JSON.stringify(body||{})});if(!r.ok)throw new Error(r.status+' '+await r.text());return r.json()}
function histTable(rows,cols,onclick){const h=document.getElementById('hist');
  h.innerHTML='<table><tr>'+cols.map(c=>'<th>'+esc(c[0])+'</th>').join('')+'</tr>'+rows.map(r=>'<tr class="click" data-id="'+esc(r.id||r.run_id)+'">'+cols.map(c=>'<td class="'+(c[2]||'')+'">'+(c[1](r))+'</td>').join('')+'</tr>').join('')+'</table>';
  h.querySelectorAll('tr.click').forEach(tr=>tr.onclick=()=>onclick(+tr.dataset.id))}
const V=v=>v?`<span class="v v-${esc(v)}" style="animation:none">${esc(v)}</span>`:'—';
async function showRuns(){try{const rows=await api('/api/history',{limit:40});
  histTable(rows,[['ID',r=>r.id],['Time',r=>esc(r.ts.replace('T',' ')),'loc'],['Command',r=>esc(r.command)],['Verdict',r=>V(r.overall)],['Vuln',r=>r.n_vulnerable],['Weak',r=>r.n_weak],['Targets',r=>esc(r.targets.join(' ')),'loc']],loadRun)}catch(e){type('MOTHER: '+e)}}
async function showInv(){try{const rows=await api('/api/inventory',{});
  histTable(rows,[['Target',r=>esc(r.target),'loc'],['Latest verdict',r=>V(r.overall)],['Last run',r=>esc(r.ts.replace('T',' ')),'loc'],['Run',r=>r.run_id],['Findings',r=>r.n_findings]],loadRun)}catch(e){type('MOTHER: '+e)}}
async function loadRun(id){try{const d=await api('/api/run_get',{id});render(d);type(`MOTHER: RUN ${id} RECALLED FROM ARCHIVE · ${d.findings.length} FINDINGS`);window.scrollTo({top:document.querySelector('#log').offsetTop-80,behavior:'smooth'})}catch(e){type('MOTHER: '+e)}}
document.getElementById('hist-runs').onclick=showRuns;document.getElementById('hist-inv').onclick=showInv;
async function exportAs(fmt,a){const r=await fetch('/api/export?format='+fmt,{method:'POST',headers:{'X-Token':TOKEN},body:'{}'});const b=await r.blob();a.href=URL.createObjectURL(b);}
document.getElementById('exp-csv').addEventListener('click',async function(e){if(this.dataset.ready){this.dataset.ready='';return}e.preventDefault();await exportAs('csv',this);this.dataset.ready='1';this.click()});
document.getElementById('exp-json').addEventListener('click',async function(e){if(this.dataset.ready){this.dataset.ready='';return}e.preventDefault();await exportAs('json',this);this.dataset.ready='1';this.click()});
api('/api/history',{limit:0}).then(()=>{}).catch(()=>{});document.getElementById('dbpath').textContent="__DBPATH__";showRuns();
const modal=document.getElementById('modal');
document.getElementById('import-info').onclick=()=>{modal.hidden=false};
document.getElementById('modal-close').onclick=()=>{modal.hidden=true};
modal.addEventListener('click',e=>{if(e.target===modal)modal.hidden=true});
document.addEventListener('keydown',e=>{if(e.key==='Escape')modal.hidden=true});
const impFile=document.getElementById('import-file'),impStatus=document.getElementById('import-status');
document.getElementById('import').onclick=()=>impFile.click();
impFile.onchange=async()=>{const f=impFile.files[0];if(!f)return;impFile.value='';
  run.disabled=true;impStatus.textContent='parsing '+f.name+' …';type('MOTHER: READING TARGET LIST '+f.name.toUpperCase()+' …');out.innerHTML='';sum.innerHTML='';
  try{const r=await fetch('/api/batch',{method:'POST',headers:{'X-Token':TOKEN,'X-Filename':encodeURIComponent(f.name)},body:await f.arrayBuffer()});
    if(!r.ok){type('MOTHER: ERROR '+r.status+' · '+(await r.text()));impStatus.textContent='';return}
    const d=await r.json();
    impStatus.innerHTML=`<span class="rows-ok">${d.rows.length} targets</span>`+(d.errors.length?` · <span class="rows-err">${d.errors.length} rows skipped</span>`:'');
    render(d);
    if(d.errors.length){const div=document.createElement('div');div.className='target';div.innerHTML='<div class="head"><span class="name">&gt; skipped rows</span></div><table><tr><th>Line</th><th>Content</th><th>Reason</th></tr>'+d.errors.map(e=>`<tr><td>${e.line}</td><td class="loc">${esc(e.host||'')}${e.port?':'+e.port:''}</td><td class="note">${esc(e.error)}</td></tr>`).join('')+'</table>';out.prepend(div)}
    type(`MOTHER: BATCH OF ${d.rows.length} TARGETS COMPLETE · ${d.findings.length} FINDINGS · OVERALL ${d.overall||'—'}`);showRuns();
  }catch(e){type('MOTHER: UNABLE TO COMPLY · '+e)}finally{run.disabled=false}};
drop.onclick=()=>{const i=document.createElement('input');i.type='file';i.multiple=true;i.onchange=()=>drop.dispatchEvent(new DragEvent('drop',{dataTransfer:(()=>{const d=new DataTransfer();[...i.files].forEach(f=>d.items.add(f));return d})()}));i.click()};
</script></body></html>
"""


def _serialize(findings: List[Finding]) -> bytes:
    w = worst(findings)
    data = {"overall": w.value if w else None,
            "findings": [{"target": f.target, "location": f.location, "algorithm": f.algorithm, "category": f.category,
                          "verdict": f.verdict.value, "bits": f.bits, "note": f.note} for f in findings]}
    return json.dumps(data).encode()


HOST_RE = __import__("re").compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(:\d{1,5})?$")


def detect_command(cmd: str, target: str) -> str:
    """If a file/scan target is clearly a URL or hostname that does not exist on disk, reroute it."""
    if cmd not in ("file", "scan"):
        return cmd
    t = target.strip()
    if os.path.exists(os.path.expanduser(t)):
        return cmd
    if t.lower().startswith(("http://", "https://")):
        return "web"
    if HOST_RE.match(t) and not t.endswith((".pem", ".crt", ".key", ".p12", ".pfx", ".gpg", ".asc", ".zip", ".7z", ".pdf", ".json")):
        return "ssh" if t.endswith(":22") else "tls"
    return cmd


def run_command(cmd: str, targets: List[str], timeout: float = 5.0) -> List[Finding]:
    findings = []
    if targets and cmd in ("file", "scan"):
        detected = {detect_command(cmd, t) for t in targets}
        if len(detected) == 1 and detected != {cmd}:
            new = detected.pop()
            findings.append(Finding.info(", ".join(targets), "mode", "input looks like a %s target, switched from %s to %s automatically" % (
                "URL" if new == "web" else "host", cmd.upper(), new.upper())))
            cmd = new
    if cmd == "file":
        from .formats import analyze_file
        for t in targets:
            findings.extend(analyze_file(os.path.expanduser(t)))
    elif cmd == "scan":
        from .codescan import scan_path
        for t in targets:
            findings.extend(scan_path(os.path.expanduser(t)))
    elif cmd == "tls":
        from .tlsprobe import probe_tls
        for t in targets:
            findings.extend(probe_tls(t, timeout))
    elif cmd == "ssh":
        from .sshprobe import probe_ssh
        for t in targets:
            findings.extend(probe_ssh(t, timeout))
    elif cmd == "web":
        from .webprobe import probe_web
        for t in targets:
            findings.extend(probe_web(t, timeout))
    else:
        raise ValueError("unknown command")
    return findings


class Handler(BaseHTTPRequestHandler):
    server_version = "pqcheck/" + __version__

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/template.csv":
            from .batch import TEMPLATE_CSV
            return self._send(200, TEMPLATE_CSV.encode(), "text/csv")
        if path != "/":
            return self._send(404, b"not found", "text/plain")
        page = (HTML.replace("__TOKEN__", TOKEN).replace("__VERSION__", __version__).replace("__LOGO__", LOGO_SVG)
                .replace("__DBPATH__", self.server.store.path.replace("\\", "/") if self.server.store else "off"))
        self._send(200, page.encode(), "text/html")

    def do_POST(self):
        if self.headers.get("X-Token") != TOKEN:
            return self._send(403, b"bad token", "text/plain")
        length = int(self.headers.get("Content-Length", "0"))
        if length > 256 * 1024 * 1024:
            return self._send(413, b"too large", "text/plain")
        body = self.rfile.read(length)
        st = self.server.store
        path = self.path.split("?")[0]
        try:
            if path == "/api/run":
                req = json.loads(body.decode())
                targets = [str(t) for t in req.get("targets", [])][:50]
                cmd = str(req.get("cmd", ""))
                findings = run_command(cmd, targets, self.server.timeout)
                if st:
                    with self.server.lock:
                        st.save_run(cmd, targets, findings)
            elif path == "/api/history":
                req = json.loads(body.decode() or "{}")
                rows = st.runs(int(req.get("limit", 40)) or 40, req.get("target")) if st else []
                return self._send(200, json.dumps(rows).encode())
            elif path == "/api/inventory":
                return self._send(200, json.dumps(st.latest_per_target() if st else []).encode())
            elif path == "/api/run_get":
                req = json.loads(body.decode())
                findings = st.findings(int(req.get("id", 0))) if st else []
            elif path == "/api/export":
                fmt = "json" if "format=json" in self.path else "csv"
                data = st.export(fmt) if st else ""
                return self._send(200, data.encode("utf-8"), "application/json" if fmt == "json" else "text/csv")
            elif path == "/api/batch":
                from urllib.parse import unquote
                from .batch import parse_list, run_rows
                name = os.path.basename(unquote(self.headers.get("X-Filename", "list")))
                rows, errors = parse_list(body, name)
                if not rows:
                    return self._send(400, ("no usable rows in %s (%d skipped)" % (name, len(errors))).encode(), "text/plain")
                findings = []
                for row, fs in run_rows(rows[:200], self.server.timeout):
                    if row.note:
                        for f in fs:
                            if f.location == "headline":
                                f.note += " | note: " + row.note
                    findings.extend(fs)
                if st:
                    with self.server.lock:
                        st.save_run("batch", [name] + [r.target for r in rows[:200]], findings)
                data = json.loads(_serialize(findings))
                data["rows"] = [r.as_dict() for r in rows[:200]]
                data["errors"] = [e.as_dict() for e in errors]
                return self._send(200, json.dumps(data).encode())
            elif path == "/api/upload":
                from urllib.parse import unquote
                from .formats import analyze_bytes
                from .knowledge import Verdict
                name = os.path.basename(unquote(self.headers.get("X-Filename", "upload")))
                findings = analyze_bytes(name, body) or [Finding.info(name, "file", "format not recognised as a cryptographic container", Verdict.UNKNOWN)]
                if st:
                    with self.server.lock:
                        st.save_run("upload", [name], findings)
            else:
                return self._send(404, b"not found", "text/plain")
        except ValueError as e:
            return self._send(400, str(e).encode(), "text/plain")
        self._send(200, _serialize(findings))


def serve(port: int = 8765, open_browser: bool = True, timeout: float = 5.0, verbose: bool = False,
          port_explicit: bool = False, db_path=None, save: bool = True) -> int:
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        if port_explicit or port == 0:
            print("pqcheck gui: cannot bind 127.0.0.1:%d (%s). Try --port 0 for a random free port." % (port, e.strerror), file=sys.stderr)
            return 1
        print("pqcheck gui: port %d is busy, picking a free one" % port, file=sys.stderr)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.timeout_probe = timeout
    httpd.timeout = timeout
    httpd.verbose = verbose
    httpd.lock = threading.Lock()
    httpd.store = None
    if save:
        try:
            from .store import Store
            httpd.store = Store(db_path)
            print("pqcheck gui: history database %s" % httpd.store.path)
        except Exception as e:
            print("pqcheck gui: history disabled (%s)" % e, file=sys.stderr)
    url = "http://127.0.0.1:%d/" % httpd.server_address[1]
    try:
        print("pqcheck gui: %s  (Ctrl-C to stop)" % url)
    except Exception:
        pass   # windowed builds have no stdout
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
