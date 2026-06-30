import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
import sys
import uuid
import subprocess
import json
import re
from datetime import datetime
from pydantic import BaseModel
from typing import List, Optional
import requests
from dotenv import load_dotenv

# Ensure backend directory is in sys.path so relative imports work correctly
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    print("[WARNING] VIRUSTOTAL_API_KEY not found in .env. IP reputation scan will be skipped.", file=sys.stderr)

# In-memory storage - Global
cases = {}
jobs = {}
case_status_store = {}

# Membuat instance FastAPI
app = FastAPI(title="Engram Forensics API - Volatility 3 Integrated")

# Menambahkan middleware untuk CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CaseCreate(BaseModel):
    case_name: str
    dump_path: str
    analyst_name: str
    description: Optional[str] = None

# Path logic for frontend
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
    frontend_dir = os.path.join(base_path, "frontend", "dist")
else:
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_dir = os.path.join(base_path, "..", "frontend", "dist")

index_html_path = os.path.join(frontend_dir, "index.html")

# --- Helpers ---

def convert_windows_to_wsl_path(windows_path: str) -> str:
    """Konversi path Windows (C:\\...) ke format WSL (/mnt/c/...)"""
    match = re.match(r'^([a-zA-Z]):\\(.*)', windows_path)
    if match:
        drive = match.group(1).lower()
        rest = match.group(2).replace('\\', '/')
        return f"/mnt/{drive}/{rest}"
    return windows_path.replace('\\', '/')

def run_volatility(dump_path: str, plugin: str) -> Optional[List[dict]]:
    """Eksekusi vol3 menggunakan vol.py internal dan venv python"""
    
    # Menentukan path secara dinamis agar portable
    src_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(src_dir)
    project_root = os.path.dirname(backend_dir)
    
    vol_path = os.path.join(backend_dir, "volatility3", "vol.py")
    
    # Mencari executable python di venv proyek
    if os.name == 'nt':
        venv_python = os.path.join(project_root, "venv", "Scripts", "python.exe")
    else:
        # Di Linux/WSL, coba bin/python (Linux venv) dulu
        venv_python = os.path.join(project_root, "venv", "bin", "python")
        if not os.path.exists(venv_python):
            # Fallback ke Windows venv executable jika berada di WSL/shared drive
            venv_python = os.path.join(project_root, "venv", "Scripts", "python.exe")

    # Jika kita masih tidak menemukan venv python, fallback ke sistem
    if not os.path.exists(venv_python):
        venv_python = "python3" if os.name != 'nt' else "python"

    # Jika kita di Linux tapi memanggil python.exe (Windows), 
    # kita biarkan path dump apa adanya (asumsi user input path Windows).
    # Jika memanggil python Linux, pastikan path dump dalam format WSL.
    actual_dump_path = dump_path
    if not venv_python.lower().endswith(".exe") and os.name != 'nt':
        actual_dump_path = convert_windows_to_wsl_path(dump_path)

    # Membangun perintah eksekusi
    cmd = [venv_python, vol_path, "--offline", "-f", actual_dump_path, "-r", "json", plugin]
    
    print(f"[DEBUG] Menjalankan: {' '.join(cmd)}")
    
    try:
        # Timeout 15 menit untuk dump yang besar
        process = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=900)
        
        if process.returncode != 0:
            print(f"[!] ERROR pada Volatility (Plugin: {plugin}):")
            print(f"--- STDERR ---\n{process.stderr}\n--------------")
            return None
        
        try:
            results = json.loads(process.stdout)
            print(f"[+] Selesai memproses {plugin}, jumlah data: {len(results)}")
            return results
        except json.JSONDecodeError:
            print(f"[!] Gagal decode JSON dari output vol3 {plugin}.")
            print(f"--- STDOUT PREVIEW (first 500 chars) ---\n{process.stdout[:500]}\n----------------------")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"[!] TIMEOUT: Eksekusi plugin {plugin} melampaui batas waktu 15 menit.")
        return None
    except Exception as e:
        print(f"[!] EXCEPTION saat menjalankan vol3: {e}")
        return None

def check_ip_reputation(ip_address: str) -> dict:
    """
    Melakukan pengecekan reputasi IP menggunakan VirusTotal Public API.
    Mempertimbangkan rate limit.
    """
    if not VT_API_KEY:
        return {"malicious": 0, "suspicious": 0, "status": "skipped_no_key"}

    # Batasi untuk IP publik saja
    if ip_address in ["127.0.0.1", "0.0.0.0"] or \
       ip_address.startswith("10.") or \
       ip_address.startswith("172.16.") or \
       ip_address.startswith("172.17.") or \
       ip_address.startswith("172.18.") or \
       ip_address.startswith("172.19.") or \
       ip_address.startswith("172.2") or \
       ip_address.startswith("172.30.") or \
       ip_address.startswith("172.31.") or \
       ip_address.startswith("192.168.") or \
       ":" in ip_address: # Simple check for IPv6, often local/internal
        return {"malicious": 0, "suspicious": 0, "status": "skipped_private_ip"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # Timeout pendek untuk menghindari blocking terlalu lama
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        return {"malicious": malicious, "suspicious": suspicious, "status": "checked"}
    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            print(f"[WARNING] VirusTotal API Rate Limit Exceeded for {ip_address}", file=sys.stderr)
            return {"malicious": 0, "suspicious": 0, "status": "rate_limited"}
        print(f"[ERROR] HTTP Error for {ip_address}: {e}", file=sys.stderr)
        return {"malicious": 0, "suspicious": 0, "status": "error"}
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] Connection Error for {ip_address}: {e}", file=sys.stderr)
        return {"malicious": 0, "suspicious": 0, "status": "connection_error"}
    except requests.exceptions.Timeout:
        print(f"[WARNING] VirusTotal API Timeout for {ip_address}", file=sys.stderr)
        return {"malicious": 0, "suspicious": 0, "status": "timeout"}
    except json.JSONDecodeError:
        print(f"[ERROR] Failed to decode JSON from VirusTotal for {ip_address}", file=sys.stderr)
        return {"malicious": 0, "suspicious": 0, "status": "json_error"}
    except Exception as e:
        print(f"[ERROR] Unexpected error in check_ip_reputation for {ip_address}: {e}", file=sys.stderr)
        return {"malicious": 0, "suspicious": 0, "status": "error"}


def calculate_process_score(proc: dict, all_procs: List[dict]) -> tuple:
    """Heuristik deteksi malware sederhana"""
    score = 0
    reasons = []
    
    name = proc.get("ImageFileName", "").lower()
    pid = proc.get("PID")
    ppid = proc.get("PPID")
    
    if name == "svchost.exe":
        parent = next((p for p in all_procs if p.get("PID") == ppid), None)
        parent_name = parent.get("ImageFileName", "").lower() if parent else "unknown"
        if parent_name != "services.exe":
            score += 45
            reasons.append("unusual_parent")
            
    if not proc.get("FileName"):
        score += 30
        reasons.append("no_disk_path")

    suspicious_keywords = ["malware", "beacon", "meterpreter", "exploit", "nc.exe"]
    if any(k in name for k in suspicious_keywords):
        score += 60
        reasons.append("suspicious_name")

    severity = "clean"
    if score >= 85: severity = "critical"
    elif score >= 70: severity = "high"
    elif score >= 50: severity = "medium"
    elif score > 0: severity = "low"
    
    return min(score, 100), reasons, severity

def background_analysis(case_id: str):
    """Pipeline analisis utama yang berjalan di background"""
    global cases, jobs
    if case_id not in cases: return
    
    case = cases[case_id]
    if case_id not in jobs:
        jobs[case_id] = {
            "status": "queued",
            "progress": {"percent": 0, "current_plugin": "init"}
        }
    job = jobs[case_id]
    
    if not os.path.exists(case["dump_path"]):
        print(f"[!] File tidak ditemukan: {case['dump_path']}")
        job["status"] = "failed"
        case["status"] = "failed"
        return

    dump_path = case["dump_path"]
    job["status"] = "running"
    case["status"] = "running"
    
    # Plugin list sesuai instruksi Hackathon
    pipeline = [
        ("windows.info", 10),
        ("windows.pslist", 25),
        ("windows.cmdline", 40),
        ("windows.netscan", 55),
        ("windows.malware.malfind", 70),
        ("windows.malware.pebmasquerade", 85),
        ("windows.registry.userassist", 100)
    ]
    
    for i, (plugin, percent) in enumerate(pipeline):
        job["progress"]["current_plugin"] = plugin
        results = run_volatility(dump_path, plugin)
        
        if results is None:
            # windows.info seringkali gagal jika profil tidak pas, kita beri grace period
            if plugin == "windows.info":
                cases[case_id]["raw_results"][plugin] = []
                continue
            job["status"] = "failed"
            case["status"] = "failed"
            return

        cases[case_id]["raw_results"][plugin] = results
        job["progress"]["percent"] = percent

        # Khusus untuk windows.netscan, lakukan pengecekan reputasi IP
        if plugin == "windows.netscan":
            netscan_results = cases[case_id]["raw_results"]["windows.netscan"]
            # ... (logika VT tetap dipertahankan)
            external_ips_to_check = []
            for conn in netscan_results:
                foreign_addr = conn.get("ForeignAddr")
                state = conn.get("State")
                if foreign_addr and state == "ESTABLISHED":
                    if not (foreign_addr.startswith("10.") or foreign_addr.startswith("172.") or foreign_addr.startswith("192.168.") or foreign_addr == "127.0.0.1" or ":" in foreign_addr):
                        external_ips_to_check.append(foreign_addr)
            unique_ips_to_check = list(set(external_ips_to_check))[:5]
            for ip in unique_ips_to_check:
                vt_data = check_ip_reputation(ip)
                for conn in netscan_results:
                    if conn.get("ForeignAddr") == ip:
                        conn["vt_status"] = vt_data

    job["status"] = "completed"
    case["status"] = "completed"
    case["completed_at"] = datetime.now().isoformat() + "Z"
    
    pslist = cases[case_id]["raw_results"].get("windows.pslist", [])
    malfind = cases[case_id]["raw_results"].get("windows.malware.malfind", [])
    netscan = cases[case_id]["raw_results"].get("windows.netscan", [])
    peb = cases[case_id]["raw_results"].get("windows.malware.pebmasquerade", [])
    
    case["summary"] = {
        "total_processes": len(pslist),
        "suspicious_processes": len([p for p in pslist if calculate_process_score(p, pslist)[0] > 40]),
        "critical_alerts": len(malfind) + len(peb),
        "ioc_found": len(netscan),
        "yara_hits": 0
    }
    print(f"[***] Analisis Case {case_id} SELESAI.")

def run_volatility_pipeline(case_id: str, dump_path: str):
    from pipeline import run_full_analysis, get_case_summary
    from virustotal_checker import check_ips_with_virustotal, build_virustotal_lookup
    
    PLUGINS = [
        'windows.pslist',
        'windows.dlllist', 
        'windows.handles',
        'windows.ldrmodules',
        'windows.malfind',
        'windows.modules',
        'windows.svcscan',
        'windows.callbacks',
        'windows.psscan',
        'windows.netscan',
    ]
    
    try:
        volatility_results = {}
        for idx, plugin_name in enumerate(PLUGINS):
            if case_id not in case_status_store:
                return
            case_status_store[case_id]['current_plugin'] = plugin_name
            # Plugins cover 0% to 85% of progress
            percent = int((idx / len(PLUGINS)) * 85)
            case_status_store[case_id]['percent'] = percent
            
            try:
                res = run_volatility(dump_path, plugin_name)
                if res is None:
                    res = []
            except Exception as e:
                print(f"[WARNING] Plugin {plugin_name} failed: {e}", file=sys.stderr)
                res = []
                
            key = plugin_name.replace('windows.', '')
            volatility_results[key] = res
            
        # VirusTotal Reputation Scan Phase (90% progress)
        if case_id not in case_status_store:
            return
        case_status_store[case_id]['current_plugin'] = 'Checking VirusTotal IOC reputation...'
        case_status_store[case_id]['percent'] = 90
        
        virustotal_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        netscan_results = volatility_results.get('netscan', [])
        
        virustotal_lookup = None
        if virustotal_api_key:
            try:
                from virustotal_checker import is_valid_public_ip
                ip_counts = {}
                for conn in (netscan_results or []):
                    foreign_addr = conn.get("ForeignAddr") or conn.get("foreign_addr") or conn.get("foreign") or conn.get("ForeignAddress")
                    if not foreign_addr:
                        continue
                    ip_candidate = str(foreign_addr).strip()
                    if ':' in ip_candidate:
                        if ip_candidate.startswith('[') and ']' in ip_candidate:
                            ip_candidate = ip_candidate.split(']')[0].replace('[', '')
                        elif ip_candidate.count(':') == 1:
                            ip_candidate = ip_candidate.split(':')[0]
                    ip_candidate = ip_candidate.strip()
                    if ip_candidate and is_valid_public_ip(ip_candidate):
                        ip_counts[ip_candidate] = ip_counts.get(ip_candidate, 0) + 1
                
                # Sort unique IPs by frequency descending
                unique_ips = sorted(ip_counts.keys(), key=lambda ip: ip_counts[ip], reverse=True)
                
                # Query VirusTotal API (asynchronously since check_ips_with_virustotal is async)
                import asyncio
                try:
                    vt_results = asyncio.run(check_ips_with_virustotal(unique_ips, virustotal_api_key))
                except RuntimeError:
                    # In case loop is already running in current thread
                    new_loop = asyncio.new_event_loop()
                    try:
                        vt_results = new_loop.run_until_complete(check_ips_with_virustotal(unique_ips, virustotal_api_key))
                    finally:
                        new_loop.close()
                
                virustotal_lookup = build_virustotal_lookup(netscan_results, vt_results)
            except Exception as vt_error:
                print(f"[WARNING] VirusTotal check failed: {vt_error}", file=sys.stderr)
                virustotal_lookup = None
        else:
            print("[INFO] VirusTotal API key is not configured. Skipping reputation check.", file=sys.stderr)
            virustotal_lookup = None

        # ML Case-level Scoring Phase
        ml_case_level_result = None
        try:
            import joblib
            import pandas as pd
            import numpy as np
            
            # Paths to ML files
            model_path = os.path.join(backend_dir, 'engram_isolation_forest.pkl')
            scaler_path = os.path.join(backend_dir, 'engram_scaler.pkl')
            metadata_path = os.path.join(backend_dir, 'engram_model_metadata.pkl')
            
            # Check if files exist
            if os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(metadata_path):
                model = joblib.load(model_path)
                scaler = joblib.load(scaler_path)
                metadata = joblib.load(metadata_path)
                
                feature_names = metadata['feature_names']
                score_min = metadata['score_min']
                score_max = metadata['score_max']
                
                # Extract 55 features at case level
                from feature_extractor import extract_all_features
                extracted_features = extract_all_features(volatility_results)
                
                # DataFrame with correct columns
                X = pd.DataFrame([extracted_features])[feature_names]
                
                # Transform and predict
                X_scaled = scaler.transform(X)
                prediction_val = model.predict(X_scaled)[0] # -1 = anomali, 1 = normal
                raw_score = model.decision_function(X_scaled)[0]
                
                # Convert raw score to 0-100 percentage
                percentage = (1 - (raw_score - score_min) / (score_max - score_min)) * 100
                percentage = float(np.clip(percentage, 0, 100))
                
                ml_case_level_result = {
                    'prediction': 'MALWARE' if prediction_val == -1 else 'BENIGN',
                    'malware_probability': percentage
                }
                print(f"[***] ML Prediction: {ml_case_level_result['prediction']} ({ml_case_level_result['malware_probability']:.2f}%)")
            else:
                print("[WARNING] One or more ML model files (.pkl) are missing. Skipping ML scoring.", file=sys.stderr)
        except Exception as ml_err:
            print(f"[WARNING] ML scoring failed: {ml_err}", file=sys.stderr)
            ml_case_level_result = None

        # Analysis phase (95% progress)
        if case_id not in case_status_store:
            return
        case_status_store[case_id]['current_plugin'] = 'Analyzing results...'
        case_status_store[case_id]['percent'] = 95
        
        try:
            results = run_full_analysis(volatility_results, virustotal_lookup=virustotal_lookup, ml_case_level_result=ml_case_level_result)
            summary = get_case_summary(results)
            
            case_status_store[case_id].update({
                'status': 'completed',
                'percent': 100,
                'current_plugin': None,
                'results': results,
                'case_summary': summary,
                'completed_at': datetime.now().isoformat() + "Z"
            })
            
            # Update the existing cases entry for backward compatibility
            if case_id in cases:
                cases[case_id]["status"] = "completed"
                cases[case_id]["summary"] = {
                    "total_processes": summary["total_processes"],
                    "suspicious_processes": summary["flagged_count"],
                    "critical_alerts": summary["critical_count"] + summary["high_count"],
                    "ioc_found": len(netscan_results),
                    "yara_hits": 0
                }
        except Exception as pipeline_error:
            print(f"[ERROR] Pipeline calculation failed: {pipeline_error}", file=sys.stderr)
            case_status_store[case_id].update({
                'status': 'failed',
                'percent': 100,
                'current_plugin': None,
                'error_message': f"Pipeline calculation failed: {pipeline_error}"
            })
            if case_id in cases:
                cases[case_id]["status"] = "failed"
    except Exception as e:
        print(f"[ERROR] Global pipeline error: {e}", file=sys.stderr)
        if case_id in case_status_store:
            case_status_store[case_id].update({
                'status': 'failed',
                'percent': 100,
                'current_plugin': None,
                'error_message': f"Global pipeline error: {e}"
            })
        if case_id in cases:
            cases[case_id]["status"] = "failed"

# --- API Endpoints ---

@app.post("/api/cases")
async def create_case(case_data: CaseCreate):
    global cases
    case_id = f"case_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:4]}"
    new_case = {
        "case_id": case_id,
        "case_name": case_data.case_name,
        "dump_path": case_data.dump_path,
        "analyst_name": case_data.analyst_name,
        "description": case_data.description,
        "status": "ready",
        "created_at": datetime.now().isoformat() + "Z",
        "summary": None,
        "raw_results": {
            "windows.pslist": [], "windows.netscan": [], "windows.malware.malfind": [],
            "windows.info": [], "windows.cmdline": [], "windows.malware.pebmasquerade": [],
            "windows.registry.userassist": []
        }
    }
    cases[case_id] = new_case
    return {"case_id": case_id, "case_name": case_data.case_name, "status": "created"}

@app.get("/api/cases")
async def list_cases():
    return {"success": True, "data": list(cases.values()), "error": None}

@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    if case_id not in cases:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"success": True, "data": cases[case_id], "error": None}

@app.post("/api/cases/{case_id}/analyze")
async def analyze_case(case_id: str, background_tasks: BackgroundTasks):
    if case_id not in cases:
        raise HTTPException(status_code=404, detail="Case not found")
    
    # Validation of dump_path existence
    dump_path = cases[case_id]["dump_path"]
    if not os.path.exists(dump_path):
        raise HTTPException(status_code=400, detail=f"Dump path does not exist: {dump_path}")
        
    case_status_store[case_id] = {
        'status': 'running',
        'percent': 0,
        'current_plugin': None,
        'started_at': datetime.now().isoformat() + "Z",
        'completed_at': None,
        'error_message': None,
        'results': None,
        'case_summary': None
    }
    
    cases[case_id]["status"] = "running"
    background_tasks.add_task(run_volatility_pipeline, case_id, dump_path)
    return {'status': 'running', 'case_id': case_id}

class CaseStatusResponse(BaseModel):
    status: str
    current_plugin: Optional[str] = None
    percent: int
    error_message: Optional[str] = None

@app.get("/api/cases/{case_id}/status", response_model=CaseStatusResponse)
async def get_case_status(case_id: str):
    if case_id not in case_status_store:
        raise HTTPException(status_code=404, detail="Case status not found")
    status_info = case_status_store[case_id]
    return CaseStatusResponse(
        status=status_info.get('status', 'pending'),
        current_plugin=status_info.get('current_plugin'),
        percent=status_info.get('percent', 0),
        error_message=status_info.get('error_message')
    )

@app.get("/api/cases/{case_id}/results")
async def get_case_results(case_id: str):
    if case_id not in case_status_store:
        raise HTTPException(status_code=404, detail="Case status not found")
    status_info = case_status_store[case_id]
    if status_info.get('status') != 'completed':
        raise HTTPException(status_code=400, detail="Analysis not completed yet")
    return {
        'case_id': case_id,
        'results': status_info.get('results'),
        'summary': status_info.get('case_summary')
    }

@app.get("/api/cases/{case_id}/processes")
async def get_processes(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_ps = cases[case_id].get("raw_results", {}).get("windows.pslist", [])
    raw_cmd = cases[case_id].get("raw_results", {}).get("windows.cmdline", [])
    
    # Map CMDLine data by PID
    cmd_map = {c.get("PID"): c.get("Args", "") for c in raw_cmd}
    
    processes = []
    for p in raw_ps:
        score, reasons, severity = calculate_process_score(p, raw_ps)
        pid = p.get("PID")
        processes.append({
            "pid": pid,
            "ppid": p.get("PPID"),
            "name": p.get("ImageFileName"),
            "path": p.get("FileName") or "N/A",
            "command_line": cmd_map.get(pid, "N/A"),
            "score": score,
            "severity": severity
        })
    return {"success": True, "data": {"processes": processes}}

@app.get("/api/cases/{case_id}/network")
async def get_network(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_net = cases[case_id].get("raw_results", {}).get("windows.netscan", [])
    raw_ps = cases[case_id].get("raw_results", {}).get("windows.pslist", [])
    pid_map = {p.get("PID"): p.get("ImageFileName") for p in raw_ps}
    connections = []
    for n in raw_net:
        pid = n.get("PID")
        connections.append({
            "pid": pid,
            "process": pid_map.get(pid) or "Unknown",
            "local": f"{n.get('LocalAddr')}:{n.get('LocalPort')}",
            "foreign": f"{n.get('ForeignAddr')}:{n.get('ForeignPort')}",
            "state": n.get("State"),
            "vt_status": n.get("vt_status", {"malicious": 0, "suspicious": 0, "status": "not_scanned"})
        })
    return {"success": True, "data": {"connections": connections}}

@app.get("/api/cases/{case_id}/threats")
async def get_threats(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_mal = cases[case_id].get("raw_results", {}).get("windows.malware.malfind", [])
    raw_peb = cases[case_id].get("raw_results", {}).get("windows.malware.pebmasquerade", [])
    
    threats = []
    for m in raw_mal:
        threats.append({
            "type": "Code Injection",
            "pid": m.get("PID"),
            "process": m.get("Process") or "Unknown",
            "details": f"Protection: {m.get('Protection')} at {m.get('StartVPN')}",
            "severity": "critical"
        })
    
    for p in raw_peb:
        threats.append({
            "type": "PEB Masquerade",
            "pid": p.get("PID"),
            "process": p.get("Process") or "Unknown",
            "details": "PEB image path doesn't match loader information (Spoofing Detected)",
            "severity": "high"
        })
        
    return {"success": True, "data": {"threats": threats}}

@app.get("/api/cases/{case_id}/userassist")
async def get_userassist(case_id: str):
    if case_id not in cases: raise HTTPException(status_code=404)
    raw_ua = cases[case_id].get("raw_results", {}).get("windows.registry.userassist", [])
    
    activities = []
    for u in raw_ua:
        activities.append({
            "path": u.get("Path"),
            "run_count": u.get("Run count"),
            "last_executed": u.get("Last session"),
            "hive": u.get("Hive")
        })
    return {"success": True, "data": {"activities": activities}}

@app.get("/api/test/set_status/{case_id}/{status}/{plugin}/{percent}")
async def set_test_status(case_id: str, status: str, plugin: str, percent: int):
    global cases, jobs
    if case_id not in cases:
        cases[case_id] = {
            "case_id": case_id,
            "case_name": "Test Case",
            "dump_path": "test.raw",
            "analyst_name": "Test Analyst",
            "status": status,
            "raw_results": {}
        }
    jobs[case_id] = {
        "status": status,
        "progress": {"percent": percent, "current_plugin": plugin}
    }
    cases[case_id]["status"] = status
    return {"success": True}

if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
