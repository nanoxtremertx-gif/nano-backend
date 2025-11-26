# servidor4.py (v8.0 - FAIL-OPEN PERMISSION)
import os
import sys
import json
import uuid
import subprocess
import requests 
import shutil   
import tempfile 
import threading
import time
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- CONFIGURACIÓN ---
SRV1_URL = os.environ.get("SRV1_URL", "https://nano-xtremertx-nano-backend.hf.space")
SRV1_MASTER_KEY = os.environ.get("SRV1_KEY", "NANO_MASTER_KEY_2025")

try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path(".").resolve()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Directorios
TEMP_INPUT_DIR = BASE_DIR / "temp_in"
TEMP_OUTPUT_DIR = BASE_DIR / "temp_out"
ENCODER_DIR = BASE_DIR / "xtremertx_ai"
MODELS_DIR = ENCODER_DIR / "models"

os.makedirs(TEMP_INPUT_DIR, exist_ok=True)
os.makedirs(TEMP_OUTPUT_DIR, exist_ok=True)

# Mapeo
ENCODER_SCRIPTS = {
    "perceptual": ENCODER_DIR / "encoder.py",
    "ultrav": ENCODER_DIR / "encoderb.py",
    "bitabit": ENCODER_DIR / "encoderc.py"
}

# --- MEMORIA DE TRABAJOS ---
JOBS = {} 

def ask_permission(client_id):
    """
    Consulta permiso. Si falla o tarda > 5s, DEVUELVE TRUE (Permitir).
    Prioridad: Funcionamiento sobre Restricción.
    """
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/check-permission"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY}
        payload = {"singleUseClientId": client_id}
        
        print(f"[S4] Verificando Cooldown en S1...")
        # Timeout corto: Si no responde rápido, asumimos que está ocupado y dejamos pasar.
        resp = requests.post(url, json=payload, headers=headers, timeout=5)
        
        if resp.status_code == 200:
            allow = resp.json().get("allow", False)
            reason = resp.json().get("reason", "Unknown")
            # Si S1 dice explícitamente NO, respetamos el NO.
            if not allow: return False, reason
            return True, "OK"
            
        # Si S1 da error 500/404, dejamos pasar.
        print(f"[S4] S1 respondió error {resp.status_code}. Saltando restricción.")
        return True, "S1_Error_Skipped"
        
    except Exception as e:
        # Si hay timeout o error de red, dejamos pasar.
        print(f"[S4] S1 no responde ({str(e)}). Saltando restricción.")
        return True, "S1_Timeout_Skipped"

def upload_to_srv1(username, file_path):
    if not file_path.exists(): return False, "Archivo no existe"
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/upload-file"
        
        # Datos corregidos para DB
        payload = {
            "userId": username,
            "parentId": "null", 
            "verificationStatus": "verified_quantum", # 16 chars (entra en DB varchar 20)
            "description": "Generado por NANO CRS"
        }

        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            # Aquí sí esperamos (timeout 300s) porque es la subida vital
            resp = requests.post(url, data=payload, files=files, timeout=300)
            
        if 200 <= resp.status_code < 300:
            return True, "OK"
        else:
            return False, f"S1 Rechazo ({resp.status_code}): {resp.text[:50]}"
    except Exception as e: return False, str(e)

def report_log_final(record):
    try:
        # Reporte asíncrono (fire and forget), timeout corto
        url = f"{SRV1_URL.rstrip('/')}/api/worker/log-success"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY}
        requests.post(url, json=record, headers=headers, timeout=5)
    except: pass

# --- HILO DE TRABAJO ---
def run_encoder_job(job_id, file_path, encoder_type, username, client_id, user_role, location, user_ip):
    job = JOBS[job_id]
    job['status'] = 'processing'
    job['progress'] = 0
    start_time = time.time()
    
    temp_in = Path(file_path)
    output_dir = Path(tempfile.mkdtemp(dir=TEMP_OUTPUT_DIR))
    
    try:
        # 1. Encoder
        base_name = f"{temp_in.stem}_{encoder_type}"
        final_crs = output_dir / f"{base_name}.crs"
        script = ENCODER_SCRIPTS[encoder_type]
        
        # Autor dinámico
        cmd = [
            sys.executable, str(script),
            str(temp_in), base_name,
            "--crs_dir", str(output_dir),
            "--models_dir", str(MODELS_DIR),
            "--author", username 
        ]
        if encoder_type == "perceptual": cmd.extend(["--fidelity_quality", "0"])

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None: break
            if line:
                line = line.strip()
                if line.startswith("PROGRESS:"):
                    try:
                        p = int(line.split(":")[1])
                        job['progress'] = int(p * 0.9) 
                    except: pass
                print(f"[JOB {job_id}] {line}") 

        if process.returncode != 0 or not final_crs.exists():
            stderr = process.stderr.read()
            raise Exception(f"Fallo Encoder: {stderr[-200:]}")

        # 2. Subida
        job['progress'] = 95
        input_size_mb = temp_in.stat().st_size / (1024*1024)
        final_size_mb = final_crs.stat().st_size / (1024*1024)
        
        ok, msg = upload_to_srv1(username, final_crs)
        if not ok: raise Exception(f"Fallo subida S1: {msg}")

        # 3. Reporte
        end_time = time.time()
        exec_time_sec = end_time - start_time
        mins, secs = divmod(int(exec_time_sec), 60)
        time_str = f"{mins:02d}:{secs:02d}"

        full_record = {
            "id": job_id,
            "username": username,
            "userRole": user_role,
            "userId": client_id,
            "location": location,
            "ip_address": user_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "encoderType": encoder_type,
            "execution_time": time_str,
            "input_size_mb": f"{input_size_mb:.2f}",
            "output_size_mb": f"{final_size_mb:.2f}",
            "original_filename": temp_in.name,
            "final_filename": final_crs.name,
            "singleUseClientId": client_id
        }
        
        report_log_final(full_record)
        
        job['progress'] = 100
        job['status'] = 'completed'
        job['result'] = full_record

    except Exception as e:
        print(f"[JOB {job_id}] ERROR: {e}")
        job['status'] = 'failed'
        job['error'] = str(e)
    
    finally:
        try:
            if temp_in.exists(): os.remove(temp_in)
            shutil.rmtree(output_dir, ignore_errors=True)
        except: pass

# --- RUTAS API ---
@app.route("/convert/start", methods=["POST"])
def start_conversion():
    if "file" not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files["file"]
    
    job_id = uuid.uuid4().hex[:8]
    username = request.form.get("username", "anon")
    client_id = request.form.get("singleUseClientId", username)
    encoder_type = request.form.get("encoderType", "perceptual")
    user_role = request.form.get("userRole", "user")
    location = request.form.get("location", "Desconocido")
    user_ip = request.form.get("userIp", "0.0.0.0")

    # Check Permission (Modo Fail-Open)
    # Si hay error de red, devuelve TRUE para no bloquear.
    allowed, reason = ask_permission(client_id)
    
    if not allowed: 
        return jsonify({"success": False, "error": reason}), 429

    temp_path = Path(tempfile.mkdtemp(dir=TEMP_INPUT_DIR)) / file.filename
    file.save(temp_path)

    JOBS[job_id] = {'status': 'pending', 'progress': 0}
    thread = threading.Thread(target=run_encoder_job, args=(
        job_id, temp_path, encoder_type, username, client_id, user_role, location, user_ip
    ))
    thread.start()

    return jsonify({"success": True, "job_id": job_id}), 200

@app.route("/convert/status/<job_id>", methods=["GET"])
def check_status(job_id):
    job = JOBS.get(job_id)
    if not job: return jsonify({"error": "Job not found"}), 404
    return jsonify(job), 200

@app.route("/")
def home(): return "S4 WORKER (V8.0 - NO WAIT)", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860)