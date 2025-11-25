# servidor4.py (v4.0 - WORKER PARA HUGGING FACE)
import os
import sys
import json
import uuid
import time
import subprocess
import requests 
import shutil   
import tempfile 
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

# ===============================================================
# 🔹 CONFIGURACIÓN DEL WORKER (Srv4)
# ===============================================================
# URL REAL DE TU SERVIDOR 1 (CEREBRO)
SRV1_URL = "https://nano-xtremertx-nano-backend.hf.space" 

# CLAVE MAESTRA (Debe coincidir con la de Srv1)
SRV1_MASTER_KEY = "NANO_MASTER_KEY_2025" 

try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path(".").resolve()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Rutas Locales Temporales
TEMP_INPUT_DIR = os.path.join(BASE_DIR, "temp_in")
TEMP_OUTPUT_DIR = os.path.join(BASE_DIR, "temp_out")
ENCODER_DIR = BASE_DIR / "xtremertx_ai"
MODELS_DIR = ENCODER_DIR / "models"

os.makedirs(TEMP_INPUT_DIR, exist_ok=True)
os.makedirs(TEMP_OUTPUT_DIR, exist_ok=True)

# Mapeo de Encoders
ENCODER_SCRIPTS = {
    "perceptual": ENCODER_DIR / "encoder.py",
    "ultrav": ENCODER_DIR / "encoderb.py",
    "bitabit": ENCODER_DIR / "encoderc.py"
}

# Verificación de inicio
if not MODELS_DIR.exists():
    print(f"⚠️  ADVERTENCIA: Directorio de modelos no encontrado: {MODELS_DIR}")

# ===============================================================
# 🧠 COMUNICACIÓN CON EL CEREBRO (Srv1)
# ===============================================================

def ask_permission(client_id):
    """Pregunta a Srv1 si este usuario puede convertir."""
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/check-permission"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY, "Content-Type": "application/json"}
        payload = {"singleUseClientId": client_id}
        
        print(f"[S4] Consultando permiso a: {url}")
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if resp.status_code == 200:
            data = resp.json()
            return data.get("allow", False), data.get("reason", "Desconocido")
        elif resp.status_code == 404:
            return False, "Srv1 no tiene la ruta /api/worker/check-permission configurada."
        return False, f"Error Srv1: {resp.status_code}"
    except Exception as e:
        print(f"[ERROR CONEXIÓN SRV1] {e}")
        return False, "Error de conexión con el Servidor Maestro"

def report_success(record):
    """Envía el registro de éxito a Srv1 para activar el cooldown."""
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/log-success"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY, "Content-Type": "application/json"}
        requests.post(url, json=record, headers=headers, timeout=10)
        print("[S4] Cooldown reportado a Srv1.")
    except Exception as e:
        print(f"[ERROR LOG SRV1] No se pudo guardar el log: {e}")

def upload_result_to_srv1(username, file_path, original_name):
    """Sube el archivo final a la base de datos de Srv1."""
    if not file_path.exists(): return False
    
    print(f"[S4] Subiendo {file_path.name} a {SRV1_URL} para {username}...")
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/upload-file"
        
        # Preparamos los datos tal cual los espera Srv1 (/api/upload-file)
        payload = {
            "userId": username,
            "parentId": "null", # A la raíz
            "verificationStatus": "clean_by_worker"
        }
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            resp = requests.post(url, data=payload, files=files, timeout=300)
            
        if 200 <= resp.status_code < 300:
            print("[S4] Subida exitosa.")
            return True
        else:
            print(f"[S4] Fallo subida. Código: {resp.status_code}. Resp: {resp.text}")
            return False
            
    except Exception as e:
        print(f"[S4] Excepción al subir: {e}")
        return False

# ===============================================================
# 🔄 ENDPOINT PRINCIPAL: /convert
# ===============================================================
@app.route("/convert", methods=["POST"])
def convert_remote():
    print("\n--- [S4] Nueva Petición de Conversión ---")
    
    # 1. Recibir Datos
    if "file" not in request.files: return jsonify({"success": False, "error": "Sin archivo"}), 400
    file = request.files["file"]
    username = request.form.get("username", "anon")
    client_id = request.form.get("singleUseClientId", "")
    encoder_type = request.form.get("encoderType", "perceptual")
    
    if not client_id: return jsonify({"success": False, "error": "Falta Client ID"}), 400
    if encoder_type not in ENCODER_SCRIPTS: return jsonify({"success": False, "error": "Encoder inválido"}), 400

    print(f"[S4] Usuario: {username} | Encoder: {encoder_type}")

    # 2. Consultar al Jefe (Srv1) si hay permiso
    allowed, reason = ask_permission(client_id)
    if not allowed:
        print(f"[S4] Permiso denegado por Srv1: {reason}")
        return jsonify({"success": False, "error": reason}), 429

    # 3. Guardar Entrada Temporalmente
    temp_in = Path(tempfile.mkdtemp(dir=TEMP_INPUT_DIR)) / file.filename
    output_dir = None
    
    try:
        file.save(temp_in)
        
        # 4. Configurar Salida
        job_id = uuid.uuid4().hex[:8]
        output_dir = Path(tempfile.mkdtemp(dir=TEMP_OUTPUT_DIR))
        base_name = f"{Path(file.filename).stem}_{encoder_type}"
        final_crs = output_dir / f"{base_name}.crs"
        
        # 5. Ejecutar Encoder (Subprocess)
        script = ENCODER_SCRIPTS[encoder_type]
        cmd = [
            sys.executable, str(script),
            str(temp_in), base_name,
            "--crs_dir", str(output_dir),
            "--models_dir", str(MODELS_DIR),
            "--author", "NANO"
        ]
        
        print(f"[S4] Ejecutando encoder...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0 or not final_crs.exists():
            print(f"[S4] Error Encoder STDERR: {result.stderr[-300:]}")
            raise Exception(f"Fallo Encoder (Code {result.returncode})")
            
        # 6. Entregar al Jefe (Srv1)
        upload_ok = upload_result_to_srv1(username, final_crs, file.filename)
        
        if not upload_ok:
            return jsonify({"success": False, "error": "Conversión OK, pero falló envío a tu cuenta."}), 502
            
        # 7. Reportar Misión Cumplida (Para activar cooldown)
        record = {
            "id": job_id,
            "username": username,
            "singleUseClientId": client_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "encoderType": encoder_type
        }
        report_success(record)
        
        # 8. Limpieza
        return jsonify({"success": True, "message": "Archivo enviado a tu cuenta."}), 200

    except Exception as e:
        print(f"[S4] Error Fatal: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        # Borrar temporales siempre
        try:
            if temp_in.exists(): os.remove(temp_in)
            if output_dir and output_dir.exists(): shutil.rmtree(output_dir)
        except: pass

# ===============================================================
# 🚀 MAIN
# ===============================================================
if __name__ == "__main__":
    print("-" * 50)
    print("🚀 SERVIDOR 4 (WORKER) - CONECTADO A HUGGING FACE")
    print(f"📡 Maestro URL: {SRV1_URL}")
    print(f"🛠️  Puerto Local: 5050")
    print("-" * 50)
    app.run(host="0.0.0.0", port=5050)
