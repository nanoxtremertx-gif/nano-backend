import os
import sys
import json
import uuid
import subprocess
import requests 
import shutil   
import tempfile 
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

# ===============================================================
# 🔹 CONFIGURACIÓN DEL OBRERO (S4)
# ===============================================================

# URL de tu Servidor 1 (Cerebro)
SRV1_URL = os.environ.get("SRV1_URL", "https://nano-xtremertx-nano-backend.hf.space")
SRV1_MASTER_KEY = os.environ.get("SRV1_KEY", "NANO_MASTER_KEY_2025")

try:
    BASE_DIR = Path(__file__).resolve().parent
except NameError:
    BASE_DIR = Path(".").resolve()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Directorios Temporales
TEMP_INPUT_DIR = BASE_DIR / "temp_in"
TEMP_OUTPUT_DIR = BASE_DIR / "temp_out"
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

if not MODELS_DIR.exists():
    print(f"⚠️  ADVERTENCIA CRÍTICA: No se encuentran los modelos en: {MODELS_DIR}")

# ===============================================================
# 🧠 COMUNICACIÓN CON EL CEREBRO
# ===============================================================

def ask_permission(client_id):
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/check-permission"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY, "Content-Type": "application/json"}
        payload = {"singleUseClientId": client_id}
        
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("allow", False), data.get("reason", "Desconocido")
        return False, f"Error Srv1 ({resp.status_code})"
    except Exception as e:
        return False, f"Error Red: {str(e)}"

def upload_result_to_srv1(username, file_path):
    """Sube el archivo final a Srv1 y devuelve (Éxito, Mensaje)."""
    if not file_path.exists(): return False, "Archivo CRS no generado."
    
    print(f"[S4] Subiendo a: {SRV1_URL}...")
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/upload-file"
        
        payload = {
            "userId": username,
            "parentId": "null", 
            "verificationStatus": "verified_nano_quantum"
        }
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            resp = requests.post(url, data=payload, files=files, timeout=300)
            
        if 200 <= resp.status_code < 300:
            return True, "OK"
        else:
            # Capturamos el error real que devuelve Srv1
            error_msg = f"Srv1 rechazó el archivo (Código {resp.status_code}): {resp.text[:100]}"
            print(f"[S4] Error Subida: {error_msg}")
            return False, error_msg
            
    except Exception as e:
        error_msg = f"Error de Conexión al subir: {str(e)}"
        print(f"[S4] Excepción: {error_msg}")
        return False, error_msg

def report_success(record):
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/log-success"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY, "Content-Type": "application/json"}
        requests.post(url, json=record, headers=headers, timeout=10)
    except: pass

# ===============================================================
# 🔄 RUTA CONVERT
# ===============================================================
@app.route("/convert", methods=["POST"])
def convert_remote():
    if "file" not in request.files: return jsonify({"success": False, "error": "Sin archivo"}), 400
    file = request.files["file"]
    
    username = request.form.get("username", "anon")
    client_id = request.form.get("singleUseClientId", username)
    encoder_type = request.form.get("encoderType", "perceptual")

    if encoder_type not in ENCODER_SCRIPTS: encoder_type = "perceptual"

    print(f"[S4] Job: {username} | Encoder: {encoder_type}")

    # 1. Permiso
    allowed, reason = ask_permission(client_id)
    if not allowed:
        return jsonify({"success": False, "error": reason}), 429

    # 2. Procesamiento
    temp_in = Path(tempfile.mkdtemp(dir=TEMP_INPUT_DIR)) / file.filename
    output_dir = Path(tempfile.mkdtemp(dir=TEMP_OUTPUT_DIR))
    
    try:
        file.save(temp_in)
        base_name = f"{Path(file.filename).stem}_{encoder_type}"
        final_crs = output_dir / f"{base_name}.crs"
        
        # Comando corregido (Sin argumentos fantasmas)
        script = ENCODER_SCRIPTS[encoder_type]
        cmd = [
            sys.executable, str(script),
            str(temp_in), base_name,
            "--crs_dir", str(output_dir),
            "--models_dir", str(MODELS_DIR),
            "--author", "NANO"
        ]
        if encoder_type == "perceptual": cmd.extend(["--fidelity_quality", "0"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0 or not final_crs.exists():
            print(f"[S4] STDERR: {result.stderr[-300:]}")
            raise Exception(f"Fallo IA: {result.stderr[-100:]}")
            
        # 3. Subida (Con diagnóstico detallado)
        ok, msg = upload_result_to_srv1(username, final_crs)
        
        if not ok:
            # Aquí devolvemos el mensaje exacto del error (404, 500, Connection Error)
            return jsonify({"success": False, "error": f"Fallo al guardar: {msg}"}), 502
            
        # 4. Éxito
        report_success({
            "id": uuid.uuid4().hex[:8],
            "username": username,
            "singleUseClientId": client_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "encoderType": encoder_type
        })
        
        return jsonify({"success": True, "message": "Procesado y enviado.", "record": {
            "final_crs_name": final_crs.name,
            "final_size_mb": final_crs.stat().st_size / (1024*1024)
        }}), 200

    except Exception as e:
        print(f"[S4] Fatal: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        try:
            if temp_in.exists(): os.remove(temp_in)
            shutil.rmtree(output_dir, ignore_errors=True)
        except: pass

@app.route("/")
def home(): return "S4 DIAGNOSTIC MODE (ONLINE)", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860)