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

# Directorios de Inteligencia (Teletransportados por Docker)
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
    print(f"⚠️  ADVERTENCIA CRÍTICA: No se encuentran los modelos en: {MODELS_DIR}")
    print("Asegúrate de que Git LFS funcionó en el Dockerfile.")

# ===============================================================
# 🧠 COMUNICACIÓN CON EL CEREBRO (Srv1)
# ===============================================================

def ask_permission(client_id):
    """Pregunta a Srv1 si este usuario puede convertir (Cooldown)."""
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/check-permission"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY, "Content-Type": "application/json"}
        payload = {"singleUseClientId": client_id}
        
        print(f"[S4] Consultando permiso a Srv1...")
        resp = requests.post(url, json=payload, headers=headers, timeout=15)
        
        if resp.status_code == 200:
            data = resp.json()
            return data.get("allow", False), data.get("reason", "Desconocido")
        elif resp.status_code == 404:
            # Si Srv1 no tiene la ruta, permitimos por defecto para no romper flujo (opcional)
            return False, "Srv1 no compatible (404)."
        return False, f"Error Srv1: {resp.status_code}"
    except Exception as e:
        print(f"[ERROR CONEXIÓN SRV1] {e}")
        return False, "Error de conexión con el Servidor Maestro"

def upload_result_to_srv1(username, file_path):
    """Sube el archivo final a la base de datos de Srv1."""
    if not file_path.exists(): return False
    
    print(f"[S4] Subiendo {file_path.name} a {SRV1_URL}...")
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/upload-file"
        
        # Srv1 espera: file, userId, parentId, verificationStatus
        payload = {
            "userId": username,
            "parentId": "null", 
            "verificationStatus": "verified_nano_quantum" # Marca de agua en DB
        }
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            resp = requests.post(url, data=payload, files=files, timeout=300)
            
        if 200 <= resp.status_code < 300:
            return True
        else:
            print(f"[S4] Fallo subida. Código: {resp.status_code}. Resp: {resp.text}")
            return False
    except Exception as e:
        print(f"[S4] Excepción al subir: {e}")
        return False

def report_success(record):
    """Envía el registro de éxito a Srv1 para activar el cooldown."""
    try:
        url = f"{SRV1_URL.rstrip('/')}/api/worker/log-success"
        headers = {"X-Admin-Key": SRV1_MASTER_KEY, "Content-Type": "application/json"}
        requests.post(url, json=record, headers=headers, timeout=10)
    except: pass

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
    client_id = request.form.get("singleUseClientId", username)
    encoder_type = request.form.get("encoderType", "perceptual") # Predeterminado: perceptual

    # Validación de encoder
    if encoder_type not in ENCODER_SCRIPTS: 
        print(f"[S4] Encoder '{encoder_type}' no existe. Forzando perceptual.")
        encoder_type = "perceptual"

    print(f"[S4] Job: {username} | Encoder: {encoder_type}")

    # 2. Consultar al Jefe (Srv1)
    allowed, reason = ask_permission(client_id)
    if not allowed:
        print(f"[S4] Denegado: {reason}")
        return jsonify({"success": False, "error": reason}), 429

    # 3. Preparar Archivos
    temp_in = Path(tempfile.mkdtemp(dir=TEMP_INPUT_DIR)) / file.filename
    output_dir = Path(tempfile.mkdtemp(dir=TEMP_OUTPUT_DIR))
    
    try:
        file.save(temp_in)
        
        base_name = f"{Path(file.filename).stem}_{encoder_type}"
        final_crs = output_dir / f"{base_name}.crs"
        
        # 4. Configurar Comando (NANO FORZADO)
        script = ENCODER_SCRIPTS[encoder_type]
        cmd = [
            sys.executable, str(script),
            str(temp_in), base_name,
            "--crs_dir", str(output_dir),
            "--models_dir", str(MODELS_DIR),
            # --- FIRMAS DE AUTORIDAD ---
            "--author", "NANO",
            "--fingerprint", "NANO",
            "--qdna", "NANO"
        ]
        
        # Si es perceptual, forzar calidad 0
        if encoder_type == "perceptual":
            cmd.extend(["--fidelity_quality", "0"])

        print(f"[S4] Ejecutando IA...")
        
        # 5. Ejecutar (Timeout 10 min por si acaso)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0 or not final_crs.exists():
            print(f"[S4] Error STDERR: {result.stderr[-400:]}")
            raise Exception("Error crítico en el Encoder de IA.")
            
        # 6. Entregar al Jefe
        upload_ok = upload_result_to_srv1(username, final_crs)
        
        if not upload_ok:
            return jsonify({"success": False, "error": "Conversión lista, pero falló la conexión con Srv1 para guardar el archivo."}), 502
            
        # 7. Reportar Misión Cumplida
        report_success({
            "id": uuid.uuid4().hex[:8],
            "username": username,
            "singleUseClientId": client_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "encoderType": encoder_type
        })
        
        return jsonify({"success": True, "message": "Procesado y enviado."}), 200

    except Exception as e:
        print(f"[S4] Error Fatal: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        # Limpieza Brutal
        try:
            if temp_in.exists(): os.remove(temp_in)
            shutil.rmtree(output_dir, ignore_errors=True)
        except: pass

@app.route("/")
def home():
    return "NANO WORKER S4 (ONLINE)", 200

# ===============================================================
# 🚀 MAIN (Puerto 7860 para HF)
# ===============================================================
if __name__ == "__main__":
    print("-" * 50)
    print("🚀 SERVIDOR 4 (WORKER) - HUGGING FACE EDITION")
    print(f"📡 Maestro: {SRV1_URL}")
    print(f"🛠️  Puerto: 7860")
    print("-" * 50)
    app.run(host="0.0.0.0", port=7860)
