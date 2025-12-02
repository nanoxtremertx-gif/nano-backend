from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os
import io
import numpy as np
import base64
import json
import hashlib
import random
from PIL import Image, UnidentifiedImageError
from cryptography.fernet import Fernet

# ===============================================================
# 🔐 CONSTANTES DE SEGURIDAD Y CONFIGURACIÓN
# ===============================================================

HUELLA_SECRET_KEY = b'p2s5v8y/B?E(H+MbQeThWmZq4t7w!z$C'
MAGIC_HEADER = "XRTX_SIG::"
TERMINATOR = "::END_SIG"
REDUNDANCY_FACTOR_LSB = 3
MAX_PAYLOAD_BITS = 1500 

# ===============================================================
# 🧠 LÓGICA FORENSE (Adaptada de procedencia_forense.py)
# ===============================================================

class ForensicReport:
    def __init__(self):
        self.status = "UNKNOWN" # VERIFIED, MANIPULATED, CLEAN, SUSPICIOUS
        self.signature_data = {}
        self.forensic_evidence = []
        self.confidence_score = 0.0

    def add_evidence(self, message, weight=0.0):
        self.forensic_evidence.append(message)
        self.confidence_score += weight

def _get_pixel_constellation(seed_key: bytes, width: int, height: int, count: int) -> list:
    seed = hashlib.sha256(seed_key).hexdigest()
    rng = random.Random(seed)
    indices = list(range(width * height))
    rng.shuffle(indices)
    count = min(count, len(indices))
    coordinates = [(i % width, i // width) for i in indices[:count]]
    return coordinates

def _extract_and_decrypt(read_data_bytes: bytes) -> dict:
    """Intenta desencriptar bytes crudos."""
    results = {"valid": False}
    header_bytes = MAGIC_HEADER.encode('utf-8')
    terminator_bytes = TERMINATOR.encode('utf-8')
    
    start_index = read_data_bytes.find(header_bytes)
    if start_index != -1:
        end_index = read_data_bytes.find(terminator_bytes, start_index + len(header_bytes))
        if end_index != -1:
            try:
                start_payload = start_index + len(header_bytes)
                encrypted_payload = read_data_bytes[start_payload:end_index]
                fernet = Fernet(base64.urlsafe_b64encode(HUELLA_SECRET_KEY))
                decrypted_payload = fernet.decrypt(encrypted_payload)
                payload = json.loads(decrypted_payload.decode('utf-8'))
                results["valid"] = True
                results["data"] = payload
            except:
                pass
    return results

# --- NIVEL 1: DETECCIÓN CRIPTOGRÁFICA (ESTRICTA) ---
def attempt_crypto_read(img_array) -> dict:
    height, width, _ = img_array.shape
    total_pixels = width * height
    max_pixels_needed = MAX_PAYLOAD_BITS * REDUNDANCY_FACTOR_LSB
    
    if total_pixels == 0: return {"valid": False}
    
    # Generar constelación basada en dimensiones actuales
    constellation = _get_pixel_constellation(HUELLA_SECRET_KEY, width, height, min(max_pixels_needed, total_pixels))

    # 1. Intento LSB (v58)
    bits_lsb = ""
    readable_bits = len(constellation) // REDUNDANCY_FACTOR_LSB
    for i in range(readable_bits):
        votes = 0
        for r in range(REDUNDANCY_FACTOR_LSB):
            idx = i * REDUNDANCY_FACTOR_LSB + r
            if idx < len(constellation):
                x, y = constellation[idx]
                if (img_array[y, x, 2] & 1) == 1: votes += 1
        bits_lsb += '1' if votes >= 2 else '0'
    
    # Convertir y probar
    try:
        bytes_lsb = int(bits_lsb, 2).to_bytes((len(bits_lsb) + 7) // 8, byteorder='big')
        res_lsb = _extract_and_decrypt(bytes_lsb)
        if res_lsb["valid"]: return {"valid": True, "method": "LSB (Invisible)", "data": res_lsb["data"]}
    except: pass

    # 2. Intento Contraste (v57)
    bits_con = ""
    for x, y in constellation:
        val = img_array[y, x, 2]
        if val > 230: bits_con += '1'
        elif val < 25: bits_con += '0'
        else: break 
        
    try:
        if len(bits_con) > 80:
            bytes_con = int(bits_con, 2).to_bytes((len(bits_con) + 7) // 8, byteorder='big')
            res_con = _extract_and_decrypt(bytes_con)
            if res_con["valid"]: return {"valid": True, "method": "Alto Contraste (Visible)", "data": res_con["data"]}
    except: pass

    return {"valid": False}

# --- NIVEL 2: DETECCIÓN DE RESIDUOS (FORENSE) ---
def analyze_artifacts(img_array, report: ForensicReport):
    height, width, channels = img_array.shape
    total_pixels = height * width
    
    mask_dark = (img_array[:,:,0] >= 8) & (img_array[:,:,0] <= 12) & \
                (img_array[:,:,1] >= 8) & (img_array[:,:,1] <= 12) & \
                (img_array[:,:,2] >= 8) & (img_array[:,:,2] <= 12) & \
                (img_array[:,:,0] == img_array[:,:,1]) & (img_array[:,:,1] == img_array[:,:,2])

    mask_light = (img_array[:,:,0] >= 243) & (img_array[:,:,0] <= 247) & \
                 (img_array[:,:,1] >= 243) & (img_array[:,:,1] <= 247) & \
                 (img_array[:,:,2] >= 243) & (img_array[:,:,2] <= 247) & \
                 (img_array[:,:,0] == img_array[:,:,1]) & (img_array[:,:,1] == img_array[:,:,2])

    count_dark = np.sum(mask_dark)
    count_light = np.sum(mask_light)
    total_suspicious = count_dark + count_light
    
    if total_suspicious > 50:
        msg = f"Detectados {total_suspicious} píxeles con patrón sintético XtremeRTX (R=G=B en rangos de firma)."
        report.add_evidence(msg, weight=0.6)
        if count_dark > 0 and count_light > 0:
             report.add_evidence("Presencia bimodal de artefactos (Claros y Oscuros), típico de firma binaria rota.", weight=0.3)

# --- NIVEL 3: DETECCIÓN DE STRINGS ROTOS (RAW) ---
def scan_raw_bytes(raw_bytes: bytes, report: ForensicReport):
    try:
        if b"XRTX_SIG" in raw_bytes:
            report.add_evidence("Fragmento de cabecera 'XRTX_SIG' hallado en crudo. (Intento de firma confirmado).", weight=1.0)
        elif b"XRTX" in raw_bytes:
            report.add_evidence("Fragmento 'XRTX' hallado en crudo.", weight=0.4)
            
        if b"idf" in raw_bytes and b"qdna" in raw_bytes:
            report.add_evidence("Estructura de payload JSON detectada en metadatos.", weight=0.5)
                
    except Exception as e:
        report.add_evidence(f"No se pudo leer raw bytes: {e}", weight=0.0)

# ===============================================================
# 🚀 APLICACIÓN FLASK (SERVER 5)
# ===============================================================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB Max
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "V Forensic Unit ONLINE", "api_version": "5.0 (Sherlock)"}), 200

@app.route('/health', methods=['GET'])
def health_check():
    return "FORENSIC ONLINE (S5)", 200

@app.route('/analyze-provenance', methods=['POST'])
def handle_provenance_request():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No se proporcionó el archivo 'file'"}), 400
        
    file = request.files['file']
    
    try:
        # 1. Lectura de Bytes
        file_bytes = file.read()
        if not file_bytes:
            raise ValueError("Archivo vacío.")
            
        # 2. Inicializar Reporte
        report = ForensicReport()
        
        # 3. Conversión a Imagen para análisis visual
        try:
            image = Image.open(io.BytesIO(file_bytes))
            if image.mode != 'RGB':
                image = image.convert('RGB')
            img_array = np.array(image)
        except UnidentifiedImageError:
             raise ValueError("El archivo no es una imagen válida.")

        # --- FASE 1: Criptografía ---
        crypto_res = attempt_crypto_read(img_array)
        
        if crypto_res["valid"]:
            report.status = "VERIFIED"
            report.signature_data = crypto_res["data"]
            report.add_evidence(f"Firma criptográfica válida hallada (Método: {crypto_res.get('method')})", weight=10.0)
        else:
            # --- FASE 2: Forense (Si falla criptografía) ---
            analyze_artifacts(img_array, report)
            scan_raw_bytes(file_bytes, report) # Pasamos bytes originales
            
            # Decisión final
            if report.confidence_score >= 0.9:
                report.status = "MANIPULATED"
            elif report.confidence_score > 0.3:
                report.status = "SUSPICIOUS"
            else:
                report.status = "CLEAN"

        # 4. Construir Respuesta JSON
        response = {
            "success": True,
            "report": {
                "status": report.status,
                "confidence_score": round(report.confidence_score, 2),
                "evidence_log": report.forensic_evidence,
                "signature_data": report.signature_data if report.status == "VERIFIED" else None
            }
        }
        
        return jsonify(response), 200

    except ValueError as e:
        sys.stderr.write(f"ERROR 406: {e}\n")
        return jsonify({"success": False, "error": str(e)}), 406
    
    except Exception as e:
        sys.stderr.write(f"ERROR 500: {e}\n")
        return jsonify({"success": False, "error": f"Error Forense Interno: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860)