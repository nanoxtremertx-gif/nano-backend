# servidor5.py (v5.1 - Actualizado con Sherlock v6.0 Sniper Mode)
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

# --- TOLERANCIAS SHERLOCK v6.0 (Modo Sniper) ---
# Sintonizado para ignorar ruido JPEG natural pero atrapar residuos aislados
TOL_DARK_RANGE = (2, 25)    
TOL_LIGHT_RANGE = (230, 254)
TOL_COLOR_VARIANCE = 15     
MIN_NEIGHBOR_CONTRAST = 10  # Umbral CRÍTICO para el filtro de aislamiento

# ===============================================================
# 🧠 LÓGICA FORENSE (SHERLOCK V6.0)
# ===============================================================

class ForensicReport:
    def __init__(self):
        self.status = "UNKNOWN" # VERIFIED, MANIPULATED, CLEAN, TRACE
        self.signature_data = {}
        self.forensic_evidence = []
        self.confidence_score = 0.0
        self.pixels_found = 0

    def add_evidence(self, message, weight=0.0):
        self.forensic_evidence.append(message)
        self.confidence_score += weight
        if self.confidence_score > 100.0: self.confidence_score = 100.0

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
    
    constellation = _get_pixel_constellation(HUELLA_SECRET_KEY, width, height, min(max_pixels_needed, total_pixels))

    # 1. Intento LSB
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
    
    try:
        bytes_lsb = int(bits_lsb, 2).to_bytes((len(bits_lsb) + 7) // 8, byteorder='big')
        res_lsb = _extract_and_decrypt(bytes_lsb)
        if res_lsb["valid"]: return {"valid": True, "method": "LSB (Invisible)", "data": res_lsb["data"]}
    except: pass

    # 2. Intento Contraste
    bits_con = ""
    for x, y in constellation:
        val = img_array[y, x, 2]
        if val >= 240: bits_con += '1'
        elif val <= 15: bits_con += '0'
        else: break 
        
    try:
        if len(bits_con) > 80:
            bytes_con = int(bits_con, 2).to_bytes((len(bits_con) + 7) // 8, byteorder='big')
            res_con = _extract_and_decrypt(bytes_con)
            if res_con["valid"]: return {"valid": True, "method": "Alto Contraste (Visible)", "data": res_con["data"]}
    except: pass

    return {"valid": False}

# --- NIVEL 2: ESCÁNER DE RESIDUOS INTELIGENTE (SNIPER MODE) ---
def scan_smart_residuals(img_array, report: ForensicReport):
    """
    Busca píxeles aislados (Puntillismo Artificial) aplicando el Filtro de Aislamiento.
    Evita falsos positivos de sombras naturales.
    """
    h, w, channels = img_array.shape
    # Trabajar con int16 para evitar desbordamiento en restas
    img_signed = img_array.astype(np.int16)
    R, G, B = img_signed[:,:,0], img_signed[:,:,1], img_signed[:,:,2]

    # 1. Filtro de Color (Candidatos Grisáceos y en Rango)
    color_mask = (np.abs(R - G) <= TOL_COLOR_VARIANCE) & \
                 (np.abs(G - B) <= TOL_COLOR_VARIANCE) & \
                 (np.abs(R - B) <= TOL_COLOR_VARIANCE)

    val_mask_dark = (G >= TOL_DARK_RANGE[0]) & (G <= TOL_DARK_RANGE[1])
    val_mask_light = (G >= TOL_LIGHT_RANGE[0]) & (G <= TOL_LIGHT_RANGE[1])
    
    candidates_mask = color_mask & (val_mask_dark | val_mask_light)
    y_idxs, x_idxs = np.where(candidates_mask)
    
    confirmed_artifacts = 0
    strict_mode = len(y_idxs) > 5000 
    
    # 2. Filtro de Aislamiento Espacial (Sniper)
    for i in range(len(y_idxs)):
        y, x = y_idxs[i], x_idxs[i]
        
        # Ignorar bordes extremos
        if y <= 1 or y >= h-2 or x <= 1 or x >= w-2: continue
        
        center_val = np.mean(img_signed[y, x])
        
        # Vecinos (Arriba, Abajo, Izq, Der)
        neighbors = [
            np.mean(img_signed[y-1, x]), 
            np.mean(img_signed[y+1, x]), 
            np.mean(img_signed[y, x-1]), 
            np.mean(img_signed[y, x+1])
        ]
        
        is_isolated = True
        similarity_count = 0
        effective_threshold = MIN_NEIGHBOR_CONTRAST + (10 if strict_mode else 0)

        for n_val in neighbors:
            # Si la diferencia es pequeña, es un vecino "amigo" (parte de la misma mancha/sombra)
            if abs(center_val - n_val) < effective_threshold:
                similarity_count += 1
        
        # Si se parece a 2 o más vecinos, es natural (sombra/mancha) -> DESCARTAR
        if similarity_count >= 2:
            is_isolated = False
            
        if is_isolated:
            confirmed_artifacts += 1

    report.pixels_found = confirmed_artifacts

    if confirmed_artifacts > 0:
        # REGLA DEL 0.9%
        prob = confirmed_artifacts * 0.9
        
        report.add_evidence(f"Puntillismo Aislado Detectado: {confirmed_artifacts} píxeles artificiales.", prob)
        
        if confirmed_artifacts < 5:
            report.add_evidence("⚠️ Traza Mínima: Posible residuo de limpieza profunda.", 0)
        elif confirmed_artifacts > 50:
            report.add_evidence("🔴 Patrón Disperso: Alta probabilidad de imagen Evoker manipulada.", 0)

# --- NIVEL 3: DETECCIÓN DE STRINGS ROTOS (RAW) ---
def scan_raw_bytes(raw_bytes: bytes, report: ForensicReport):
    try:
        # Solo escaneamos el inicio para no sobrecargar en archivos gigantes
        chunk = raw_bytes[:4096] 
        if b"XRTX_SIG" in chunk:
            report.add_evidence("Fragmento de cabecera 'XRTX_SIG' hallado en crudo.", weight=20.0)
        elif b"XRTX" in chunk:
            report.add_evidence("Fragmento 'XRTX' hallado en crudo.", weight=5.0)
            
        if b"idf" in chunk and b"qdna" in chunk:
            report.add_evidence("Estructura JSON de autoría en metadatos.", weight=10.0)
                
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
    return jsonify({"status": "V Forensic Unit ONLINE", "api_version": "5.1 (Sherlock Sniper)"}), 200

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

        # --- FASE 1: Criptografía (Intento Maestro) ---
        crypto_res = attempt_crypto_read(img_array)
        
        if crypto_res["valid"]:
            report.status = "VERIFIED"
            report.confidence_score = 100.0
            report.signature_data = crypto_res["data"]
            report.add_evidence(f"Firma criptográfica válida hallada (Método: {crypto_res.get('method')})", weight=0.0)
        else:
            # --- FASE 2: Forense Sherlock (Si falla criptografía) ---
            # Aquí es donde se ejecuta el escáner "Sniper"
            scan_smart_residuals(img_array, report)
            scan_raw_bytes(file_bytes, report)
            
            # Decisión final basada en la puntuación
            if report.confidence_score >= 80:
                report.status = "MANIPULATED"
            elif report.confidence_score > 0:
                report.status = "TRACE"
            else:
                report.status = "CLEAN"

        # 4. Construir Respuesta JSON
        response = {
            "success": True,
            "report": {
                "status": report.status,
                "confidence_score": round(report.confidence_score, 2),
                "pixels_found": report.pixels_found, # Dato para debug
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
    # Puerto cambiado a 7860 como en la versión anterior
    app.run(host='0.0.0.0', port=7860)
