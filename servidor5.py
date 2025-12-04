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
# 🧠 LÓGICA FORENSE REFINADA (Cero Falsos Positivos)
# ===============================================================

class ForensicReport:
    def __init__(self):
        self.status = "UNKNOWN" # VERIFIED, MANIPULATED, CLEAN
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
    """Intenta desencriptar bytes crudos buscando cabeceras."""
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

# --- NIVEL 1: DETECCIÓN CRIPTOGRÁFICA (FIRMA VÁLIDA) ---
def attempt_crypto_read(img_array) -> dict:
    height, width, _ = img_array.shape
    total_pixels = width * height
    max_pixels_needed = MAX_PAYLOAD_BITS * REDUNDANCY_FACTOR_LSB
    
    if total_pixels == 0: return {"valid": False}
    
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

# --- NIVEL 2: DETECCIÓN DE HUELLAS ROTAS (FORENSE ESTRICTO) ---
def scan_raw_bytes_for_traces(raw_bytes: bytes, report: ForensicReport):
    """
    Busca fragmentos de la tecnología XtremeRTX que sobreviven a compresiones agresivas.
    NO busca píxeles (demasiados falsos positivos). Busca DATOS.
    """
    try:
        # 1. Cabecera Mágica Rota
        # Si encontramos "XRTX_SIG" pero la criptografía falló antes, es MANIPULADO.
        if b"XRTX_SIG" in raw_bytes:
            report.add_evidence("Cabecera 'XRTX_SIG' detectada en estructura profunda (Firma corrupta).", weight=1.0)
        
        # 2. Fragmentos de JSON característicos
        # "idf", "qdna", "api" son las keys que usa tu sistema.
        # En una imagen normal, es muy raro encontrar la secuencia exacta b'"qdna":'
        if b'"qdna":' in raw_bytes or b"'qdna':" in raw_bytes:
            report.add_evidence("Fragmento de metadatos 'qdna' hallado en crudo.", weight=0.8)
            
        if b'"idf":' in raw_bytes and b'"ts":' in raw_bytes:
            report.add_evidence("Estructura de identificación parcial hallada.", weight=0.6)

    except Exception as e:
        pass

# ===============================================================
# 🚀 APLICACIÓN FLASK
# ===============================================================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB Max
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "V Forensic Unit ONLINE", "api_version": "5.5 (Precision)"}), 200

@app.route('/health', methods=['GET'])
def health_check():
    return "FORENSIC ONLINE (S5)", 200

@app.route('/analyze-provenance', methods=['POST'])
def handle_provenance_request():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No se proporcionó el archivo 'file'"}), 400
        
    file = request.files['file']
    
    try:
        # 1. Lectura de Bytes (Para análisis profundo y visual)
        file_bytes = file.read()
        if not file_bytes:
            raise ValueError("Archivo vacío.")
            
        # 2. Inicializar Reporte
        report = ForensicReport()
        
        # 3. Conversión a Imagen para análisis criptográfico visual
        try:
            image = Image.open(io.BytesIO(file_bytes))
            if image.mode != 'RGB':
                image = image.convert('RGB')
            img_array = np.array(image)
        except UnidentifiedImageError:
             raise ValueError("El archivo no es una imagen válida.")

        # --- FASE 1: Criptografía (La prueba de oro) ---
        crypto_res = attempt_crypto_read(img_array)
        
        if crypto_res["valid"]:
            # Si se lee la firma, es auténtico.
            report.status = "VERIFIED"
            report.signature_data = crypto_res["data"]
            report.confidence_score = 10.0
            report.add_evidence(f"Firma criptográfica íntegra (Método: {crypto_res.get('method')})")
        else:
            # --- FASE 2: Búsqueda de Rastros (Si falla cripto) ---
            # Ya NO analizamos píxeles RGB para evitar falsos positivos en fotos oscuras.
            # Solo buscamos huellas de datos (Strings rotos).
            
            scan_raw_bytes_for_traces(file_bytes, report)
            
            # Decisión final basada en evidencias sólidas
            if report.confidence_score >= 0.5:
                # Encontramos trazas de texto XRTX pero no firma válida -> Manipulado
                report.status = "MANIPULATED"
            else:
                # No encontramos nada raro -> Limpio
                report.status = "CLEAN"
                report.confidence_score = 0.0

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
