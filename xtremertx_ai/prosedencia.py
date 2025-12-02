# procedencia_forense.py (v3.0 - Analizador Sherlock: Detección de Blanqueo y Recorte)
import sys
import os
from PIL import Image, UnidentifiedImageError
import numpy as np
import base64
import json
import hashlib
import random
from cryptography.fernet import Fernet
import argparse
from pathlib import Path

# --- CONSTANTES DE SEGURIDAD (Deben coincidir con Evoker) ---
HUELLA_SECRET_KEY = b'p2s5v8y/B?E(H+MbQeThWmZq4t7w!z$C'
MAGIC_HEADER = "XRTX_SIG::"
TERMINATOR = "::END_SIG"
REDUNDANCY_FACTOR_LSB = 3
MAX_PAYLOAD_BITS = 1500 

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
        # Si es gris medio, rompemos (firma rota)
        else: break 
        
    try:
        if len(bits_con) > 80: # Mínimo de bits para considerar
            bytes_con = int(bits_con, 2).to_bytes((len(bits_con) + 7) // 8, byteorder='big')
            res_con = _extract_and_decrypt(bytes_con)
            if res_con["valid"]: return {"valid": True, "method": "Alto Contraste (Visible)", "data": res_con["data"]}
    except: pass

    return {"valid": False}

# --- NIVEL 2: DETECCIÓN DE RESIDUOS (FORENSE) ---
def analyze_artifacts(img_array, report: ForensicReport):
    """
    Busca huellas estadísticas de manipulación.
    Evoker firma con valores RGB exactos (ej. 10,10,10 o 245,245,245).
    Una imagen natural o comprimida tiene ruido (ej. 10,11,9).
    Si encontramos muchos píxeles 'planos' en esos valores, es una firma rota por recorte.
    """
    height, width, channels = img_array.shape
    total_pixels = height * width
    
    # Buscar píxeles "Evoker Dark" (R=G=B alrededor de 10)
    # Tolerancia estricta: R, G y B deben ser IGUALES (característica de firma Evoker v59)
    # y estar en el rango de firma.
    
    # Máscara para píxeles oscuros de firma (aprox 10)
    mask_dark = (img_array[:,:,0] >= 8) & (img_array[:,:,0] <= 12) & \
                (img_array[:,:,1] >= 8) & (img_array[:,:,1] <= 12) & \
                (img_array[:,:,2] >= 8) & (img_array[:,:,2] <= 12) & \
                (img_array[:,:,0] == img_array[:,:,1]) & (img_array[:,:,1] == img_array[:,:,2])

    # Máscara para píxeles claros de firma (aprox 245)
    mask_light = (img_array[:,:,0] >= 243) & (img_array[:,:,0] <= 247) & \
                 (img_array[:,:,1] >= 243) & (img_array[:,:,1] <= 247) & \
                 (img_array[:,:,2] >= 243) & (img_array[:,:,2] <= 247) & \
                 (img_array[:,:,0] == img_array[:,:,1]) & (img_array[:,:,1] == img_array[:,:,2])

    count_dark = np.sum(mask_dark)
    count_light = np.sum(mask_light)
    total_suspicious = count_dark + count_light

    # Umbral heurístico: Una foto natural 4K no suele tener 500 píxeles que sean EXACTAMENTE R=G=B=10
    # a menos que sea muy oscura y sintética. Evoker inyecta cientos.
    
    ratio = total_suspicious / total_pixels
    
    if total_suspicious > 50: # Mínimo absoluto para sospechar
        msg = f"Detectados {total_suspicious} píxeles con patrón sintético XtremeRTX (R=G=B en rangos de firma)."
        report.add_evidence(msg, weight=0.6)
        
        if count_dark > 0 and count_light > 0:
             report.add_evidence("Presencia bimodal de artefactos (Claros y Oscuros), típico de firma binaria rota.", weight=0.3)

    return

# --- NIVEL 3: DETECCIÓN DE STRINGS ROTOS (RAW) ---
def scan_raw_bytes(file_path, report: ForensicReport):
    try:
        with open(file_path, "rb") as f:
            raw = f.read()
            
            # Buscar cabecera mágica rota
            if b"XRTX_SIG" in raw:
                report.add_evidence("Fragmento de cabecera 'XRTX_SIG' hallado en crudo. (Intento de firma confirmado).", weight=1.0)
            elif b"XRTX" in raw:
                report.add_evidence("Fragmento 'XRTX' hallado en crudo.", weight=0.4)
                
            # Buscar JSON keys comunes en payloads desencriptados que a veces quedan en caché de metadatos
            if b"idf" in raw and b"qdna" in raw:
                report.add_evidence("Estructura de payload JSON detectada en metadatos.", weight=0.5)
                
    except Exception as e:
        report.add_evidence(f"No se pudo leer raw bytes: {e}", weight=0.0)

# --- MOTOR PRINCIPAL ---
def forensic_analysis(file_path: Path):
    print(f"🔎 INICIANDO ANÁLISIS FORENSE: {file_path.name}")
    report = ForensicReport()
    
    try:
        image = Image.open(file_path)
        img_array = np.array(image.convert('RGB'))
    except Exception as e:
        print(f"❌ Error fatal: No es una imagen válida ({e})")
        return

    # 1. Prueba Criptográfica (La ideal)
    crypto_res = attempt_crypto_read(img_array)
    
    if crypto_res["valid"]:
        report.status = "VERIFIED"
        report.signature_data = crypto_res["data"]
        report.add_evidence(f"Firma criptográfica válida hallada método: {crypto_res['method']}", weight=10.0)
    else:
        # Si falló la criptografía, entramos en modo SHERLOCK
        print("⚠️  Firma ilegible por métodos estándar. Iniciando escaneo de residuos...")
        
        # 2. Análisis de Píxeles (Detectar recorte/compresión)
        analyze_artifacts(img_array, report)
        
        # 3. Análisis de Bytes (Detectar metadatos supervivientes)
        scan_raw_bytes(file_path, report)
        
        # CONCLUSIÓN BASADA EN EVIDENCIA
        if report.confidence_score >= 0.9:
            report.status = "MANIPULATED"
        elif report.confidence_score > 0.3:
            report.status = "SUSPICIOUS"
        else:
            report.status = "CLEAN"

    # --- INFORME FINAL ---
    print("\n" + "="*40)
    print(f"INFORME FORENSE: {file_path.name}")
    print("="*40)
    
    if report.status == "VERIFIED":
        print("✅ ESTADO: AUTÉNTICO (Firma Íntegra)")
        d = report.signature_data
        print(f"   👤 Autor ID : {d.get('idf')}")
        print(f"   🧬 ADN Q    : {d.get('qdna')}")
        print(f"   🛠️ API      : {d.get('api')}")
        
    elif report.status == "MANIPULATED":
        print("🚫 ESTADO: MANIPULADO / FIRMA ROTA")
        print("   DIAGNOSTICO: El archivo contiene restos innegables de tecnología XtremeRTX,")
        print("                pero la integridad de la firma fue destruida.")
        print("\n   🔍 Evidencia encontrada:")
        for ev in report.forensic_evidence:
            print(f"   - {ev}")
        print("\n   ⚠️  Causa probable: Recorte (Crop), Redimensionado o Compresión agresiva.")
        print("       La autoría original no puede leerse, pero el origen es XtremeRTX.")
        
    elif report.status == "SUSPICIOUS":
        print("🤔 ESTADO: SOSPECHOSO (Indicios Débiles)")
        print("   DIAGNOSTICO: Algunos patrones coinciden, pero no son concluyentes.")
        print("\n   🔍 Indicios:")
        for ev in report.forensic_evidence:
            print(f"   - {ev}")
            
    else:
        print("⚪ ESTADO: LIMPIO / EXTERNO")
        print("   No se detectaron firmas ni residuos de tecnología XtremeRTX.")
        print("   El archivo parece ser una imagen estándar o fue 'blanqueado' perfectamente.")
        
    print("="*40 + "\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="XtremeRTX Forensics v3.0")
    parser.add_argument("image_file", type=Path, help="Archivo a analizar")
    args = parser.parse_args()

    if args.image_file.is_file():
        forensic_analysis(args.image_file)
        if len(sys.argv) > 1:
            try: input("Presiona Enter para cerrar...")
            except: pass
    else:
        print("Archivo no encontrado.")
