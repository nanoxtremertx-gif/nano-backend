# --- servidor3.py (V3.9 - FIX DE DESERIALIZACIÓN Y MAPPING DE CLAVES) ---
from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import pickle
import io
import sys

# ===============================================================
# 🧠 LÓGICA DE ANÁLISIS (vcore_analisis)
# ===============================================================

def analyze_crs_from_bytes(file_bytes: bytes) -> dict:
    """
    Lee y analiza los metadatos de un archivo .crs desde sus bytes, 
    con manejo de errores de deserialización más robusto.
    """
    results = {
        "is_encrypted": True,
        
        "public_fingerprint": "No hay dato",
        "creation_date": "No hay dato",
        "version_id": "No hay dato",
        "password_mode": "No hay dato",
        
        "author_q_dna": "No aplica (Encriptado)",
        "creation_module": "No aplica (Encriptado)",
        "fidelity_quality": "No aplica (Encriptado)"
    }

    if not file_bytes:
        raise ValueError("Error: Archivo de entrada vacío o corrupto (0 bytes).")

    try:
        # Intento de deserialización principal
        outer_data = pickle.loads(file_bytes)

    except pickle.UnpicklingError:
        # Error de formato
        raise ValueError("Error de formato: El archivo CRS está corrupto o no es un formato pickle válido.")
        
    except Exception as e:
        # Error de sistema (memoria/recursión)
        sys.stderr.write(f"ERROR CRÍTICO DE PICKLE: {e}\n")
        raise RuntimeError(f"Error de sistema: No se pudo deserializar el archivo.")


    # --- LÓGICA DE EXTRACCIÓN ---
    try:
        results['public_fingerprint'] = outer_data.get('public_author', 'No hay dato')
        results['creation_date'] = outer_data.get('created_at', 'No hay dato')
        results['password_mode'] = outer_data.get('password_mode', 'No hay dato')
        results['version_id'] = outer_data.get('version_id', outer_data.get('version', 'No hay dato'))

        crs_data = None
        
        if isinstance(outer_data, dict) and outer_data.get('is_encrypted', False):
            results['is_encrypted'] = True
        else:
            results['is_encrypted'] = False
            crs_data = outer_data

        if crs_data and isinstance(crs_data, dict):
            results['author_q_dna'] = crs_data.get('author') or crs_data.get('author_id') or 'No hay dato'
            results['fidelity_quality'] = crs_data.get('fidelity_quality', 'No hay dato')
            
            version = str(results['version_id'])
            
            if version.startswith("51.") or "LexiconPaeth" in version:
                results['creation_module'] = "Bit a Bit (Léxico-Paeth)"
            elif "Generalista" in version:
                results['creation_module'] = "Ultra Visual (Generalista)"
            elif "Perceptual" in version or "12.9" in version:
                quality_val = results['fidelity_quality']
                quality_str = f"{quality_val}%" if quality_val != 'No hay dato' else 'No especificada'
                results['creation_module'] = f"Perceptual (Kiphu+Odin, Fidelidad: {quality_str})"
            else:
                results['creation_module'] = "Desconocido (Legacy/Otro)"
        
    except Exception as e:
        # Este error ocurre si la ESTRUCTURA INTERNA no es la esperada (metadatos faltantes)
        raise RuntimeError(f"Error en metadatos internos: {e}")

    return results

# ===============================================================
# 🚀 OBJETO GLOBAL DE LA APLICACIÓN (PARA GUNICORN)
# ===============================================================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 
CORS(app, resources={r"/*": {"origins": "*"}})

# --- RUTAS ---

@app.route('/', methods=['GET'])
def home():
    """Confirma que la aplicación está corriendo en la raíz."""
    return jsonify({"status": "V Core Analyzer ONLINE", "api_version": "3.9"}), 200

@app.route('/health', methods=['GET'])
def health_check():
    return "ANALYZER ONLINE (S3)", 200

@app.route('/analyze-crs-metadata', methods=['POST'])
def handle_analysis_request():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No se proporcionó el archivo 'file'"}), 400
        
    file = request.files['file']
    
    try:
        file_bytes = file.read()
        results = analyze_crs_from_bytes(file_bytes)
        
        # --- Mapear la salida del análisis a las claves que el frontend espera ---
        
        # 1. Limpieza de datos encriptados
        is_encrypted = results['is_encrypted']
        if is_encrypted:
            q_dna = None
            creation_module = "Encriptado"
            fidelity_quality = None
        else:
            q_dna = results.get('author_q_dna')
            creation_module = results['creation_module']
            fidelity_quality = results.get('fidelity_quality')

        # 2. Devolver la respuesta con el mapeo EXACTO del frontend
        return jsonify({
            "success": True, 
            "analysis": {
                # MAPPING CRÍTICO para misarchivos.jsx:
                "id_fingerprint": results['public_fingerprint'], 
                "q_dna": q_dna,               
                "technical_version": results['version_id'],      
                "is_encrypted": is_encrypted,
                "creation_module": creation_module,
                "fidelity_quality": fidelity_quality
            }
        }), 200
        
    except ValueError as e:
        # Error de archivo corrupto o vacío (reporte 406)
        sys.stderr.write(f"ERROR 406: {e}\n")
        return jsonify({"success": False, "error": str(e)}), 406
    
    except RuntimeError as e:
        # Error de estructura interna (reporte 500)
        sys.stderr.write(f"ERROR 500: {e}\n")
        return jsonify({"success": False, "error": f"Falla Interna del Analizador: {str(e)}"}), 500
    
    except Exception as e:
        # Cualquier otra excepción no capturada
        sys.stderr.write(f"ERROR INESPERADO: {e}\n")
        return jsonify({"success": False, "error": "Error inesperado en el servidor."}), 500
