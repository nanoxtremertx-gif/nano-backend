# servidor3.py (v1.3 - Estandarizado con todos los Metadatos)
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import sys
import os
import io

# --- 1. Inicialización del servidor Flask ---
app = Flask(__name__)
# Permite CUALQUIER origen para CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# --- 2. Lógica de Análisis (Adaptada para funcionar desde un stream en memoria) ---
def analyze_crs_from_stream(file_stream) -> dict:
    """
    Lee y analiza los metadatos de un archivo .crs desde un stream.
    Retorna un diccionario con los resultados.
    """
    results = {
        "is_encrypted": True, # Asumimos cifrado hasta que se demuestre lo contrario
        
        # Metadatos Públicos (Capa exterior)
        "public_fingerprint": "No hay dato",
        "creation_date": "No hay dato",
        "version_id": "No hay dato",
        "password_mode": "No hay dato",
        
        # Metadatos Sensibles/Internos (Debe ser extraído del bloque de datos o puesto en No aplica)
        "author_q_dna": "No aplica (Encriptado)",
        "creation_module": "No aplica (Encriptado)",
        "fidelity_quality": "No aplica (Encriptado)"
    }

    try:
        # Cargamos los datos del stream (Capa exterior)
        outer_data = pickle.load(file_stream)

        # 1. Extracción de Metadatos Públicos
        results['public_fingerprint'] = outer_data.get('public_author', 'No hay dato')
        results['creation_date'] = outer_data.get('created_at', 'No hay dato')
        results['password_mode'] = outer_data.get('password_mode', 'No hay dato')
        
        # Intentamos obtener la versión de la capa exterior o interior
        results['version_id'] = outer_data.get('version_id', outer_data.get('version', 'No hay dato'))

        crs_data = None
        
        # 2. Verificar Cifrado
        if isinstance(outer_data, dict) and outer_data.get('is_encrypted', False):
            results['is_encrypted'] = True
        else:
            results['is_encrypted'] = False
            crs_data = outer_data # Los datos internos son el objeto principal

        # 3. Procesar Metadatos Internos (Solo si NO está encriptado)
        if crs_data and isinstance(crs_data, dict):
            # Q-DNA / Autor Interno
            results['author_q_dna'] = crs_data.get('author') or crs_data.get('author_id') or 'No hay dato'
            
            # Calidad de Fidelidad (Solo Perceptual y Legacy la tienen explícitamente)
            results['fidelity_quality'] = crs_data.get('fidelity_quality', 'No hay dato')
            
            # Determinación del Módulo de Creación (Basado en version_id)
            version = str(results['version_id'])
            
            if version.startswith("51.") or "LexiconPaeth" in version:
                results['creation_module'] = "Bit a Bit (Léxico-Paeth)"
            elif "Generalista" in version:
                results['creation_module'] = "Ultra Visual (Generalista)"
            elif "Perceptual" in version or "12.9" in version:
                results['creation_module'] = f"Perceptual (Kiphu+Odin, Fidelidad: {results['fidelity_quality']}%)"
            else:
                results['creation_module'] = "Desconocido (Legacy/Otro)"
        
        elif results['is_encrypted']:
            # Ajustar los campos internos a "Encriptado" si la clave is_encrypted es True
            results['author_q_dna'] = "No aplica (Encriptado)"
            results['creation_module'] = "No aplica (Encriptado)"
            results['fidelity_quality'] = "No aplica (Encriptado)"
            
    except pickle.UnpicklingError:
        raise ValueError("Archivo CRS corrupto o no es un formato pickle válido.")
    except Exception as e:
        print(f"Fallo crítico interno: {e}", file=sys.stderr)
        raise RuntimeError(f"Fallo crítico al leer el archivo.")

    return results

# --- 3. Definición de la Ruta de la API (/analyze-crs-metadata) ---
@app.route('/analyze-crs-metadata', methods=['POST'])
def handle_crs_analysis():
    # ... (El código de la ruta HTTP se mantiene igual, llamando a analyze_crs_from_stream)
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No se ha enviado ningún archivo."}), 400
    file = request.files['file']
    if file.filename == '' or not file.filename.lower().endswith('.crs'):
        return jsonify({"success": False, "error": "Archivo no válido. Se esperaba un archivo .crs."}), 400

    try:
        analysis_results = analyze_crs_from_stream(file.stream)
        return jsonify({"success": True, **analysis_results}), 200

    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except RuntimeError as re:
        return jsonify({"success": False, "error": str(re)}), 500
    except Exception as e:
        print(f"Error fatal no manejado: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": "Fallo interno y crítico del servidor."}), 500


# --- 4. Ruta de Salud (Health Check) ---
@app.route('/')
def health_check():
    return jsonify({"status": "Servidor 3 ONLINE", "role": "Análisis CRS v1.3"}), 200

# ¡FIN DEL ARCHIVO! (Asumimos que el bloque de inicio local fue eliminado de GitHub)
