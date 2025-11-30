# servidor3.py (v1.3 - FIX DE BLOQUEO DE PICKLE)
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import sys
import io

# --- 1. Inicialización del servidor Flask ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- 2. Lógica de Análisis (Acepta bytes en memoria) ---
def analyze_crs_from_bytes(file_bytes) -> dict:
    """
    Lee y analiza los metadatos de un archivo .crs desde un buffer de bytes.
    """
    results = {
        "id_fingerprint": "No disponible",
        "q_dna": "No disponible",
        "creation_module": "Desconocido",
        "technical_version": "No disponible",
        "is_encrypted": False
    }

    try:
        # FIX CRÍTICO: Usar pickle.loads para deserializar bytes en memoria
        outer_data = pickle.loads(file_bytes)

        # 1. Extracción de Fingerprint de nivel superior
        results['id_fingerprint'] = outer_data.get('public_author', 'No disponible')
        crs_data = None

        # 2. Verificar Cifrado
        if isinstance(outer_data, dict) and outer_data.get('is_encrypted'):
            results['is_encrypted'] = True
            results['q_dna'] = "N/A (Encriptado)"
            results['creation_module'] = "N/A (Encriptado)"
            results['technical_version'] = outer_data.get('version_id', 'N/A (Encriptado)')
        else:
            crs_data = outer_data

        if crs_data and isinstance(crs_data, dict):
            # 4. Extracción de Q-DNA y Versión Técnica
            results['q_dna'] = crs_data.get('author_id') or crs_data.get('author', 'No disponible')
            version = str(crs_data.get('version', 'legacy_kiphu_odin'))
            results['technical_version'] = version

            # 5. Determinación del Módulo de Creación (Lógica de Negocio)
            if version.startswith("51."):
                results['creation_module'] = "Bit a Bit (Léxico-Paeth)"
            elif "Generalista" in version:
                results['creation_module'] = "Ultra Visual (Generalista)"
            else:
                fidelity = crs_data.get('fidelity_quality')
                if fidelity is not None:
                    results['creation_module'] = f"Perceptual (Fidelidad WebP: {fidelity}%)"
                else:
                    results['creation_module'] = "Perceptual (Kiphu+Odin - Fidelidad no especificada)"
    
    except pickle.UnpicklingError:
        raise ValueError("Archivo CRS corrupto o no es un formato pickle válido.")
    except Exception as e:
        print(f"Fallo crítico interno: {e}", file=sys.stderr)
        raise RuntimeError(f"Fallo crítico al leer el archivo.")

    return results

# --- 3. Definición de la Ruta de la API (/analyze-crs-metadata) ---
@app.route('/analyze-crs-metadata', methods=['POST'])
def handle_crs_analysis():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No se ha enviado ningún archivo."}), 400
    
    file = request.files['file']
    
    if file.filename == '' or not file.filename.lower().endswith('.crs'):
        return jsonify({"success": False, "error": "Archivo no válido. Se esperaba un archivo .crs."}), 400

    try:
        # ** FIX CRÍTICO: LEER TODO EL BINARIO DEL STREAM DE RED **
        file_bytes = file.read() 
        
        # 3. Llama a la función de análisis
        analysis_results = analyze_crs_from_bytes(file_bytes)
        
        # 4. Devuelve el resultado exitoso (Código 200 OK)
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
