# --- servidor3.py (V3.1 - ANALIZADOR CRS FIABLE) ---
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import pickle
import io

# ===============================================================
# 🧠 LÓGICA DE ANÁLISIS (Idéntica a vcore_analisis.py)
# ===============================================================

def analyze_crs_from_bytes(file_bytes: bytes) -> dict:
    """
    Lee y analiza los metadatos de un archivo .crs desde sus bytes.
    Esta lógica es el 'v core analysis' solicitado.
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

    try:
        outer_data = pickle.loads(file_bytes)

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
        
    except pickle.UnpicklingError:
        raise ValueError("El archivo CRS está corrupto o no es un formato pickle válido.")
    except Exception as e:
        raise RuntimeError(f"Error crítico al analizar la estructura del archivo: {e}")

    return results

# ===============================================================
# 🏭 FUNCIÓN FÁBRICA Y RUTAS
# ===============================================================

def create_app():
    """Define la aplicación Flask para que Gunicorn la pueda inicializar."""
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 
    CORS(app, resources={r"/*": {"origins": "*"}})

    @app.route('/health', methods=['GET'])
    def health_check():
        return "ANALYZER ONLINE (S3)", 200

    @app.route('/analyze-crs-metadata', methods=['POST'])
    def handle_analysis_request():
        """Toma el CRS, ejecuta el análisis y devuelve los metadatos."""
        if 'file' not in request.files:
            return jsonify({"success": False, "error": "No se proporcionó el archivo 'file'"}), 400
            
        file = request.files['file']
        
        try:
            file_bytes = file.read()
            results = analyze_crs_from_bytes(file_bytes)
            
            # Limpiar el output para el JSON final
            if results['is_encrypted']:
                results['author_q_dna'] = None
                results['fidelity_quality'] = None
                results['creation_module'] = "Encriptado"
            else:
                 results['author_q_dna'] = results.get('author_q_dna')

            return jsonify({"success": True, "analysis": results}), 200
            
        except ValueError as e:
            # Archivo corrupto
            return jsonify({"success": False, "error": str(e)}), 406
        except RuntimeError as e:
            # Error de servidor
            return jsonify({"success": False, "error": str(e)}), 500
        except Exception as e:
            return jsonify({"success": False, "error": f"Error inesperado en el servidor: {str(e)}"}), 500

    return app

# ===============================================================
# 🚀 PUNTO DE ENTRADA
# ===============================================================
if __name__ == '__main__':
    # Esto es solo para pruebas locales; Gunicorn usa create_app()
    app = create_app()
    app.run(host='0.0.0.0', port=7860)
