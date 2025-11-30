# servidor3.py (v1.2 - Servidor de Análisis de Metadatos CRS)
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import sys
import io

# --- 1. Inicialización del servidor Flask ---
app = Flask(__name__)
# Permite CUALQUIER origen para CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# --- 2. Lógica de Análisis (Adaptada para funcionar desde un stream en memoria) ---
def analyze_crs_from_stream(file_stream) -> dict:
    """
    Lee y analiza los metadatos de un archivo .crs directamente desde un stream binario.
    Retorna un diccionario con los resultados.
    """
    results = {
        "id_fingerprint": "No disponible",
        "q_dna": "No disponible",
        "creation_module": "Desconocido",
        "technical_version": "No disponible",
        "is_encrypted": False
    }

    try:
        # Intenta cargar los datos del stream usando pickle.
        outer_data = pickle.load(file_stream)

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
            # 3. Si no está encriptado, los datos internos son el objeto principal
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
                # Perceptual (Kiphu+Odin)
                fidelity = crs_data.get('fidelity_quality')
                if fidelity is not None:
                    results['creation_module'] = f"Perceptual (Fidelidad WebP: {fidelity}%)"
                else:
                    results['creation_module'] = "Perceptual (Kiphu+Odin - Fidelidad no especificada)"
    
    except pickle.UnpicklingError:
        raise ValueError("Archivo CRS corrupto o no es un formato pickle válido.")
    except Exception as e:
        # Fallo de lectura/procesamiento genérico.
        print(f"Fallo crítico interno: {e}", file=sys.stderr)
        raise RuntimeError(f"Fallo crítico al leer el archivo.")

    return results

# --- 3. Definición de la Ruta de la API (/analyze-crs-metadata) ---
@app.route('/analyze-crs-metadata', methods=['POST'])
def handle_crs_analysis():
    # 1. Valida que se haya enviado un archivo
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No se ha enviado ningún archivo."}), 400
    
    file = request.files['file']
    
    # 2. Valida la extensión
    if file.filename == '' or not file.filename.lower().endswith('.crs'):
        return jsonify({"success": False, "error": "Archivo no válido. Se esperaba un archivo .crs."}), 400

    try:
        # 3. Llama a la función de análisis, pasando el stream binario
        analysis_results = analyze_crs_from_stream(file.stream)
        
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
    return jsonify({"status": "Servidor 3 ONLINE", "role": "Análisis CRS v1.2"}), 200

# --- 5. Inicia el servidor al ejecutar el script ---
if __name__ == '__main__':
    print(">>> Servidor 3 iniciado en puerto 5002.")
    # Este bloque es clave para el arranque directo de Python
    app.run(host='0.0.0.0', port=5002, debug=False)
