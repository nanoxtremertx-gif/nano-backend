# servidor2.py (DEFINITIVO - CON DEGRADACIÓN DE SEGURIDAD 15% - ESCUCHA EN PUERTO 5001)

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import base64
import io
import zlib
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from pathlib import Path
import sys
import os

# --- CONFIGURACIÓN INICIAL ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- DEPENDENCIAS ---
TF_AVAILABLE = False
try:
    import tensorflow as tf
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    TF_AVAILABLE = True
except ImportError:
    print("ADVERTENCIA: TensorFlow no encontrado.", file=sys.stderr)

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- CONSTANTES ---
GENESIS_NAME = 'kiphu_genesis_engine.keras'
ODIN_NAME = 'odin_corrector.keras'
GENERALISTA_NAME = 'generalista_hd_best.keras'
LEXICON_NAME = 'khipu_lexicon.npy'

def get_app_path():
    return Path(__file__).parent

# Ajusta la ruta según donde estén tus modelos en la imagen Docker
MODELS_DIR = get_app_path() / "xtremertx_ai" / "models"
MODELS_CACHE = {}

# --- CARGA DE MODELOS ---
def load_model_server(model_name):
    if model_name not in MODELS_CACHE:
        path = MODELS_DIR / model_name
        if not path.exists():
            # Fallback: intentar buscar en carpeta local si falla la estructura compleja
            path = get_app_path() / model_name 
            if not path.exists():
                raise FileNotFoundError(f"Modelo faltante: {model_name}")
        
        print(f"Cargando modelo: {model_name}...")
        if model_name.endswith('.keras'):
            if not TF_AVAILABLE: raise ImportError("TensorFlow requerido.")
            MODELS_CACHE[model_name] = tf.keras.models.load_model(str(path), compile=False)
        elif model_name.endswith('.npy'):
            MODELS_CACHE[model_name] = np.load(path)
    return MODELS_CACHE[model_name]

# --- CRIPTOGRAFÍA ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_data(encrypted_crs_data: dict, password: str) -> dict | None:
    try:
        salt, encrypted_data = encrypted_crs_data['salt'], encrypted_crs_data['encrypted_data']
        fernet = Fernet(derive_key(password, salt))
        return pickle.loads(fernet.decrypt(encrypted_data))
    except InvalidToken:
        raise ValueError("Contraseña incorrecta.")

def paeth_predictor(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc: return a
    elif pb <= pc: return b
    else: return c

# --- MOTOR DE RECONSTRUCCIÓN (CON DEGRADACIÓN DE SEGURIDAD) ---
def reconstruct_and_degrade(crs_data_bytes: bytes, password: str = None) -> str:
    """
    1. Reconstruye la imagen.
    2. APLICA DEGRADACIÓN AL 15%.
    3. Devuelve base64 para vista previa web segura.
    """
    try:
        crs_data = pickle.loads(crs_data_bytes)
    except Exception:
        raise ValueError("Archivo corrupto.")

    # 1. Desencriptar
    author_fingerprint = "Desconocido"
    if isinstance(crs_data, dict) and crs_data.get('is_encrypted'):
        if not password: raise ValueError("ARCHIVO_ENCRIPTADO_REQ_PASS")
        crs_data = decrypt_data(crs_data, password)
        author_fingerprint = crs_data.get('author_id', 'Privado')
    else:
        author_fingerprint = crs_data.get('author_id', 'No disponible')

    # 2. Reconstruir (Lógica v10.15)
    file_version = crs_data.get("version", "legacy")
    shape_data = crs_data.get("true_original_shape") or crs_data.get("original_shape")
    final_w, final_h = shape_data[:2]
    final_array = None

    try:
        if file_version.startswith("51."):
            khipu_lexicon = load_model_server(LEXICON_NAME)
            original_shape, compressed_tiles = crs_data["original_shape"], crs_data["payload_list"]
            tile_size = crs_data["tile_size"]
            reconstructed_array = np.zeros(original_shape, dtype=np.int16)
            tile_idx, total_tiles = 0, len(compressed_tiles)
            border_pixel = np.array([0,0,0], dtype=np.int16)

            for y in range(0, original_shape[0], tile_size):
                for x in range(0, original_shape[1], tile_size):
                    if tile_idx >= total_tiles: continue
                    encoded_array = np.frombuffer(zlib.decompress(compressed_tiles[tile_idx]), dtype=np.int16)
                    flat_residual, i = [], 0
                    while i < len(encoded_array):
                        if encoded_array[i] == 32767: flat_residual.extend(khipu_lexicon[encoded_array[i+1]]); i += 2
                        else: flat_residual.append(encoded_array[i]); i += 1
                    h_t, w_t = min(tile_size, original_shape[0]-y), min(tile_size, original_shape[1]-x)
                    residual_tile = np.array(flat_residual, dtype=np.int16).reshape((h_t, w_t, 3))
                    for ty in range(h_t):
                        for tx in range(w_t):
                            ay, ax = y+ty, x+tx
                            a = reconstructed_array[ay, ax-1] if ax>0 else border_pixel
                            b = reconstructed_array[ay-1, ax] if ay>0 else border_pixel
                            c = reconstructed_array[ay-1, ax-1] if ay>0 and ax>0 else border_pixel
                            reconstructed_array[ay, ax] = np.array([paeth_predictor(a[k],b[k],c[k]) for k in range(3)]) + residual_tile[ty, tx]
                    tile_idx += 1
            final_array = np.clip(reconstructed_array, 0, 255).astype(np.uint8)

        elif "Generalista" in file_version:
            generalista_model = load_model_server(GENERALISTA_NAME)
            core_seed, fidelity_seed = crs_data["core_seed"], crs_data["fidelity_seed"]
            enc_out = generalista_model.get_layer('max_pooling2d_2').output.shape[1:]
            dec_in = tf.keras.Input(shape=enc_out)
            x = generalista_model.layers[7](dec_in)
            for i in range(8, len(generalista_model.layers)): x = generalista_model.layers[i](x)
            decoder_g = tf.keras.models.Model(dec_in, x)
            
            rec_norm = decoder_g.predict(core_seed, verbose=0).squeeze()
            base_pil = Image.fromarray((rec_norm * 255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
            res_map = np.array(Image.open(io.BytesIO(fidelity_seed))).astype(np.int32) - 128
            final_array = np.clip(np.array(base_pil).astype(np.int32) + res_map, 0, 255).astype(np.uint8)

        else: # Genesis Legacy
            genesis_model, odin_model = load_model_server(GENESIS_NAME), load_model_server(ODIN_NAME)
            core_seed, fidelity_seed = crs_data["core_seed"], crs_data["fidelity_seed"]
            rec_norm = genesis_model.predict(core_seed, verbose=0).squeeze()
            odin_norm = odin_model.predict(np.expand_dims(rec_norm, axis=0), verbose=0).squeeze()
            base_pil = Image.fromarray((np.clip(odin_norm,0,1)*255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
            res_map = (np.array(Image.open(io.BytesIO(fidelity_seed)), dtype=np.float32)-128.0)*2.0
            final_array = np.clip(np.array(base_pil) + res_map, 0, 255).astype(np.uint8)

    except Exception as e:
        raise RuntimeError(f"Fallo reconstrucción: {e}")

    if final_array is None: raise ValueError("Error interno: Imagen vacía.")

    # --- FASE DE SEGURIDAD Y DEFORMACIÓN (15% CALIDAD) ---
    original_image = Image.fromarray(final_array)
    
    # 1. Calcular el 15% del tamaño original
    w, h = original_image.size
    target_w = max(64, int(w * 0.15)) 
    target_h = max(64, int(h * 0.15))
    
    # 2. DEFORMAR: Bajar drásticamente la resolución (Bilinear)
    deformed_image = original_image.resize((target_w, target_h), Image.Resampling.BILINEAR)
    
    # 3. RE-ESCALAR para presentación web (BOX)
    preview_size = (512, 512)
    final_preview = deformed_image.resize(preview_size, Image.Resampling.BOX)
    
    # 4. Desenfoque suave
    final_preview = final_preview.filter(ImageFilter.GaussianBlur(radius=1.5))

    # --- FOOTER DE ADVERTENCIA ---
    footer_height = 40
    pw, ph = final_preview.size
    full_preview = Image.new('RGBA', (pw, ph + footer_height), (10, 10, 10, 255))
    full_preview.paste(final_preview, (0, 0))
    
    draw = ImageDraw.Draw(full_preview)
    try: font = ImageFont.truetype("arial.ttf", 12)
    except: font = ImageFont.load_default()
        
    info_text = f"ID: {author_fingerprint} | PREVIEW 15% CALIDAD"
    draw.text((10, ph + 12), info_text, font=font, fill=(100, 100, 100))
    draw.text((pw - 100, ph + 12), "SOLO LECTURA", font=font, fill=(200, 50, 50))

    buffer = io.BytesIO()
    full_preview.save(buffer, format="PNG", optimize=True)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

# --- ENDPOINT ---
@app.route('/generate-crs-preview', methods=['POST'])
def handle_preview_generation():
    if 'file' not in request.files: return jsonify({"success": False, "error": "Sin archivo"}), 400
    file = request.files['file']
    password = request.form.get('password')
    
    if not file.filename.endswith('.crs'): return jsonify({"success": False, "error": "No es .crs"}), 400
    
    try:
        prev_b64 = reconstruct_and_degrade(file.read(), password)
        return jsonify({"success": True, "preview_base64": prev_b64}), 200
    except ValueError as ve:
        msg = str(ve)
        if "REQ_PASS" in msg: return jsonify({"success": False, "error": "LOCKED_FILE"}), 401
        return jsonify({"success": False, "error": msg}), 400
    except Exception as e:
        print(f"ERROR 500: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": "Error interno"}), 500

if __name__ == '__main__':
    # Se recomienda usar puerto 5001 para no chocar con servidor 1 si se prueban localmente
    app.run(host='0.0.0.0', port=5001, debug=True)
