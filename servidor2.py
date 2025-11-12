# servidor2.py (FINAL - VISOR PROFESIONAL SIMPLIFICADO)

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import base64
import io
import zlib
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
import sys
import os

# --- INICIALIZACIÓN Y CORS ---
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- DEPENDENCIAS Y CÓDIGO DE RECONSTRUCCIÓN (SIN CAMBIOS) ---
TF_AVAILABLE = False
try:
    import tensorflow as tf
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    TF_AVAILABLE = True
except ImportError:
    pass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
GENESIS_NAME, ODIN_NAME, GENERALISTA_NAME, LEXICON_NAME = 'kiphu_genesis_engine.keras', 'odin_corrector.keras', 'generalista_hd_best.keras', 'khipu_lexicon.npy'
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
def decrypt_data(encrypted_crs_data: dict, password: str) -> dict | None:
    try:
        salt, encrypted_data = encrypted_crs_data['salt'], encrypted_crs_data['encrypted_data']
        fernet = Fernet(derive_key(password, salt))
        decrypted_pickle = fernet.decrypt(encrypted_data)
        return pickle.loads(decrypted_pickle)
    except InvalidToken: raise ValueError("Contraseña inválida o archivo corrupto.")
    except Exception as e: raise RuntimeError(f"Ocurrió un error grave durante la desencriptación: {e}")
def paeth_predictor(a, b, c):
    p = a + b - c; pa = abs(p - a); pb = abs(p - b); pc = abs(p - c)
    if pa <= pb and pa <= pc: return a
    elif pb <= pc: return b
    else: return c
def get_app_path(): return Path(__file__).parent
MODELS_CACHE, MODELS_DIR = {}, get_app_path() / "xtremertx_ai" / "models"
def load_model_server(model_name):
    if model_name not in MODELS_CACHE:
        path = MODELS_DIR / model_name
        if not path.exists(): raise FileNotFoundError(f"Modelo no encontrado: {model_name}.")
        if model_name.endswith('.keras'):
            if not TF_AVAILABLE: raise ImportError("Error: TensorFlow/Keras no está disponible.")
            MODELS_CACHE[model_name] = tf.keras.models.load_model(str(path), compile=False)
        elif model_name.endswith('.npy'): MODELS_CACHE[model_name] = np.load(path)
        else: raise ValueError(f"Tipo de modelo no soportado: {model_name}")
    return MODELS_CACHE[model_name]

# --- FUNCIÓN DE RECONSTRUCCIÓN (Tu código original) ---
def reconstruct_and_get_image_base64(crs_data_bytes: bytes, password: str = None) -> str:
    try:
        crs_data = pickle.loads(crs_data_bytes)
    except Exception:
        raise ValueError("Archivo CRS corrupto.")

    author_fingerprint, decrypted_data = "No disponible", None
    if isinstance(crs_data, dict) and crs_data.get('is_encrypted'):
        if not password: raise ValueError("Archivo encriptado, se requiere contraseña.")
        decrypted_data = decrypt_data(crs_data, password)
        author_fingerprint = decrypted_data.get('public_author', 'Protegido')
    else:
        decrypted_data = crs_data
        author_fingerprint = decrypted_data.get('public_author', 'No disponible')

    file_version = decrypted_data.get("version", "legacy")
    shape = decrypted_data.get("true_original_shape") or decrypted_data.get("original_shape")
    if shape is None: raise ValueError("No se pudo determinar la forma de la imagen original.")
    
    final_w, final_h = shape[:2]
    final_array = None

    try:
        if file_version.startswith("51."):
            khipu_lexicon=load_model_server(LEXICON_NAME);original_shape,compressed_tiles,tile_size=decrypted_data["original_shape"],decrypted_data["payload_list"],decrypted_data["tile_size"];reconstructed_array=np.zeros(original_shape,dtype=np.int16);tile_idx,total_tiles=0,len(compressed_tiles);border_pixel=np.array([0,0,0],dtype=np.int16)
            for y in range(0,original_shape[0],tile_size):
                for x in range(0,original_shape[1],tile_size):
                    if tile_idx>=total_tiles:continue
                    encoded_array=np.frombuffer(zlib.decompress(compressed_tiles[tile_idx]),dtype=np.int16);flat_residual=[];i=0
                    while i<len(encoded_array):
                        if encoded_array[i]==32767:flat_residual.extend(khipu_lexicon[encoded_array[i+1]]);i+=2
                        else:flat_residual.append(encoded_array[i]);i+=1
                    h,w=min(tile_size,original_shape[0]-y),min(tile_size,original_shape[1]-x);residual_tile=np.array(flat_residual,dtype=np.int16).reshape((h,w,3))
                    for tile_y in range(h):
                        for tile_x in range(w):
                            abs_y,abs_x=y+tile_y,x+tile_x;a=reconstructed_array[abs_y,abs_x-1] if abs_x>0 else border_pixel;b=reconstructed_array[abs_y-1,abs_x] if abs_y>0 else border_pixel;c=reconstructed_array[abs_y-1,abs_x-1] if abs_y>0 and abs_x>0 else border_pixel;prediction=np.array([paeth_predictor(a[i],b[i],c[i]) for i in range(3)],dtype=np.int16);reconstructed_array[abs_y,abs_x]=prediction+residual_tile[tile_y,tile_x]
                    tile_idx+=1
            final_array=np.clip(reconstructed_array,0,255).astype(np.uint8)
        else:
            if not TF_AVAILABLE: raise ImportError("Error: TensorFlow/Keras es necesario.")
            if "Generalista" in file_version:
                generalista_model=load_model_server(GENERALISTA_NAME);core_seed,fidelity_seed=decrypted_data["core_seed"],decrypted_data["fidelity_seed"];encoder_output_shape=generalista_model.get_layer('max_pooling2d_2').output.shape[1:];decoder_input=tf.keras.Input(shape=encoder_output_shape);x=generalista_model.layers[7](decoder_input)
                for i in range(8,len(generalista_model.layers)):x=generalista_model.layers[i](x)
                decoder_g=tf.keras.models.Model(decoder_input,x);reconstructed_norm=decoder_g.predict(core_seed,verbose=0).squeeze();base_evoked_pil=Image.fromarray((reconstructed_norm*255).astype(np.uint8));base_evoked_resized=base_evoked_pil.resize((final_w,final_h),Image.Resampling.LANCZOS);base_evoked_array=np.array(base_evoked_resized);residual_map=np.array(Image.open(io.BytesIO(fidelity_seed))).astype(np.int32)-128;final_array=np.clip(base_evoked_array.astype(np.int32)+residual_map,0,255).astype(np.uint8)
            else:
                genesis_model,odin_model=load_model_server(GENESIS_NAME),load_model_server(ODIN_NAME);core_seed,fidelity_seed=decrypted_data["core_seed"],decrypted_data["fidelity_seed"];reconstructed_norm=genesis_model.predict(core_seed,verbose=0).squeeze();odin_corrected_norm=odin_model.predict(np.expand_dims(reconstructed_norm,axis=0),verbose=0).squeeze();base_evoked_pil=Image.fromarray((np.clip(odin_corrected_norm,0,1)*255).astype(np.uint8));base_evoked_resized=base_evoked_pil.resize((final_w,final_h),Image.Resampling.LANCZOS);base_evoked_array=np.array(base_evoked_resized,dtype=np.float32);residual_map=(np.array(Image.open(io.BytesIO(fidelity_seed)),dtype=np.float32)-128.0)*2.0;final_array=np.clip(base_evoked_array+residual_map,0,255).astype(np.uint8)
    except Exception as e:
        raise RuntimeError(f"Fallo de reconstrucción para la versión '{file_version}': {e}")

    if final_array is None: raise ValueError("No se pudo reconstruir la imagen.")
    
    original_image = Image.fromarray(final_array)
    original_image.thumbnail((512, 512), Image.Resampling.BILINEAR)
    footer_height = 35
    img_width, img_height = original_image.size
    real_preview_image = Image.new('RGBA', (img_width, img_height + footer_height), (0,0,0,0))
    real_preview_image.paste(original_image, (0, 0))
    draw = ImageDraw.Draw(real_preview_image)
    draw.rectangle([(0, img_height), (img_width, img_height + footer_height)], fill=(25, 25, 25, 230))
    try:
        font_info, font_cta = ImageFont.truetype("seguisb.ttf", 11), ImageFont.truetype("seguib.ttf", 12)
    except IOError:
        font_info, font_cta = ImageFont.load_default(), ImageFont.load_default()
    author_text = f"Fingerprint ID: {author_fingerprint}  |  (Vista Previa de Baja Calidad)"
    draw.text((10, img_height + 9), author_text, font=font_info, fill=(150, 150, 150))
    cta_text = "Descarga LectorTX/CreadorTX para ver el original"
    cta_width = draw.textlength(cta_text, font=font_cta)
    draw.text((img_width - cta_width - 10, img_height + 8), cta_text, font=font_cta, fill=(0, 191, 255))
    
    buffer = io.BytesIO()
    real_preview_image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

# --- ENDPOINT (SIMPLIFICADO) ---
@app.route('/generate-crs-preview', methods=['POST'])
def handle_preview_generation():
    if 'file' not in request.files: return jsonify({"error": "No se ha enviado ningún archivo."}), 400
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.crs'): return jsonify({"error": "Archivo no válido."}), 400
    try:
        crs_data_bytes = file.read() 
        password = request.form.get('password')
        base64_image = reconstruct_and_get_image_base64(crs_data_bytes, password=password) 
        return jsonify({
            "success": True, 
            "preview_base64": base64_image
        }), 200
    except ValueError as ve: return jsonify({"success": False, "error": str(ve)}), 400
    except (FileNotFoundError, ImportError) as fe: return jsonify({"success": False, "error": f"Error de configuración del servidor: {fe}"}), 500
    except Exception as e:
        print(f"ERROR CRÍTICO EN SERVIDOR2: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": "Fallo interno y crítico del servidor."}), 500

# --- INICIO DEL SERVIDOR (RESTAURADO) ---
if __name__ == '__main__':
    # Puerto 5001 y host 0.0.0.0 (como lo tenías)
    app.run(host='0.0.0.0', port=5001, debug=True)