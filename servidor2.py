# --- servidor2.py (V10.20 - FIX CONEXIÓN & CORS LIMPIO) ---
import os
import sys
import io
import base64
import pickle
import traceback
import numpy as np
import tensorflow as tf
from pathlib import Path
from PIL import Image, ImageFilter, ImageDraw, ImageFont
from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from urllib.parse import urlparse, urlunparse

# --- CRIPTOGRAFÍA ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- IMPORTACIÓN DE MODELOS DB ---
from models import db, User, UserFile, DocGestion

app = Flask(__name__)

# CONFIGURACIÓN DE SUBIDA (1 GB Límite)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 

# ==============================================================================
# PARTE 1: CONFIGURACIÓN SATÉLITE Y BASE DE DATOS
# ==============================================================================

MAESTRO_URL = os.environ.get('MAESTRO_URL', 'https://nano-xtremertx-nano-backend.hf.space')
if MAESTRO_URL.endswith('/'): MAESTRO_URL = MAESTRO_URL[:-1]

print(f">>> INICIANDO NODO DE IA (SERVIDOR 2) >>> CONECTADO A: {MAESTRO_URL}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
NEON_URL = os.environ.get('NEON_URL')

if NEON_URL:
    try:
        parsed = urlparse(NEON_URL)
        scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
        clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
        if 'postgresql' in clean_url and 'sslmode' not in clean_url:
            clean_url += "?sslmode=require"
        app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
        print(">>> DB NEON: CONECTADA")
    except Exception as e:
        print(f"!!! ERROR DB: {e}")
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"

# --- CORS: CONFIGURACIÓN LIMPIA (Sin duplicados manuales) ---
CORS(app, resources={r"/*": {"origins": "*"}})

bcrypt = Bcrypt(app)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=1024*1024*1024)

# ==============================================================================
# PARTE 2: LÓGICA DE IA (Modelos y Reconstrucción)
# ==============================================================================

GENESIS_NAME = 'genesis_decoder_v4.keras'
ODIN_NAME = 'odin_upscaler_v2.keras'
GENERALISTA_NAME = 'generalista_hd_best.keras'
LEXICON_NAME = 'khipu_lexicon.npy'

BASE_DIR = Path("/app")
MODELS_DIR = BASE_DIR / "xtremertx_ai" / "models"
MODELS_CACHE = {}

print(f">>> DIRECTORIO DE MODELOS ESPERADO: {MODELS_DIR}", flush=True)

def load_model_server(model_name):
    if model_name not in MODELS_CACHE:
        path = MODELS_DIR / model_name
        # Búsqueda defensiva por si los modelos están en la raíz
        if not path.exists():
            print(f"!!! AVISO: Modelo no en {path}, buscando en raíz...", file=sys.stderr)
            path = BASE_DIR / model_name 
            if not path.exists():
                raise FileNotFoundError(f"Modelo faltante: {model_name}")

        print(f">>> CARGANDO MODELO: {model_name}...", flush=True)
        try:
            if model_name.endswith('.keras'):
                MODELS_CACHE[model_name] = tf.keras.models.load_model(str(path), compile=False)
            elif model_name.endswith('.npy'):
                MODELS_CACHE[model_name] = np.load(path)
        except Exception as e:
            raise RuntimeError(f"Modelo corrupto: {e}")
            
    return MODELS_CACHE[model_name]

# --- UTILS CRYPTO ---
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_data(encrypted_dict, password):
    try:
        salt = base64.urlsafe_b64decode(encrypted_dict['salt'])
        token = encrypted_dict['data']
        key = derive_key(password, salt)
        f = Fernet(key)
        return pickle.loads(f.decrypt(token))
    except: raise ValueError("CONTRASEÑA INCORRECTA")

def get_author_fingerprint(data_dict):
    for key in ['public_author', 'author_id', 'author', 'fingerprint', 'creator']:
        val = data_dict.get(key)
        if val and str(val).strip() != "": return str(val)
    return "Desconocido"

# --- MOTOR DE RECONSTRUCCIÓN ---
def reconstruct_and_degrade(crs_data_bytes: bytes, password: str = None, full_quality: bool = False) -> str:
    try: crs_data = pickle.loads(crs_data_bytes)
    except: raise ValueError("El archivo .CRS está dañado o no es válido.")

    final_data = crs_data
    if isinstance(crs_data, dict) and crs_data.get('is_encrypted'):
        if not password: raise ValueError("ARCHIVO_ENCRIPTADO_REQ_PASS")
        final_data = decrypt_data(crs_data, password)

    author_fingerprint = get_author_fingerprint(final_data)
    file_version = final_data.get("version", "legacy")
    shape_data = final_data.get("true_original_shape") or final_data.get("original_shape")
    
    if not shape_data: raise ValueError("Datos de forma corruptos.")
    final_w, final_h = shape_data[:2]
    final_array = None

    # Inferencia IA
    try:
        if "Generalista" in file_version:
            generalista_model = load_model_server(GENERALISTA_NAME)
            core_seed = final_data["core_seed"]
            fidelity_seed = final_data["fidelity_seed"]
            
            enc_out = generalista_model.get_layer('max_pooling2d_2').output.shape[1:]
            dec_in = tf.keras.Input(shape=enc_out)
            x = generalista_model.layers[7](dec_in)
            for i in range(8, len(generalista_model.layers)): x = generalista_model.layers[i](x)
            decoder_g = tf.keras.models.Model(dec_in, x)
            
            rec_norm = decoder_g.predict(core_seed, verbose=0).squeeze()
            base_pil = Image.fromarray((rec_norm * 255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
            res_map = np.array(Image.open(io.BytesIO(fidelity_seed))).astype(np.int32) - 128
            final_array = np.clip(np.array(base_pil).astype(np.int32) + res_map, 0, 255).astype(np.uint8)

        else: 
            genesis_model = load_model_server(GENESIS_NAME)
            odin_model = load_model_server(ODIN_NAME)
            
            core_seed = final_data["core_seed"]
            fidelity_seed = final_data["fidelity_seed"]
            
            rec_norm = genesis_model.predict(core_seed, verbose=0).squeeze()
            odin_norm = odin_model.predict(np.expand_dims(rec_norm, axis=0), verbose=0).squeeze()
            base_pil = Image.fromarray((np.clip(odin_norm,0,1)*255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
            try: res_map = (np.array(Image.open(io.BytesIO(fidelity_seed)), dtype=np.float32)-128.0)*2.0
            except: res_map = np.zeros((final_h, final_w), dtype=np.float32)
            final_array = np.clip(np.array(base_pil) + res_map, 0, 255).astype(np.uint8)

    except Exception as e:
        print(f"!!! FALLO MOTOR IA: {traceback.format_exc()}", file=sys.stderr)
        raise RuntimeError(f"Fallo motor IA: {e}")

    if final_array is None: raise ValueError("Error interno: Imagen vacía.")

    # Post-Procesado (Degradación vs Full)
    try:
        original_image = Image.fromarray(final_array)
        w, h = original_image.size
        
        if full_quality:
            # Si es calidad completa, no redimensionamos pequeño
            final_preview = original_image
            info_text = f"ID: {author_fingerprint} | CALIDAD ORIGINAL 100%"
        else:
            # Degradación al 15% (Por defecto para Biblioteca)
            target_w, target_h = max(64, int(w * 0.15)), max(64, int(h * 0.15))
            deformed_image = original_image.resize((target_w, target_h), Image.Resampling.BILINEAR)
            final_preview = deformed_image.resize((512, 512), Image.Resampling.BOX)
            final_preview = final_preview.filter(ImageFilter.GaussianBlur(radius=1.5))
            info_text = f"ID: {author_fingerprint} | PREVIEW 15%"

        # Añadir pie de página con info
        footer_height = 40
        pw, ph = final_preview.size
        full_preview = Image.new('RGBA', (pw, ph + footer_height), (10, 10, 10, 255))
        full_preview.paste(final_preview, (0, 0))
        
        draw = ImageDraw.Draw(full_preview)
        try: font = ImageFont.truetype("arial.ttf", 12)
        except: font = ImageFont.load_default()
        
        draw.text((10, ph + 12), info_text, font=font, fill=(150, 150, 150))
        if not full_quality:
            draw.text((pw - 110, ph + 12), "SOLO LECTURA", font=font, fill=(200, 50, 50))

        buffer = io.BytesIO()
        full_preview.save(buffer, format="PNG", optimize=True)
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    except Exception as e:
        print(f"!!! FALLO POST-PROCESADO: {e}", file=sys.stderr)
        raise RuntimeError("Fallo generando imagen final.")

# ==============================================================================
# PARTE 3: RUTAS Y ENDPOINTS
# ==============================================================================

@app.route('/generate-crs-preview', methods=['POST'])
def handle_preview_generation():
    if 'file' not in request.files: return jsonify({"success": False, "error": "No file"}), 400
    file = request.files['file']
    password = request.form.get('password')
    
    # Soporte futuro para pedir 100% (si el frontend envía ?quality=full)
    # Por ahora el frontend no lo envía, así que full_quality será False (15%)
    is_full_quality = request.args.get('quality') == 'full'

    print(f">>> [IA] PROCESANDO: {file.filename} | FULL_QUALITY: {is_full_quality}", flush=True)
    
    if not file.filename.endswith('.crs'): return jsonify({"success": False, "error": "No es .crs"}), 400
    
    try:
        # Pasamos el parámetro is_full_quality a la función
        prev_b64 = reconstruct_and_degrade(file.read(), password, full_quality=is_full_quality)
        print(">>> [IA] PROCESO OK.", flush=True)
        return jsonify({"success": True, "preview_base64": prev_b64}), 200
    except ValueError as ve:
        msg = str(ve)
        if "REQ_PASS" in msg: return jsonify({"success": False, "error": "LOCKED_FILE"}), 401
        return jsonify({"success": False, "error": msg}), 400
    except Exception as e:
        print(f"!!! [IA] ERROR CRITICO: {e}", file=sys.stderr)
        return jsonify({"success": False, "error": f"Error IA: {str(e)}"}), 500

# --- SATÉLITE ---
@app.route('/uploads/<path:filename>')
def redirect_uploads(filename): return redirect(f"{MAESTRO_URL}/uploads/{filename}")

@app.route('/uploads/avatars/<path:filename>')
def redirect_avatars(filename): return redirect(f"{MAESTRO_URL}/uploads/avatars/{filename}")

@app.route('/documentos_gestion/<path:section>/<path:filename>')
def redirect_docs(section, filename): return redirect(f"{MAESTRO_URL}/documentos_gestion/{section}/{filename}")

@app.route('/updates/<path:filename>')
def redirect_updates(filename): return redirect(f"{MAESTRO_URL}/updates/{filename}")

# --- API LECTURA ---
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files_satellite(username):
    try:
        files = UserFile.query.filter_by(owner_username=username).all()
        file_list = []
        for f in files:
            remote_url = f"{MAESTRO_URL}/uploads/{f.storage_path}"
            file_list.append({
                "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id,
                "size_bytes": f.size_bytes, "path": remote_url, 
                "isPublished": f.is_published, "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status
            })
        return jsonify(file_list), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/biblioteca/public-files', methods=['GET'])
def get_public_files_satellite():
    try:
        files = UserFile.query.filter_by(is_published=True).order_by(UserFile.created_at.desc()).all()
        file_list = []
        for f in files:
            file_list.append({
                "id": f.id, "name": f.name, "type": f.type,
                "path": f"{MAESTRO_URL}/uploads/{f.storage_path}",
                "size": f.size_bytes, "description": f.description,
                "userId": f.owner_username
            })
        return jsonify(file_list), 200
    except: return jsonify([]), 200

@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json()
    u = User.query.filter_by(username=d.get('username')).first()
    if u and bcrypt.check_password_hash(u.hash, d.get('password')):
        avatar_url = u.avatar
        if 'uploads' in str(avatar_url) and not avatar_url.startswith('http'):
             avatar_url = f"{MAESTRO_URL}{u.avatar}" if u.avatar.startswith('/') else f"{MAESTRO_URL}/{u.avatar}"
        return jsonify({"message": "OK", "user": {"username": u.username, "role": u.role, "avatar": avatar_url}}), 200
    return jsonify({"message": "Credenciales inválidas"}), 401

@app.route('/health')
def health(): return "ALIVE", 200

@app.route('/')
def index():
    # Chequeo rápido de modelos
    models_status = "OK" if len(MODELS_CACHE) > 0 else "ESPERANDO (Carga Bajo Demanda)"
    return jsonify({
        "status": "Servidor 2 (IA + Satélite) ONLINE",
        "cors_policy": "Abierta (*)",
        "models_status": models_status,
        "linked_to": MAESTRO_URL
    })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=7860, allow_unsafe_werkzeug=True)
