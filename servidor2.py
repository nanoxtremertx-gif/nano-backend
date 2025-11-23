# --- servidor2.py (V10.22 - MODO A PRUEBA DE FALLOS) ---
import os
import sys
import io
import base64
import pickle
import traceback
import numpy as np
from pathlib import Path
from PIL import Image, ImageFilter, ImageDraw, ImageFont
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from urllib.parse import urlparse, urlunparse

# --- INTENTO DE CARGA DE TENSORFLOW (CONTROLADO) ---
try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    print("!!! ADVERTENCIA: TensorFlow no instalado o falló al cargar.", file=sys.stderr)
    TF_AVAILABLE = False

# --- CRIPTOGRAFÍA ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- IMPORTACIÓN DE MODELOS DB ---
try:
    from models import db, User, UserFile, DocGestion
except ImportError:
    print("!!! ERROR: models.py no encontrado. El servidor DB fallará.", file=sys.stderr)
    # Mock para que no crashee al inicio si falta el archivo
    db = type('Mock', (object,), {'init_app': lambda x: None})
    User = UserFile = DocGestion = None

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 

# ==============================================================================
# PARTE 1: CONFIGURACIÓN
# ==============================================================================

MAESTRO_URL = os.environ.get('MAESTRO_URL', 'https://nano-xtremertx-nano-backend.hf.space')
if MAESTRO_URL.endswith('/'): MAESTRO_URL = MAESTRO_URL[:-1]

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
    except:
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"

CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
if hasattr(db, 'init_app'): db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=1024*1024*1024)

# ==============================================================================
# PARTE 2: SISTEMA DE IA (ROBUSTO)
# ==============================================================================

BASE_DIR = Path("/app")
MODELS_DIR = BASE_DIR / "xtremertx_ai" / "models"
MODELS_CACHE = {}

# Nombres de archivos esperados
MODELS_CONFIG = {
    'generalista': 'generalista_hd_best.keras',
    'genesis': 'genesis_decoder_v4.keras',
    'odin': 'odin_upscaler_v2.keras',
    'lexicon': 'khipu_lexicon.npy'
}

def create_error_image(message):
    """Genera una imagen negra con el texto del error para el frontend."""
    img = Image.new('RGB', (512, 512), color=(20, 0, 0))
    d = ImageDraw.Draw(img)
    try: font = ImageFont.truetype("arial.ttf", 16)
    except: font = ImageFont.load_default()
    
    # Escribir mensaje multilinea
    y = 200
    for line in message.split('\n'):
        d.text((20, y), line, fill=(255, 100, 100), font=font)
        y += 20
        
    d.text((20, 480), "NANO XTREMERTX SYSTEM", fill=(100, 100, 100), font=font)
    
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def load_model_server(key):
    if not TF_AVAILABLE: return None
    model_name = MODELS_CONFIG.get(key)
    if not model_name: return None
    
    if key not in MODELS_CACHE:
        path = MODELS_DIR / model_name
        if not path.exists():
            # Fallback a raiz
            path = BASE_DIR / model_name 
            if not path.exists():
                print(f"!!! MODELO FALTANTE: {model_name}", file=sys.stderr)
                return None

        print(f">>> CARGANDO: {model_name}...", flush=True)
        try:
            if model_name.endswith('.keras'):
                MODELS_CACHE[key] = tf.keras.models.load_model(str(path), compile=False)
            elif model_name.endswith('.npy'):
                MODELS_CACHE[key] = np.load(path)
        except Exception as e:
            print(f"!!! ERROR CARGA MODELO {model_name}: {e}")
            return None
            
    return MODELS_CACHE.get(key)

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

# --- MOTOR PRINCIPAL ---
def process_preview_request(file_bytes, filename, password=None, full_quality=False):
    filename = filename.lower()
    author_fingerprint = "N/A"
    original_image = None

    # A) PROCESAMIENTO CRS (IA)
    if filename.endswith('.crs'):
        try: 
            crs_data = pickle.loads(file_bytes)
        except: 
            return create_error_image("ARCHIVO CORRUPTO\nEl archivo no es un CRS válido.")

        final_data = crs_data
        if isinstance(crs_data, dict) and crs_data.get('is_encrypted'):
            if not password: return create_error_image("ARCHIVO BLOQUEADO\nSe requiere contraseña.")
            try: final_data = decrypt_data(crs_data, password)
            except: return create_error_image("ACCESO DENEGADO\nContraseña incorrecta.")

        author_fingerprint = get_author_fingerprint(final_data)
        file_version = final_data.get("version", "legacy")
        
        # Validar datos mínimos
        shape_data = final_data.get("true_original_shape") or final_data.get("original_shape")
        if not shape_data: return create_error_image("METADATA ERRÓNEA\nFalta información de forma.")
        
        final_w, final_h = shape_data[:2]
        final_array = None

        # INFERENCIA IA
        try:
            if not TF_AVAILABLE:
                return create_error_image("SERVIDOR IA OFFLINE\nLibrerías no disponibles.")

            if "Generalista" in file_version:
                model = load_model_server('generalista')
                if not model: return create_error_image("MODELO NO ENCONTRADO\nEl modelo 'Generalista' falta en el servidor.")
                
                rec_norm = model.predict(final_data["core_seed"], verbose=0).squeeze()
                base_pil = Image.fromarray((rec_norm * 255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
                res_map = np.array(Image.open(io.BytesIO(final_data["fidelity_seed"]))).astype(np.int32) - 128
                final_array = np.clip(np.array(base_pil).astype(np.int32) + res_map, 0, 255).astype(np.uint8)
            else:
                # Legacy
                model_g = load_model_server('genesis')
                model_o = load_model_server('odin')
                if not model_g or not model_o: return create_error_image("MODELOS LEGACY FALTANTES")
                
                rec_norm = model_g.predict(final_data["core_seed"], verbose=0).squeeze()
                odin_norm = model_o.predict(np.expand_dims(rec_norm, axis=0), verbose=0).squeeze()
                base_pil = Image.fromarray((np.clip(odin_norm,0,1)*255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
                try: res_map = (np.array(Image.open(io.BytesIO(final_data["fidelity_seed"])), dtype=np.float32)-128.0)*2.0
                except: res_map = np.zeros((final_h, final_w), dtype=np.float32)
                final_array = np.clip(np.array(base_pil) + res_map, 0, 255).astype(np.uint8)

        except Exception as e:
            print(f"Error Interno IA: {e}")
            return create_error_image(f"ERROR DE PROCESAMIENTO\n{str(e)[:50]}...")

        if final_array is not None:
            original_image = Image.fromarray(final_array)

    # B) IMÁGENES ESTÁNDAR (Bypass)
    elif filename.endswith(('.png', '.jpg', '.jpeg', '.webp')):
        try:
            original_image = Image.open(io.BytesIO(file_bytes))
            if original_image.mode != 'RGB': original_image = original_image.convert('RGB')
            author_fingerprint = "IMAGEN"
        except: return create_error_image("FORMATO INVÁLIDO")
    
    else:
        return create_error_image("FORMATO NO SOPORTADO\nUse .CRS, .PNG o .JPG")

    if original_image is None: return create_error_image("ERROR DESCONOCIDO\nNo se generó imagen.")

    # C) RENDERIZADO FINAL (15% vs 100%)
    try:
        w, h = original_image.size
        if full_quality:
            final_preview = original_image
            info_text = f"ID: {author_fingerprint} | CALIDAD: 100%"
        else:
            # Degradación 15%
            target_w, target_h = max(64, int(w * 0.15)), max(64, int(h * 0.15))
            deformed_image = original_image.resize((target_w, target_h), Image.Resampling.BILINEAR)
            final_preview = deformed_image.resize((512, 512), Image.Resampling.BOX)
            final_preview = final_preview.filter(ImageFilter.GaussianBlur(radius=2))
            info_text = f"ID: {author_fingerprint} | PREVIEW 15%"

        # Footer Informativo
        pw, ph = final_preview.size
        full_preview = Image.new('RGBA', (pw, ph + 40), (10, 10, 10, 255))
        full_preview.paste(final_preview, (0, 0))
        
        d = ImageDraw.Draw(full_preview)
        try: font = ImageFont.truetype("arial.ttf", 12)
        except: font = ImageFont.load_default()
        
        d.text((10, ph + 12), info_text, font=font, fill=(150, 150, 150))
        
        buffer = io.BytesIO()
        full_preview.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode('utf-8')

    except Exception as e:
        return create_error_image(f"ERROR RENDERIZADO\n{str(e)}")

# ==============================================================================
# PARTE 3: RUTAS
# ==============================================================================

@app.route('/generate-crs-preview', methods=['POST'])
def handle_preview_generation():
    if 'file' not in request.files: return jsonify({"success": False, "error": "No file"}), 400
    file = request.files['file']
    password = request.form.get('password')
    is_full_quality = request.args.get('quality') == 'full'

    print(f">>> [REQ] Procesando: {file.filename}", flush=True)
    
    try:
        # Usamos la función segura que devuelve IMAGEN (aunque sea de error)
        prev_b64 = process_preview_request(file.read(), file.filename, password, is_full_quality)
        return jsonify({"success": True, "preview_base64": prev_b64}), 200
    except Exception as e:
        # Última red de seguridad
        print(f"!!! PÁNICO 500: {e}", file=sys.stderr)
        # Devolver imagen de error generada al vuelo en vez de 500
        err_img = create_error_image(f"ERROR CRÍTICO SERVIDOR\n{str(e)}")
        return jsonify({"success": True, "preview_base64": err_img}), 200

# --- RUTAS SATÉLITE ---
@app.route('/uploads/<path:filename>')
def redirect_uploads(filename): return redirect(f"{MAESTRO_URL}/uploads/{filename}")

@app.route('/uploads/avatars/<path:filename>')
def redirect_avatars(filename): return redirect(f"{MAESTRO_URL}/uploads/avatars/{filename}")

@app.route('/documentos_gestion/<path:section>/<path:filename>')
def redirect_docs(section, filename): return redirect(f"{MAESTRO_URL}/documentos_gestion/{section}/{filename}")

@app.route('/updates/<path:filename>')
def redirect_updates(filename): return redirect(f"{MAESTRO_URL}/updates/{filename}")

# --- API ---
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files_satellite(username):
    try:
        if not UserFile: return jsonify([]), 200 # Si falló importación
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
        if not UserFile: return jsonify([]), 200
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
    if not User: return jsonify({"message": "Error DB"}), 500
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
    return jsonify({
        "status": "Servidor 2 (Satélite Blindado) ONLINE",
        "models": list(MODELS_CACHE.keys()),
        "tf_available": TF_AVAILABLE
    })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=7860, allow_unsafe_werkzeug=True)
