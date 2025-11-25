# --- servidor2.py (V10.25 - MODO FORENSE Y DIAGNÓSTICO TOTAL) ---
import os
import sys
import io
import base64
import pickle
import traceback
import numpy as np
import glob
from pathlib import Path
from PIL import Image, ImageFilter, ImageDraw, ImageFont
from flask import Flask, request, jsonify, redirect, make_response
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from urllib.parse import urlparse, urlunparse

# --- CARGA TENSORFLOW ---
try:
    import tensorflow as tf
    TF_AVAILABLE = True
    print(f">>> TENSORFLOW VERSION: {tf.__version__}", flush=True)
except ImportError:
    print("!!! TENSORFLOW NO DETECTADO", file=sys.stderr)
    TF_AVAILABLE = False

# --- CRIPTOGRAFÍA ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- MOCK DB ---
try:
    from models import db, User, UserFile, DocGestion
except ImportError:
    db = type('Mock', (object,), {'init_app': lambda x: None})
    User = UserFile = DocGestion = None

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 

# ==============================================================================
# PARTE 1: CONFIGURACIÓN
# ==============================================================================

MAESTRO_URL = os.environ.get('MAESTRO_URL', 'https://nano-xtremertx-nano-backend.hf.space')
if MAESTRO_URL.endswith('/'): MAESTRO_URL = MAESTRO_URL[:-1]

print(f">>> INICIANDO SERVIDOR 2 (V10.25) FORENSE >>>", flush=True)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
NEON_URL = os.environ.get('NEON_URL')

# DB SETUP (Omitido por brevedad, igual a versiones anteriores)
if NEON_URL:
    try:
        parsed = urlparse(NEON_URL)
        scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
        clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
        if 'postgresql' in clean_url and 'sslmode' not in clean_url: clean_url += "?sslmode=require"
        app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
    except: app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"
else: app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"

CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
if hasattr(db, 'init_app'): db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=1024*1024*1024)

# ==============================================================================
# PARTE 2: SISTEMA DE IA (AUDITORÍA DE ARCHIVOS)
# ==============================================================================

BASE_DIR = Path("/app")
MODELS_DIR = BASE_DIR / "xtremertx_ai" / "models"
MODELS_CACHE = {}

MODELS_CONFIG = {
    'generalista': 'generalista_hd_best.keras',
    'genesis': 'genesis_decoder_v4.keras',
    'odin': 'odin_upscaler_v2.keras',
    'lexicon': 'khipu_lexicon.npy'
}

def audit_files():
    """ESTA FUNCIÓN TE DIRÁ LA VERDAD EN LOS LOGS"""
    print("="*50, flush=True)
    print(">>> INICIANDO AUDITORÍA DE ARCHIVOS...", flush=True)
    print(f">>> BUSCANDO EN: {MODELS_DIR}", flush=True)
    
    if not MODELS_DIR.exists():
        print(f"!!! LA CARPETA NO EXISTE: {MODELS_DIR}", flush=True)
        print(f">>> CONTENIDO DE /app/xtremertx_ai:", flush=True)
        try:
            for f in (BASE_DIR / "xtremertx_ai").glob("*"): print(f" - {f.name}")
        except: print("No se puede leer /app/xtremertx_ai")
        return

    files_found = list(MODELS_DIR.glob("*"))
    print(f">>> ARCHIVOS EN CARPETA MODELS ({len(files_found)}):", flush=True)
    
    for f in files_found:
        size = f.stat().st_size
        size_str = f"{size} bytes"
        if size > 1024: size_str = f"{size/1024:.2f} KB"
        if size > 1024*1024: size_str = f"{size/(1024*1024):.2f} MB"
        
        print(f" 📄 {f.name} [{size_str}]", flush=True)
        
        # PRUEBA DEL ALGODÓN: SI ES PEQUEÑO, LEEMOS EL CONTENIDO
        if size < 2000:
            try:
                content = f.read_text()
                print(f"    🔍 CONTENIDO SOSPECHOSO: {content[:100]}", flush=True)
                if "git-lfs" in content:
                    print("    🚨 CONFIRMADO: ES UN PUNTERO LFS, NO EL MODELO REAL.", flush=True)
            except:
                print("    ❓ No se pudo leer texto (quizás binario corrupto).", flush=True)

    print("="*50, flush=True)

# EJECUTAR AUDITORÍA AL INICIO
audit_files()

def create_error_image(message):
    img = Image.new('RGB', (512, 512), color=(0, 0, 0))
    d = ImageDraw.Draw(img)
    try: font = ImageFont.truetype("arial.ttf", 14)
    except: font = ImageFont.load_default()
    
    y = 50
    d.text((20, 20), "DIAGNÓSTICO SERVIDOR IA", fill=(0, 255, 255), font=font)
    
    for line in message.split('\n'):
        d.text((20, y), line, fill=(255, 100, 100), font=font)
        y += 20
    
    # Listar estado actual
    y += 30
    d.text((20, y), "ESTADO DE ARCHIVOS:", fill=(255, 255, 0), font=font)
    y += 20
    
    for name, filename in MODELS_CONFIG.items():
        path = MODELS_DIR / filename
        status = "MISSING"
        if path.exists():
            size = path.stat().st_size
            if size < 2000: status = "LFS POINTER (1KB)"
            else: status = f"OK ({size/(1024*1024):.1f}MB)"
        
        d.text((20, y), f"- {filename}: {status}", fill=(200, 200, 200), font=font)
        y += 20

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def load_model_server(key):
    if not TF_AVAILABLE: return None
    filename = MODELS_CONFIG.get(key)
    if not filename: return None
    
    if key in MODELS_CACHE: return MODELS_CACHE[key]

    path = MODELS_DIR / filename
    if not path.exists(): return None
    
    # Si es un puntero, ni intentamos cargarlo con TensorFlow para que no explote
    if path.stat().st_size < 2000:
        print(f"!!! SALTANDO CARGA DE {filename} (Es un puntero LFS)", file=sys.stderr)
        return "LFS_ERROR"

    print(f">>> CARGANDO {key.upper()}...", flush=True)
    try:
        if filename.endswith('.npy'): MODELS_CACHE[key] = np.load(path)
        else: MODELS_CACHE[key] = tf.keras.models.load_model(str(path), compile=False)
        return MODELS_CACHE[key]
    except Exception as e:
        print(f"!!! ERROR CARGA {filename}: {e}")
        return None

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
def process_preview_request(file_bytes, filename, password=None, full_quality=False):
    filename = filename.lower()
    author_fingerprint = "N/A"
    original_image = None

    if filename.endswith('.crs'):
        try: crs_data = pickle.loads(file_bytes)
        except: return create_error_image("ARCHIVO CRS CORRUPTO")

        final_data = crs_data
        if isinstance(crs_data, dict) and crs_data.get('is_encrypted'):
            if not password: return create_error_image("ARCHIVO ENCRIPTADO")
            try: final_data = decrypt_data(crs_data, password)
            except: return create_error_image("CONTRASEÑA INCORRECTA")

        author_fingerprint = get_author_fingerprint(final_data)
        file_version = final_data.get("version", "legacy")
        shape_data = final_data.get("true_original_shape") or final_data.get("original_shape")
        if not shape_data: return create_error_image("METADATA DAÑADA")
        final_w, final_h = shape_data[:2]
        
        try:
            if not TF_AVAILABLE: return create_error_image("ERROR: TENSORFLOW NO INSTALADO")

            if "Generalista" in file_version:
                model = load_model_server('generalista')
                if model == "LFS_ERROR": return create_error_image("ERROR: MODELO GENERALISTA ES UN PUNTERO LFS\n(1KB en vez de 200MB)")
                if not model: return create_error_image(f"ERROR: MODELO GENERALISTA NO ENCONTRADO\nEn: {MODELS_DIR}")
                
                rec_norm = model.predict(final_data["core_seed"], verbose=0).squeeze()
                base_pil = Image.fromarray((rec_norm * 255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
                res_map = np.array(Image.open(io.BytesIO(final_data["fidelity_seed"]))).astype(np.int32) - 128
                final_array = np.clip(np.array(base_pil).astype(np.int32) + res_map, 0, 255).astype(np.uint8)
            else:
                # Legacy
                model_g = load_model_server('genesis')
                model_o = load_model_server('odin')
                
                if model_g == "LFS_ERROR" or model_o == "LFS_ERROR": 
                    return create_error_image("ERROR: MODELOS LEGACY SON PUNTEROS LFS\nRevisar Git LFS en Dockerfile.")
                
                if not model_g or not model_o: 
                    return create_error_image(f"ERROR: FALTAN MODELOS LEGACY\nEn: {MODELS_DIR}")
                
                rec_norm = model_g.predict(final_data["core_seed"], verbose=0).squeeze()
                odin_norm = model_o.predict(np.expand_dims(rec_norm, axis=0), verbose=0).squeeze()
                base_pil = Image.fromarray((np.clip(odin_norm,0,1)*255).astype(np.uint8)).resize((final_w, final_h), Image.Resampling.LANCZOS)
                try: res_map = (np.array(Image.open(io.BytesIO(final_data["fidelity_seed"])), dtype=np.float32)-128.0)*2.0
                except: res_map = np.zeros((final_h, final_w), dtype=np.float32)
                final_array = np.clip(np.array(base_pil) + res_map, 0, 255).astype(np.uint8)
        
        except Exception as e:
            return create_error_image(f"ERROR INFERENCIA IA:\n{str(e)}")

        if final_array is not None:
            original_image = Image.fromarray(final_array)

    elif filename.endswith(('.png', '.jpg', '.jpeg', '.webp')):
        try:
            original_image = Image.open(io.BytesIO(file_bytes))
            if original_image.mode != 'RGB': original_image = original_image.convert('RGB')
            author_fingerprint = "IMG"
        except: return create_error_image("IMAGEN INVÁLIDA")
    else: return create_error_image("FORMATO NO SOPORTADO")

    if original_image is None: return create_error_image("ERROR DESCONOCIDO")

    try:
        if full_quality:
            final_preview = original_image
            info_text = f"ID: {author_fingerprint} | 100%"
        else:
            w, h = original_image.size
            target_w, target_h = max(64, int(w * 0.15)), max(64, int(h * 0.15))
            deformed_image = original_image.resize((target_w, target_h), Image.Resampling.BILINEAR)
            final_preview = deformed_image.resize((512, 512), Image.Resampling.BOX)
            final_preview = final_preview.filter(ImageFilter.GaussianBlur(radius=2))
            info_text = f"ID: {author_fingerprint} | PREVIEW 15%"

        footer_height = 40
        pw, ph = final_preview.size
        full_preview = Image.new('RGBA', (pw, ph + 40), (10, 10, 10, 255))
        full_preview.paste(final_preview, (0, 0))
        d = ImageDraw.Draw(full_preview)
        try: font = ImageFont.truetype("arial.ttf", 12)
        except: font = ImageFont.load_default()
        d.text((10, ph + 12), info_text, font=font, fill=(150, 150, 150))
        if not full_quality:
            d.text((pw - 110, ph + 12), "SOLO LECTURA", font=font, fill=(200, 50, 50))

        buffer = io.BytesIO()
        full_preview.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode('utf-8')

    except Exception as e: return create_error_image(f"ERROR RENDER: {e}")

@app.route('/generate-crs-preview', methods=['POST'])
def handle_preview_generation():
    if 'file' not in request.files: return jsonify({"success": False, "error": "No file"}), 400
    file = request.files['file']
    password = request.form.get('password')
    is_full_quality = request.args.get('quality') == 'full'
    print(f">>> SOLICITUD: {file.filename}", flush=True)
    try:
        prev_b64 = process_preview_request(file.read(), file.filename, password, is_full_quality)
        return jsonify({"success": True, "preview_base64": prev_b64}), 200
    except Exception as e:
        err_img = create_error_image(f"ERROR CRITICO:\n{str(e)}")
        return jsonify({"success": True, "preview_base64": err_img}), 200

# RUTAS SATÉLITE
@app.route('/uploads/<path:filename>')
def redirect_uploads(filename): return redirect(f"{MAESTRO_URL}/uploads/{filename}")
@app.route('/uploads/avatars/<path:filename>')
def redirect_avatars(filename): return redirect(f"{MAESTRO_URL}/uploads/avatars/{filename}")
@app.route('/documentos_gestion/<path:section>/<path:filename>')
def redirect_docs(section, filename): return redirect(f"{MAESTRO_URL}/documentos_gestion/{section}/{filename}")
@app.route('/updates/<path:filename>')
def redirect_updates(filename): return redirect(f"{MAESTRO_URL}/updates/{filename}")

# API
@app.route('/api/my-files/<username>', methods=['GET'])
def get_files_satellite(username):
    try:
        if not UserFile: return jsonify([]), 200
        files = UserFile.query.filter_by(owner_username=username).all()
        file_list = []
        for f in files:
            file_list.append({
                "id": f.id, "name": f.name, "type": f.type, "parentId": f.parent_id,
                "size_bytes": f.size_bytes, "path": f"{MAESTRO_URL}/uploads/{f.storage_path}", 
                "isPublished": f.is_published, "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status
            })
        return jsonify(file_list), 200
    except: return jsonify([]), 200

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
    if not User: return jsonify({"message": "DB Error"}), 500
    u = User.query.filter_by(username=d.get('username')).first()
    if u and bcrypt.check_password_hash(u.hash, d.get('password')):
        url = u.avatar
        if 'uploads' in str(url) and not url.startswith('http'): url = f"{MAESTRO_URL}{u.avatar}"
        return jsonify({"message": "OK", "user": {"username": u.username, "role": u.role, "avatar": url}}), 200
    return jsonify({"message": "Credenciales inválidas"}), 401

@app.route('/health')
def health(): return "ALIVE", 200

@app.route('/')
def index():
    return jsonify({
        "status": "Servidor 2 FORENSE",
        "diagnostic": "Revisa los logs de la consola",
        "tf_available": TF_AVAILABLE
    })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=7860, allow_unsafe_werkzeug=True)
