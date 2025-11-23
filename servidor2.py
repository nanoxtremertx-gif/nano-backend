# --- servidor2.py (VERSIÓN SATÉLITE FINAL - GITHUB) ---
import os
from flask import Flask, jsonify, redirect, request
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from urllib.parse import urlparse, urlunparse

# Importamos modelos (esto funciona porque el Dockerfile clonó el repo completo)
from models import db, User, UserFile, DocGestion 

app = Flask(__name__)

# --- 1. CONFIGURACIÓN DEL MAESTRO ---
# URL de Servidor 1 para redireccionar archivos físicos
MAESTRO_URL = os.environ.get('MAESTRO_URL', 'https://tu-servidor-1.hf.space')
# Limpieza de URL para evitar dobles barras
if MAESTRO_URL.endswith('/'): MAESTRO_URL = MAESTRO_URL[:-1]

print(f">>> INICIANDO NODO DE IA (SERVIDOR 2) >>> CONECTADO A: {MAESTRO_URL}")

# --- 2. CONEXIÓN A BASE DE DATOS NEON (COMPARTIDA) ---
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
NEON_URL = os.environ.get('NEON_URL')

if NEON_URL:
    try:
        # Corrección de protocolo para SQLAlchemy (postgres -> postgresql)
        parsed = urlparse(NEON_URL)
        scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
        clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
        
        # Forzar SSL si es necesario (Requerido por Neon)
        if 'postgresql' in clean_url and 'sslmode' not in clean_url:
            clean_url += "?sslmode=require"
        
        app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
        print(">>> DB NEON: CONECTADA")
    except Exception as e:
        print(f"!!! ERROR DB: {e}")
        app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///error.db"
else:
    print("!!! ALERTA: FALTA NEON_URL EN VARIABLES DE HUGGING FACE")
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///local_temp.db"

# Inicialización de extensiones
cors = CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- 3. RUTA UPTIME ROBOT (CRUCIAL PARA QUE NO SE DUERMA) ---
@app.route('/health')
def health(): return "ALIVE", 200

@app.route('/')
def index():
    return jsonify({
        "status": "Servidor 2 (IA Node) ONLINE",
        "mode": "Satellite/Inference",
        "linked_to": MAESTRO_URL,
        "fix_applied": "allow_unsafe_werkzeug"
    })

# --- 4. REDIRECCIÓN DE ARCHIVOS (TELETRANSPORTACIÓN) ---
# Servidor 2 no tiene archivos físicos, redirige al Maestro.

@app.route('/uploads/<path:filename>')
def redirect_uploads(filename): return redirect(f"{MAESTRO_URL}/uploads/{filename}")

@app.route('/uploads/avatars/<path:filename>')
def redirect_avatars(filename): return redirect(f"{MAESTRO_URL}/uploads/avatars/{filename}")

@app.route('/documentos_gestion/<path:section>/<path:filename>')
def redirect_docs(section, filename): return redirect(f"{MAESTRO_URL}/documentos_gestion/{section}/{filename}")

@app.route('/updates/<path:filename>')
def redirect_updates(filename): return redirect(f"{MAESTRO_URL}/updates/{filename}")

# --- 5. API LECTURA (LEE DB COMPARTIDA) ---

@app.route('/api/my-files/<username>', methods=['GET'])
def get_files_satellite(username):
    try:
        # Lee de la DB real (Neon)
        files = UserFile.query.filter_by(owner_username=username).all()
        file_list = []
        for f in files:
            # Construye URL remota apuntando al Maestro
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
        # Ajustar avatar para que apunte al maestro si es ruta local
        avatar_url = u.avatar
        if 'uploads' in str(avatar_url) and not avatar_url.startswith('http'):
             avatar_url = f"{MAESTRO_URL}{u.avatar}" if u.avatar.startswith('/') else f"{MAESTRO_URL}/{u.avatar}"
        
        return jsonify({"message": "OK", "user": {"username": u.username, "role": u.role, "avatar": avatar_url}}), 200
    return jsonify({"message": "Credenciales inválidas"}), 401

# --- ARRANQUE CON EL PARCHE PARA HUGGING FACE ---
if __name__ == '__main__':
    # allow_unsafe_werkzeug=True soluciona el RuntimeError en producción
    socketio.run(app, host='0.0.0.0', port=7860, allow_unsafe_werkzeug=True)
