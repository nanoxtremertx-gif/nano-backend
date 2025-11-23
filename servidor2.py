# --- servidor2.py (VERSIÓN SATÉLITE - VISOR DE ARCHIVOS Y BD COMPARTIDA) ---
import os
from flask import Flask, jsonify, redirect, request
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from urllib.parse import urlparse, urlunparse

# --- IMPORTANTE: Asegúrate de que models.py esté en la misma carpeta ---
from models import db, User, UserFile, DocGestion 

app = Flask(__name__)

# --- 1. CONFIGURACIÓN DEL MAESTRO (TELETRANSPORTACIÓN) ---
# Si no configuras la variable, intentará adivinar, pero mejor ponla en Settings.
MAESTRO_URL = os.environ.get('MAESTRO_URL', 'https://tu-servidor-1-maestro.hf.space')

# Eliminar barra al final si existe para evitar dobles //
if MAESTRO_URL.endswith('/'):
    MAESTRO_URL = MAESTRO_URL[:-1]

print(f">>> INICIANDO SERVIDOR 2 (SATÉLITE) >>> APUNTANDO A: {MAESTRO_URL}")

# --- 2. CONEXIÓN A LA BASE DE DATOS NEON (CEREBRO COMPARTIDO) ---
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
NEON_URL = os.environ.get('NEON_URL')

if NEON_URL:
    try:
        # Corrección automática para SQLAlchemy (postgres:// -> postgresql://)
        parsed = urlparse(NEON_URL)
        scheme = 'postgresql' if parsed.scheme == 'postgres' else parsed.scheme
        clean_url = urlunparse((scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)).strip("'").strip()
        
        # Forzar SSL mode si es Neon
        if 'postgresql' in clean_url and 'sslmode' not in clean_url:
            clean_url += "?sslmode=require"
        
        app.config['SQLALCHEMY_DATABASE_URI'] = clean_url
        print(">>> CONEXIÓN DB: ÉXITO (NEON SQL)")
    except Exception as e:
        print(f"!!! ERROR CRÍTICO DB: {e}")
else:
    print("!!! ALERTA: NO HAY NEON_URL. Usando SQLite temporal (DATOS SE BORRARÁN AL REINICIAR)")
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///temp_error.db"

# Inicializar extensiones
cors = CORS(app, resources={r"/*": {"origins": "*"}}) # Permite acceso total
bcrypt = Bcrypt(app)
db.init_app(app)

# --- 3. RUTA PARA UPTIMEROBOT (NO BORRAR) ---
@app.route('/health')
def health_check_uptime():
    return "ALIVE", 200

@app.route('/')
def index():
    return jsonify({
        "status": "Servidor 2 (Satélite) ONLINE",
        "mode": "Read-Only / Mirror",
        "database": "Neon PostgreSQL" if NEON_URL else "SQLite (Error)",
        "linked_to": MAESTRO_URL
    }), 200

# --- 4. TELETRANSPORTACIÓN DE ARCHIVOS (REDIRECCIÓN AL MAESTRO) ---
# Cuando el frontend pide una imagen a Servidor 2, lo mandamos a Servidor 1
# que es quien tiene el archivo físico real.

@app.route('/uploads/<path:filename>')
def redirect_uploads(filename):
    return redirect(f"{MAESTRO_URL}/uploads/{filename}")

@app.route('/uploads/avatars/<path:filename>')
def redirect_avatars(filename):
    return redirect(f"{MAESTRO_URL}/uploads/avatars/{filename}")

@app.route('/documentos_gestion/<path:section>/<path:filename>')
def redirect_docs(section, filename):
    return redirect(f"{MAESTRO_URL}/documentos_gestion/{section}/{filename}")

@app.route('/updates/<path:filename>')
def redirect_updates(filename):
    return redirect(f"{MAESTRO_URL}/updates/{filename}")

# --- 5. API DE DATOS (LEE LA DB COMPARTIDA) ---

@app.route('/api/my-files/<username>', methods=['GET'])
def get_files_satellite(username):
    try:
        # Consultamos la DB real (Neon)
        files = UserFile.query.filter_by(owner_username=username).all()
        file_list = []
        for f in files:
            # Construimos la URL apuntando explícitamente al MAESTRO
            # Así el frontend, aunque esté en Servidor 2, cargará la imagen desde Servidor 1
            remote_url = f"{MAESTRO_URL}/uploads/{f.storage_path}"
            
            file_list.append({
                "id": f.id,
                "name": f.name,
                "type": f.type,
                "parentId": f.parent_id,
                "size": f.size_bytes, # Puedes añadir formateo si quieres
                "path": remote_url,   # <--- LA MAGIA: El link es del Servidor 1
                "isPublished": f.is_published,
                "date": f.created_at.strftime('%Y-%m-%d'),
                "verificationStatus": f.verification_status
            })
        return jsonify(file_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/biblioteca/public-files', methods=['GET'])
def get_public_files_satellite():
    try:
        files = UserFile.query.filter_by(is_published=True).order_by(UserFile.created_at.desc()).all()
        file_list = []
        for f in files:
            file_list.append({
                "id": f.id,
                "name": f.name,
                "type": f.type,
                "path": f"{MAESTRO_URL}/uploads/{f.storage_path}", # Link remoto
                "size": f.size_bytes,
                "description": f.description,
                "userId": f.owner_username
            })
        return jsonify(file_list), 200
    except: return jsonify([]), 200

# --- LOGIN (Funciona igual porque la DB es la misma) ---
@app.route('/api/login', methods=['POST'])
def login():
    d = request.get_json()
    u = User.query.filter_by(username=d.get('username')).first()
    
    if u and bcrypt.check_password_hash(u.hash, d.get('password')):
        # Ajustamos el avatar para que apunte al maestro si es local
        avatar_url = u.avatar
        if 'uploads' in str(avatar_url) and not avatar_url.startswith('http'):
             avatar_url = f"{MAESTRO_URL}{u.avatar}" if u.avatar.startswith('/') else f"{MAESTRO_URL}/{u.avatar}"

        return jsonify({
            "message": "OK",
            "user": {
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "avatar": avatar_url # Avatar con URL corregida
            }
        }), 200
    return jsonify({"message": "Credenciales inválidas"}), 401

if __name__ == '__main__':
    # Puerto 7860 es el estándar de Hugging Face Spaces
    app.run(host='0.0.0.0', port=7860)
